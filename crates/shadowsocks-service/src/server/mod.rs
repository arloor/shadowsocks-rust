//! Shadowsocks server

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use futures::future;
use log::{info, trace};
use prom_label::{Label, LabelImpl};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, histogram::Histogram},
    registry::Registry,
};
use shadowsocks::net::{AcceptOpts, ConnectOpts, UdpSocketOpts};

use crate::{
    config::{Config, ConfigType},
    dns::build_dns_resolver,
    utils::ServerHandle,
};

pub use self::{
    server::{Server, ServerBuilder},
    tcprelay::TcpServer,
    udprelay::UdpServer,
};

pub mod context;
#[allow(clippy::module_inception)]
pub mod server;
mod tcprelay;
mod udprelay;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const SERVER_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Starts a shadowsocks server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Server);
    assert!(!config.server.is_empty());

    trace!("{:?}", config);

    // Warning for Stream Ciphers
    #[cfg(feature = "stream-cipher")]
    for inst in config.server.iter() {
        let server = &inst.config;

        if server.method().is_stream() {
            log::warn!(
                "stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.",
                server.method(),
                server.addr()
            );
        }
    }

    #[cfg(all(unix, not(target_os = "android")))]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            log::warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut servers = Vec::new();

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,
        #[cfg(target_os = "freebsd")]
        user_cookie: config.outbound_user_cookie,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_local_addr: config.outbound_bind_addr.map(|ip| SocketAddr::new(ip, 0)),
        bind_interface: config.outbound_bind_interface,

        udp: UdpSocketOpts {
            allow_fragmentation: config.outbound_udp_allow_fragmentation,

            ..Default::default()
        },

        ..Default::default()
    };

    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));
    connect_opts.tcp.mptcp = config.mptcp;
    connect_opts.udp.mtu = config.udp_mtu;

    let mut accept_opts = AcceptOpts {
        ipv6_only: config.ipv6_only,
        ..Default::default()
    };
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;
    accept_opts.tcp.fastopen = config.fast_open;
    accept_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));
    accept_opts.tcp.mptcp = config.mptcp;
    accept_opts.udp.mtu = config.udp_mtu;

    let resolver = build_dns_resolver(config.dns, config.ipv6_first, config.dns_cache_size, &connect_opts)
        .await
        .map(Arc::new);

    let acl = config.acl.map(Arc::new);

    for inst in config.server {
        let svr_cfg = inst.config;
        let mut server_builder = ServerBuilder::new(svr_cfg);

        if let Some(ref r) = resolver {
            server_builder.set_dns_resolver(r.clone());
        }

        let mut connect_opts = connect_opts.clone();
        let accept_opts = accept_opts.clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = inst.outbound_fwmark {
            connect_opts.fwmark = Some(fwmark);
        }

        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = inst.outbound_user_cookie {
            connect_opts.user_cookie = Some(user_cookie);
        }

        if let Some(bind_local_addr) = inst.outbound_bind_addr {
            connect_opts.bind_local_addr = Some(SocketAddr::new(bind_local_addr, 0));
        }

        if let Some(bind_interface) = inst.outbound_bind_interface {
            connect_opts.bind_interface = Some(bind_interface);
        }

        if let Some(udp_allow_fragmentation) = inst.outbound_udp_allow_fragmentation {
            connect_opts.udp.allow_fragmentation = udp_allow_fragmentation;
        }

        server_builder.set_connect_opts(connect_opts);
        server_builder.set_accept_opts(accept_opts);

        if let Some(c) = config.udp_max_associations {
            server_builder.set_udp_capacity(c);
        }
        if let Some(d) = config.udp_timeout {
            server_builder.set_udp_expiry_duration(d);
        }
        if let Some(ref m) = config.manager {
            server_builder.set_manager_addr(m.addr.clone());
        }

        match inst.acl {
            Some(acl) => server_builder.set_acl(Arc::new(acl)),
            None => {
                if let Some(ref acl) = acl {
                    server_builder.set_acl(acl.clone());
                }
            }
        }

        if config.ipv6_first {
            server_builder.set_ipv6_first(config.ipv6_first);
        }

        server_builder.set_security_config(&config.security);

        let server = server_builder.build().await?;
        servers.push(server);
    }

    if servers.len() == 1 {
        let server = servers.pop().unwrap();
        return server.run().await;
    }

    let mut vfut = Vec::with_capacity(servers.len());

    for server in servers {
        vfut.push(ServerHandle(tokio::spawn(async move { server.run().await })));
    }

    let (res, ..) = future::select_all(vfut).await;
    res
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct AccessLabel {
    pub client: String,
    pub relay_over_tls: Option<bool>, // 只有bypass时，该字段才为Some
    pub target: String,
    pub username: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct TunnelHandshakeLabel {
    pub target: String,
    // pub final_target: Option<String>, // 是否是通过bypass中继的
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();
    let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
    registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());
    register_metric_cleaner(proxy_traffic.clone(), "proxy_traffic".to_owned(), 2);
    // Summary指标：统计tunnel_proxy_bypass从接收请求到完成bypass握手的耗时
    let tunnel_handshake_duration = Family::<LabelImpl<TunnelHandshakeLabel>, Histogram>::new_with_constructor(|| {
        // 使用细粒度的buckets来统计耗时分布，单位是ms
        Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0])
    });
    registry.register(
        "tunnel_handshake_duration",
        "Duration in seconds from receiving request to completing tunnel handshake",
        tunnel_handshake_duration.clone(),
    );
    register_metric_cleaner(
        tunnel_handshake_duration.clone(),
        "tunnel_handshake_duration".to_owned(),
        2,
    );

    Metrics {
        registry,
        proxy_traffic,
        tunnel_handshake_duration,
    }
});

pub struct Metrics {
    pub registry: Registry,
    pub(crate) proxy_traffic: Family<LabelImpl<AccessLabel>, Counter>,
    pub(crate) tunnel_handshake_duration: Family<LabelImpl<TunnelHandshakeLabel>, Histogram>,
}

// 每两小时清空一次，否则一直累积，光是exporter的流量就很大，观察到每天需要3.7GB。不用担心rate函数不准，promql查询会自动处理reset（数据突降）的数据。
// 不过，虽然能够处理reset，但increase会用最后一个出现的值-第一个出现的值。在我们清空的实现下，reset后第一个出现的值肯定不是0，所以increase的算出来的值会稍少（少第一次出现的值）
// 因此对于准确性要求较高的http_req_counter，这里的清空间隔就放大一点
fn register_metric_cleaner<T: Label + Send + Sync, M: 'static + Send + Sync>(
    counter: Family<T, M>,
    name: String,
    interval_in_hour: u64,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_in_hour * 60 * 60)).await;
            info!("cleaning prometheus metric labels for {name}");
            counter.clear();
        }
    });
}
