//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use log::trace;
use pin_project::pin_project;
use shadowsocks::{
    net::{ConnectOpts, TcpStream},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::{MonProxyStream, OutboundProxyStream, TcpDialer},
};
pub struct BasicAuth(pub String);
use super::auto_proxy_io::AutoProxyIo;

/// Outbound transport used by [`AutoProxyClientStream`]: either a direct
/// TCP connection or a tunnel through the configured outbound proxy chain.
#[allow(clippy::large_enum_variant)]
#[pin_project(project = OutboundTransportProj)]
pub enum OutboundTransport {
    /// Direct TCP, no outbound chain configured.
    Direct(#[pin] TcpStream),
    /// Tunnel produced by `OutboundProxyClient::connect_tcp`.
    Chained(#[pin] OutboundProxyStream),
}

impl OutboundTransport {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct(s) => s.local_addr(),
            Self::Chained(s) => s.local_addr(),
        }
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Direct(s) => s.set_nodelay(nodelay),
            // For tunnels we can only forward the request to the underlying
            // TCP socket if it is exposed; the unified enum has no such
            // accessor today, so the call is a no-op.
            Self::Chained(_) => Ok(()),
        }
    }
}

impl AsyncRead for OutboundTransport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_read(cx, buf),
            OutboundTransportProj::Chained(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundTransport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_write(cx, buf),
            OutboundTransportProj::Chained(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_flush(cx),
            OutboundTransportProj::Chained(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_shutdown(cx),
            OutboundTransportProj::Chained(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_write_vectored(cx, bufs),
            OutboundTransportProj::Chained(s) => s.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Direct(s) => s.is_write_vectored(),
            Self::Chained(s) => s.is_write_vectored(),
        }
    }
}

/// `TcpDialer` adapter that dials directly via the shadowsocks
/// infrastructure (DNS resolver, connect options).
struct DirectTcpDialer<'a> {
    context: &'a ServiceContext,
    opts: &'a ConnectOpts,
}

impl<'a> TcpDialer for DirectTcpDialer<'a> {
    async fn dial(&self, addr: &Address) -> io::Result<TcpStream> {
        TcpStream::connect_remote_with_opts(self.context.context_ref(), addr, self.opts).await
    }
}

/// Unified stream for bypassed and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project(project = AutoProxyClientStreamProj)]
pub enum AutoProxyClientStream {
    /// Tunnel through the shadowsocks server (optionally over the outbound
    /// proxy chain).
    Proxied(#[pin] ProxyClientStream<MonProxyStream<OutboundTransport>>),
    #[cfg(feature = "https-tunnel")]
    HttpTunnel(#[pin] HttpTunnelStream),
    /// Direct TCP, bypassing the shadowsocks server.
    Bypassed(#[pin] TcpStream),
}

#[cfg(feature = "https-tunnel")]
use {
    bytes::{BufMut, BytesMut},
    log::warn,
    rustls_native_certs::CertificateResult,
    std::io::ErrorKind,
    std::sync::LazyLock,
    tokio::io::AsyncWriteExt,
    tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    },
};
#[cfg(feature = "https-tunnel")]
#[pin_project]
pub struct HttpTunnelStream {
    #[pin]
    stream: tokio_rustls::client::TlsStream<MonProxyStream<shadowsocks::net::TcpStream>>,
    addr: Address,
    auth: String,
}

#[cfg(feature = "https-tunnel")]
impl HttpTunnelStream {
    pub async fn handshake(&mut self) -> io::Result<()> {
        let addr = self.addr.clone();
        let auth = self.auth.clone();
        let mut stream = &mut self.stream;
        connect_tunnel(addr, stream, &auth).await?;
        wait_response(&mut stream).await?;
        Ok(())
    }
}

impl AutoProxyClientStream {
    pub async fn handshake_tunnel(&mut self) -> io::Result<()> {
        match self {
            AutoProxyClientStream::Proxied(_) => Ok(()),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(tunnel_stream) => {
                tunnel_stream.handshake().await?;
                Ok(())
            }
            AutoProxyClientStream::Bypassed(_) => Ok(()),
        }
    }
    pub fn auth(&self) -> Option<BasicAuth> {
        match self {
            AutoProxyClientStream::Proxied(_) => None,
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(tunnel_stream) => Some(BasicAuth(tunnel_stream.auth.clone())),
            AutoProxyClientStream::Bypassed(_) => None,
        }
    }
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(context: Arc<ServiceContext>, server: &ServerIdent, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        if context.check_target_bypassed(&addr).await {
            trace!("Bypassing target address {addr}");
            Self::connect_bypassed_with_opts_inner(context, addr, opts).await
        } else {
            #[cfg(feature = "https-tunnel")]
            {
                Self::connect_http_tunnel(context, server, addr).await
            }
            #[cfg(not(feature = "https-tunnel"))]
            {
                trace!("Proxying target address {addr}");
                Self::connect_proxied_with_opts_inner(context, server, addr, opts).await
            }
        }
    }

    #[cfg(feature = "https-tunnel")]
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_http_tunnel<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        let stream = TcpStream::connect_server_with_opts(
            context.context_ref(),
            server.server_config().tcp_external_addr(),
            context.connect_opts_ref(),
        )
        .await?;

        static TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
            let mut config = ClientConfig::builder()
                .with_root_certificates({
                    // Load WebPKI roots (Mozilla's root certificates)
                    let mut store = RootCertStore::empty();
                    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                    let CertificateResult { certs, errors, .. } = rustls_native_certs::load_native_certs();
                    if !errors.is_empty() {
                        for error in errors {
                            warn!("failed to load cert (native), error: {}", error);
                        }
                    }

                    for cert in certs {
                        if let Err(err) = store.add(cert) {
                            warn!("failed to add cert (native), error: {}", err);
                        }
                    }

                    store
                })
                .with_no_client_auth();

            // Try to negotiate HTTP/2
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        });

        let connector = TlsConnector::from(TLS_CONFIG.clone());
        let host = match ServerName::try_from(server.server_config().addr().host()) {
            Ok(n) => n,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid dnsname \"{}\"", server.server_config().addr().host()),
                ));
            }
        };
        let flow_stat = context.flow_stat();
        let tls_stream = connector
            .connect(host.to_owned(), MonProxyStream::from_stream(stream, flow_stat))
            .await?;

        use base64::Engine;
        let base64 = base64::engine::general_purpose::STANDARD.encode(server.server_config().password());
        Ok(AutoProxyClientStream::HttpTunnel(HttpTunnelStream {
            stream: tls_stream,
            addr: addr.into(),
            auth: "Basic ".to_owned() + base64.as_str(),
        }))
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed<A>(context: Arc<ServiceContext>, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_bypassed_with_opts(context.clone(), addr, context.connect_opts_ref()).await
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed_with_opts<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        Self::connect_bypassed_with_opts_inner(context, addr, connect_opts).await
    }

    async fn connect_bypassed_with_opts_inner<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        let stream = TcpStream::connect_remote_with_opts(context.context_ref(), &addr, connect_opts).await?;
        Ok(Self::Bypassed(stream))
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied<A>(context: Arc<ServiceContext>, server: &ServerIdent, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_proxied_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        Self::connect_proxied_with_opts_inner(context, server, addr, connect_opts).await
    }

    async fn connect_proxied_with_opts_inner<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        let flow_stat = context.flow_stat();
        let target_addr: Address = addr.into();
        let ss_addr: Address = server.server_config().tcp_external_addr().into();

        let dial_result = match context.outbound_client() {
            None => TcpStream::connect_remote_with_opts(context.context_ref(), &ss_addr, connect_opts)
                .await
                .map(OutboundTransport::Direct),
            Some(client) => {
                let dialer = DirectTcpDialer {
                    context: context.as_ref(),
                    opts: connect_opts,
                };
                client
                    .connect_tcp(&dialer, &ss_addr)
                    .await
                    .map(OutboundTransport::Chained)
            }
        };

        let transport = match dial_result {
            Ok(t) => t,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };

        let mon = MonProxyStream::from_stream(transport, flow_stat);
        let stream = ProxyClientStream::from_stream(context.context(), mon, server.server_config(), target_addr);
        Ok(Self::Proxied(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().local_addr(),
            AutoProxyClientStream::Bypassed(ref s) => s.local_addr(),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(ref s) => s.stream.get_ref().0.get_ref().local_addr(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().set_nodelay(nodelay),
            AutoProxyClientStream::Bypassed(ref s) => s.set_nodelay(nodelay),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(ref s) => s.stream.get_ref().0.get_ref().set_nodelay(nodelay),
        }
    }
}
#[cfg(feature = "https-tunnel")]
async fn connect_tunnel(
    addr: Address,
    tls_stream: &mut tokio_rustls::client::TlsStream<MonProxyStream<TcpStream>>,
    auth: &str,
) -> Result<(), io::Error> {
    let connect_string = match addr {
        Address::SocketAddress(sa) => {
            format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                sa.ip(),
                sa.port(),
                sa.ip(),
                auth
            )
        }
        Address::DomainNameAddress(domain, port) => {
            format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                domain, port, domain, auth
            )
        }
    };
    let mut addr_buf = BytesMut::with_capacity(connect_string.as_bytes().len());
    addr_buf.put_slice(connect_string.as_bytes());
    tls_stream.write_all(&addr_buf).await?;

    Ok(())
}
#[cfg(feature = "https-tunnel")]
async fn wait_response(tls_stream: &mut tokio_rustls::client::TlsStream<MonProxyStream<TcpStream>>) -> io::Result<()> {
    let mut reader = tokio::io::BufReader::new(tls_stream);

    // 读取响应状态行
    let mut response_line = String::new();
    use tokio::io::AsyncBufReadExt;
    if let Err(e) = reader.read_line(&mut response_line).await {
        warn!("forward_bypass read response error: {}", e);
        return Err(io::Error::other(e));
    }

    // 检查响应是否是200
    let status_code = response_line.split_whitespace().nth(1).unwrap_or("");
    if status_code != "200" {
        warn!("forward_bypass unexpected response: {}", response_line);
        return Err(io::Error::other("unexpected response from bypass server"));
    }

    // 读取并丢弃响应头直到空行
    loop {
        let mut header_line = String::new();
        if let Err(e) = reader.read_line(&mut header_line).await {
            warn!("forward_bypass read header error: {}", e);
            return Err(io::Error::other("unexpected response from bypass server"));
        }
        if header_line == "\r\n" || header_line == "\n" {
            break;
        }
    }

    Ok(())
}

impl AutoProxyIo for AutoProxyClientStream {
    fn is_proxied(&self) -> bool {
        !matches!(*self, AutoProxyClientStream::Bypassed(..))
    }
}

impl AsyncRead for AutoProxyClientStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_read(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_read(cx, buf),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AutoProxyClientStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write(cx, buf),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_flush(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_flush(cx),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_shutdown(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_shutdown(cx),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write_vectored(cx, bufs),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_write_vectored(cx, bufs),
        }
    }
}
