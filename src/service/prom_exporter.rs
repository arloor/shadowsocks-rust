use std::{error::Error, time::Duration};

use axum::{Router, extract::MatchedPath, response::Html, routing::get};
use axum_bootstrap::error::AppError;
use http::{HeaderMap, HeaderValue, StatusCode, header};

use shadowsocks_service::server::METRICS;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

type DynError = Box<dyn Error + Send + Sync>; // wrapper for dyn Error

pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 10 }); // 3 minutes

pub(crate) async fn prom_exporter(port: u16) -> Result<(), DynError> {
    log::info!("Starting Prometheus exporter on port {}", port);
    let router = build_router();
    axum_bootstrap::new_server(port, router)
        .with_timeout(IDLE_TIMEOUT)
        // .with_tls_param(match config.over_tls {
        //     true => Some(TlsParam {
        //         tls: true,
        //         cert: config.cert.to_string(),
        //         key: config.key.to_string(),
        //     }),
        //     false => None,
        // })
        // .with_interceptor(ProxyInterceptor(proxy_handler))
        .run()
        .await
}

fn build_router() -> Router {
    // build our application with a route
    let router = Router::new()
        .route("/metrics", get(serve_metrics))
        .fallback(get(|| async {
            let mut header_map = HeaderMap::new();
            #[allow(clippy::expect_used)]
            header_map.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            (StatusCode::NOT_FOUND, header_map, Html("404".to_string()))
        }))
        .layer((
            TraceLayer::new_for_http() // Create our own span for the request and include the matched path. The matched
                // path is useful for figuring out which handler the request was routed to.
                .make_span_with(make_span)
                // By default `TraceLayer` will log 5xx responses but we're doing our specific
                // logging of errors so disable that
                .on_failure(()),
            CorsLayer::permissive(),
            TimeoutLayer::new(Duration::from_secs(30)),
            CompressionLayer::new(),
        ));

    router
}

fn make_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
    let method = req.method();
    let path = req.uri().path();

    // axum automatically adds this extension.
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched_path| matched_path.as_str());

    tracing::debug_span!("recv request", %method, %path, matched_path)
}

async fn serve_metrics(// State(state): State<Arc<AppState>>,
    // headers: HeaderMap,
) -> Result<(StatusCode, String), AppError> {
    // let mut header_map = HeaderMap::new();
    let mut buffer = String::new();
    prometheus_client::encoding::text::encode(&mut buffer, &METRICS.registry).map_err(AppError::new)?;
    Ok((http::StatusCode::OK, buffer))
}
