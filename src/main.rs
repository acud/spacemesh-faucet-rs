use ed25519::signature::{Signer, Verifier};
use std::io::{stdout, BufWriter};

use axum::{
    body::Bytes,
    extract::{MatchedPath, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
mod faucet;
mod grpc;
mod hex;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = ".keyfile")]
    keyfile: String,
    #[arg(long, default_value = "localhost:3000")]
    http_bind_address: String,

    #[arg(long, default_value = "localhost:3999")]
    rpc_address: String,
}

const LANDING: &[u8; 3049] = include_bytes!("page.html");
const KEYPAIR_LEN: usize = 64;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    tracing::info!("opening keyfile at {}", args.keyfile);
    let keyfile = fs::read(args.keyfile);
    if let Err(e) = keyfile {
        tracing::error!("error opening keyfile: {}", e);
        return Err(e.into());
    }

    let kb = String::from_utf8(keyfile.unwrap())?;
    let mut trimmed = false;
    let kb = kb.trim_end_matches(|c| {
        if !trimmed && c == '\n' {
            trimmed = true;
            true
        } else {
            false
        }
    });
    let keybytes = hex::decode_hex(&kb)?;
    if keybytes.len() != KEYPAIR_LEN {
        tracing::error!("expected a {} byte key length", KEYPAIR_LEN);
        return Ok(());
    }
    let keybytes: [u8; KEYPAIR_LEN] = keybytes.try_into().unwrap();
    let signing_key = SigningKey::from_keypair_bytes(&keybytes).unwrap();
    let grpc_svc = crate::grpc::RpcClient::new(args.rpc_address).await;
    let fct = faucet::Faucet::new(signing_key, grpc_svc);
    let pubkey = fct.public_key().to_bytes();
    tracing::info!(
        "initialized faucet with public key: {}",
        hex::encode_hex(&pubkey)
    );
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/sign", post(handle_sign))
        .with_state(Arc::new(fct))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    // Log the matched route's path (with placeholders not filled in).
                    // Use request.uri() or OriginalUri if you want the real path.
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                })
                .on_request(|_request: &Request<_>, _span: &Span| {
                    // You can use `_span.record("some_other_field", value)` in one of these
                    // closures to attach a value to the initially empty field in the info_span
                    // created above.
                    tracing::info!("got request");
                })
                .on_response(|response: &Response, _latency: Duration, _span: &Span| {
                    // ...
                    let stat = response.status();
                    let stat = stat.as_str();
                    info_span!("status", "stat {} ", stat);
                    tracing::info!("sending response");
                })
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        // ...
                        tracing::info!("on fail");
                    },
                ),
        );

    // run our app with hyper, listening globally on port 3000
    tracing::info!(
        "starting http server with bind address: {}",
        args.http_bind_address
    );
    let listener = tokio::net::TcpListener::bind(args.http_bind_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    return Ok(());
}

async fn handle_sign<S: grpc::Nonce>(
    State(state): State<Arc<faucet::Faucet<S>>>,
    Json(payload): Json<DripTx>,
) -> (StatusCode, Json<TxId>) {
    let sig = state.sign(payload).await.unwrap();

    let tx = TxId {
        tx: crate::hex::encode_hex(sig.as_slice()),
    };

    (StatusCode::OK, Json(tx))
}

async fn root() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "text/html; charset=utf-8".parse().unwrap());
    let out: String;
    unsafe { out = String::from_utf8_unchecked(LANDING.into()) };

    (headers, out)
}

async fn health() -> (StatusCode, Json<RootResponse>) {
    (
        StatusCode::OK,
        Json(RootResponse {
            status: String::from("ok"),
        }),
    )
}

#[derive(Serialize)]
struct RootResponse {
    status: String,
}

#[derive(Serialize, Deserialize)]
struct TxId {
    tx: String,
}

#[derive(Deserialize)]
struct DripTx {
    address: String,
    amount: u64,
}
