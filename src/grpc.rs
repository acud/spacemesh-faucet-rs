//use tonic::{transport::Server, Request, Response, Status};

use sm_rpc::{
    account_service_client::{self, AccountServiceClient},
    AccountList, AccountRequest,
};
pub mod sm_rpc {
    tonic::include_proto!("sm"); // The string specified here must match the proto package name
}

use mockall::automock;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

#[automock]
pub trait Nonce: Send + Sync {
    async fn next_nonce(&self, address: String) -> Result<u64, Box<dyn Error>>;
}

pub struct NoopRpcClient {}

impl NoopRpcClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl Nonce for NoopRpcClient {
    async fn next_nonce(&self, _: String) -> Result<u64, Box<dyn Error>> {
        Ok(0u64)
    }
}

pub struct RpcClient {
    svc: Arc<Mutex<AccountServiceClient<tonic::transport::Channel>>>,
}

impl Nonce for RpcClient {
    async fn next_nonce(&self, address: String) -> Result<u64, Box<dyn Error>> {
        let l = self
            .list(vec![address])
            .await
            .expect("expected a valid result")
            .into_inner();

        let account = l.accounts.get(0).ok_or("missed zero index")?;

        Ok(account.projected.unwrap().counter)
    }
}

impl RpcClient {
    pub async fn new(path: String) -> Self {
        let svc = account_service_client::AccountServiceClient::connect(path)
            .await
            .unwrap();
        let svc = Arc::new(Mutex::new(svc));
        Self { svc }
    }

    async fn list(
        &self,
        addresses: Vec<String>,
    ) -> Result<tonic::Response<AccountList>, tonic::Status> {
        let req = AccountRequest {
            addresses,
            limit: 1,
            offset: 1,
        };
        let request = tonic::Request::new(req);
        let mut vv = self.svc.lock().await;
        let res = vv.list(request).await?;
        tracing::debug!("RESPONSE={:?}", res);
        Ok(res)
    }
}
