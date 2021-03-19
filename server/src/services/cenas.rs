use protos::cenas_server::Cenas;
use protos::Empty;

use tonic::{Request, Response, Status};
use tracing::{info, instrument};
use super::propagate_trace_ctx;

#[derive(Debug)]
pub struct CenasService();

impl CenasService {
    pub fn new() -> Self {
        Self()
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[tonic::async_trait]
impl Cenas for CenasService {
    #[instrument]
    async fn dothething(&self, request: Request<Empty>) -> GrpcResult<Empty> {
        propagate_trace_ctx(&request);

        info!("Working hard to do the thing...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        info!("Thing done");
        Ok(Response::new(Empty {}))
    }
}
