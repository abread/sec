use protos::driver::driver_server::Driver;
use protos::driver::EpochUpdateRequest;
use protos::util::Empty;

use tonic::{Request, Response, Status};
use tracing::info;
use tracing_utils::instrument_tonic_service;

#[derive(Debug)]
pub struct DriverService();

impl DriverService {
    pub fn new() -> Self {
        Self()
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Driver for DriverService {
    async fn update_epoch(&self, _request: Request<EpochUpdateRequest>) -> GrpcResult<Empty> {
        info!("Working hard to do the thing...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        info!("Thing done");
        Ok(Response::new(Empty {}))
    }
}
