use crate::maybe_tracing::*;
use crate::util::{TestConfig, TestEnv};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn happy_path_test() {
    let _guard =
        tracing_utils::setup(env!("CARGO_PKG_NAME"), vec![("test", "happy_path_test")]).unwrap();

    let env = TestEnv::new(TestConfig {
        n_correct_users: 5,
        n_ha_clients: 0,
        n_malicious_users: 0,
        max_neigh_faults: 1,
        dims: (400, 400),
    })
    .await;

    info!("Tick");
    env.driver.tick().await.unwrap();

    info!("Asking users to prove their positions");
    if let Err(errs) = env.driver.prove_position_all().await {
        warn!(event = "Some users could not prove their position", ?errs);
    }
}
