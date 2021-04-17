use crate::util::{TestConfig, TestEnv};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test() {
    #[cfg(feature = "trace")]
    let _guard = tracing_utils::setup("happy_test").unwrap();

    let _env = TestEnv::new(TestConfig {
        n_correct_users: 10,
        n_ha_clients: 0,
        n_malicious_users: 0,
        max_neigh_faults: 1,
        dims: (1000, 1000),
    })
    .await;

    // TODO: this fails currently heh
    //env.tick().await;
}
