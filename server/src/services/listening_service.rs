use tokio::sync::{oneshot, Mutex};
use tracing::warn;

pub struct ListeningService<T: Clone> {
    listeners: Mutex<Vec<oneshot::Sender<T>>>
}

impl<T: Clone> ListeningService<T> {
    pub fn new() -> Self {
        ListeningService {
            listeners: Mutex::new(Vec::new())
        }
    }

    pub fn send(self, val: T) {
        for l in self.listeners.into_inner() {
            if let Err(_) = l.send(val.clone()) {
                warn!("sending value in channel failed (receiver probably dropped the ball");
            }
        }
    }

    pub async fn wait(&self) -> oneshot::Receiver<T> {
        let (tx, rx) = oneshot::channel();

        self.listeners.lock().await.push(tx);
        rx
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn no_listeners() {
        // let's just see if there are no panics
        let l = ListeningService::new();
        l.send(42);
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_listeners() {
        // let's just see if there are no panics
        let l = ListeningService::new();

        let rx = l.wait().await;
        tokio::spawn(async move {
            assert_eq!(rx.await.unwrap(), 42u64);
        });

        l.send(42u64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn multiple_listeners() {
        // let's just see if there are no panics
        let l = ListeningService::new();

        for _ in 0..10 {
            let rx = l.wait().await;
            tokio::spawn(async move {
                assert_eq!(rx.await.unwrap(), 42u64);
            });
        }

        l.send(42u64);
    }
}
