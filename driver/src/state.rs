use crate::Conf;
use model::keys::EntityId;
use model::neighbourhood::are_neighbours;
use model::Position;
use rand::prelude::*;

pub struct State {
    epoch: u64,

    /// Position of the correct nodes
    /// The indeces match indeces to Conf::correct
    ///
    grid: Vec<Position>,
}

impl State {
    pub fn new(conf: &Conf) -> Self {
        let mut rng = thread_rng();
        State {
            epoch: 0,
            grid: (0..conf.n_correct_users())
                .map(|_| {
                    Position(
                        rng.gen_range(0..conf.dims.0 as u64),
                        rng.gen_range(0..conf.dims.1 as u64),
                    )
                })
                .collect(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn position_of(&self, idx: usize) -> Position {
        self.grid[idx]
    }

    /// Generate neighbourhoods for a correct user.
    /// A neighbourhood is a vector of (EntityId, x, y) tuples.
    ///
    /// Here neighbourhood is definded by the `neighbourhood` function
    /// (it could be further abstracted, but there is no need)
    ///
    pub fn get_visible_neighbourhood(&self, conf: &Conf, idx: usize) -> Vec<EntityId> {
        /// Fill a neighbourhood with some malicious users
        /// (making sure they never exceed the incorrectness limit)
        ///
        fn fill_neighbourhood(mut neighbourhood: Vec<EntityId>, conf: &Conf) -> Vec<EntityId> {
            let mut rng = thread_rng();
            let n_malicious: usize = rng.gen_range(0..(conf.max_neighbourhood_faults + 1));
            neighbourhood.reserve(n_malicious);
            for (entity_id, _) in conf.malicious_users.choose_multiple(&mut rng, n_malicious) {
                neighbourhood.push(*entity_id)
            }

            neighbourhood
        }
        fill_neighbourhood(
            self.grid
                .iter()
                .enumerate()
                .filter(|(_, a)| are_neighbours(&self.grid[idx], a))
                .map(|(i, _)| conf.correct_users[i])
                .collect(),
            conf,
        )
    }

    /// Generate the full set of correct EntityId's, with positions.
    /// This is what the malicious nodes receive.
    pub fn get_correct_users(&self, conf: &Conf) -> Vec<(EntityId, Position)> {
        self.grid
            .iter()
            .enumerate()
            .map(|(idx, p)| (conf.correct_users[idx], *p))
            .collect()
    }

    /// Advance the epoch
    pub fn advance(&mut self, conf: &Conf) {
        let mut rng = thread_rng();
        self.epoch += 1;
        self.grid = (0..conf.n_correct_users())
            .map(|_| {
                Position(
                    rng.gen_range(0..conf.dims.0 as u64),
                    rng.gen_range(0..conf.dims.1 as u64),
                )
            })
            .collect()
    }
}
