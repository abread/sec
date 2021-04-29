use crate::Conf;
use model::keys::EntityId;
use model::neighbourhood::are_neighbours;
use model::Position;
use rand::prelude::*;
use std::collections::HashMap;

pub struct State {
    epoch: u64,

    /// Positions of correct users
    grid: HashMap<EntityId, Position>,
}

impl State {
    pub fn new(conf: &Conf) -> Self {
        let mut rng = thread_rng();
        State {
            epoch: 0,
            grid: conf
                .correct_users
                .iter()
                .map(|id| {
                    let pos = Position(
                        rng.gen_range(0..conf.dims.0 as u64),
                        rng.gen_range(0..conf.dims.1 as u64),
                    );
                    (*id, pos)
                })
                .collect(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn position_of(&self, id: EntityId) -> Position {
        self.grid.get(&id).copied().unwrap()
    }

    /// Generate neighbourhoods for a correct user.
    /// A neighbourhood is a vector of (EntityId, x, y) tuples.
    ///
    /// Here neighbourhood is definded by the `neighbourhood` function
    /// (it could be further abstracted, but there is no need)
    ///
    pub fn get_visible_neighbourhood(&self, conf: &Conf, id: EntityId) -> Vec<EntityId> {
        /// Fill a neighbourhood with some malicious users
        /// (making sure they never exceed the incorrectness limit)
        ///
        fn fill_neighbourhood(neighbourhood: &mut Vec<EntityId>, conf: &Conf) {
            let mut rng = thread_rng();
            let n_malicious: usize = rng.gen_range(0..=conf.max_neighbourhood_faults);

            neighbourhood.reserve(n_malicious);
            for (entity_id, _) in conf.malicious_users.choose_multiple(&mut rng, n_malicious) {
                neighbourhood.push(*entity_id)
            }
        }

        let pos = self.position_of(id);
        let mut neighbourhood = self
            .grid
            .iter()
            .filter(|(nid, _)| **nid != id)
            .filter(|(_, npos)| are_neighbours(&pos, npos))
            .map(|(id, _)| *id)
            .collect();

        fill_neighbourhood(&mut neighbourhood, conf);

        neighbourhood
    }

    /// Generate the full set of correct EntityId's, with positions.
    /// This is what the malicious nodes receive.
    pub fn get_correct_users(&self) -> Vec<(EntityId, Position)> {
        self.grid.iter().map(|(id, pos)| (*id, *pos)).collect()
    }

    /// Advance the epoch
    pub fn advance(&mut self, conf: &Conf) {
        let mut rng = thread_rng();
        self.epoch += 1;

        for pos in self.grid.values_mut() {
            *pos = Position(
                rng.gen_range(0..conf.dims.0 as u64),
                rng.gen_range(0..conf.dims.1 as u64),
            );
        }
    }
}
