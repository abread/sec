/// Client State
use model::{keys::EntityId, neighbourhood::are_neighbours, Position};
use rand::Rng;
use std::collections::HashMap;
use tonic::transport::Uri;

/// State of a correct user
#[derive(Debug, Default)]
pub struct CorrectUserState {
    /// Current Epoch
    epoch: u64,

    /// Current position
    position: Position,

    /// Visible neighbours
    visible_neighbours: Vec<EntityId>,

    /// Map of the Uris for all users in the system
    id_to_uri: HashMap<EntityId, Uri>,

    /// Upper bound on faults in the neighbourhood
    neighbour_faults: u64,

    /// Upper bound on faults in the neighbourhood
    server_faults: u64,
}

impl CorrectUserState {
    /// Create a new state
    pub fn new() -> Self {
        CorrectUserState {
            epoch: 0,
            position: Position(0, 0),
            visible_neighbours: vec![],
            neighbour_faults: 0,
            server_faults: 0,
            id_to_uri: HashMap::new(),
        }
    }

    /// Update state with information from the driver
    pub fn update(
        &mut self,
        epoch: u64,
        position: Position,
        neighbours: Vec<EntityId>,
        neighbour_faults: u64,
        server_faults: u64,
    ) {
        self.epoch = epoch;
        self.position = position;
        self.visible_neighbours = neighbours;
        self.neighbour_faults = neighbour_faults;
        self.server_faults = server_faults;
    }

    /// Getter for epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Getter for position
    pub fn position(&self) -> Position {
        self.position
    }

    /// Getter for neighbour_faults
    pub fn neighbour_faults(&self) -> u64 {
        self.neighbour_faults
    }

    /// Getter for server faults
    pub fn server_faults(&self) -> u64 {
        self.server_faults
    }

    /// Fill the id_to_uri table, allowing for translation
    pub fn add_mappings(&mut self, hash_map: HashMap<EntityId, String>) {
        self.id_to_uri.extend(
            hash_map
                .iter()
                .map(|(&k, v)| (k, v.parse::<Uri>().unwrap())),
        );
    }

    /// Convert an id in an Uri
    pub fn id_to_uri(&self, id: EntityId) -> &Uri {
        &self.id_to_uri[&id]
    }

    /// Iterator over the neighbourhood
    pub fn neighbourhood(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.visible_neighbours.iter().copied()
    }
}

/// A neighbour of a node
#[derive(Debug)]
pub struct Neighbour {
    pub position: Position,
    pub id: EntityId,
}

impl Neighbour {
    pub fn from_proto(proto: protos::util::Neighbour) -> Self {
        let pos = proto.pos.unwrap();
        Neighbour {
            position: Position(pos.x, pos.y),
            id: proto.id,
        }
    }
}

/// A malicious user can have several types, which dictate its operation
#[derive(Debug, Clone, Copy)]
pub enum MaliciousType {
    /// Chooses a random position and behaves correctly
    HonestOmnipresent,

    /// HonestOmnipresent but never verifies anything
    PoorVerifier,

    /// PoorVerifier but never chooses a position (ie: is always changing)
    Teleporter,
}

impl Default for MaliciousType {
    fn default() -> Self {
        MaliciousType::HonestOmnipresent
    }
}

impl From<u32> for MaliciousType {
    fn from(code: u32) -> Self {
        match code {
            0 => MaliciousType::HonestOmnipresent,
            1 => MaliciousType::PoorVerifier,
            2 => MaliciousType::Teleporter,
            _ => Self::default(),
        }
    }
}

/// State of a malicious user
#[derive(Debug, Default)]
pub struct MaliciousUserState {
    /// Current Epoch
    epoch: u64,

    /// Position which the user has committed to
    position: Option<Position>,

    /// Correct users are in the system
    correct_neighbours: Vec<Neighbour>,

    /// Malicious users in the system
    malicious_neighbours: Vec<EntityId>,

    /// Map of the Uris for all users in the system
    /// (constant field after init)
    id_to_uri: HashMap<EntityId, Uri>,

    /// Type of malicious action
    malicious_type: MaliciousType,

    /// Upper bound on faults in the neighbourhood
    neighbour_faults: u64,

    /// Upper bound on server faults
    server_faults: u64,
}

impl MaliciousUserState {
    /// Create a new state
    pub fn new() -> Self {
        MaliciousUserState {
            epoch: 0,
            position: None,
            correct_neighbours: vec![],
            malicious_neighbours: vec![],
            id_to_uri: HashMap::new(),
            malicious_type: MaliciousType::default(),
            neighbour_faults: 0,
            server_faults: 0,
        }
    }

    /// Update state with information from the driver
    pub fn update(
        &mut self,
        epoch: u64,
        correct: Vec<Neighbour>,
        malicious: Vec<EntityId>,
        type_code: u32,
        neighbour_faults: u64,
        server_faults: u64,
    ) {
        self.epoch = epoch;
        self.position = None;
        self.correct_neighbours = correct;
        self.malicious_neighbours = malicious;
        self.malicious_type = type_code.into();
        self.neighbour_faults = neighbour_faults;
        self.server_faults = server_faults;
    }

    /// Getter for epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Fill the id_to_uri table, allowing for translation
    pub fn add_mappings(&mut self, hash_map: HashMap<EntityId, String>) {
        self.id_to_uri.extend(
            hash_map
                .iter()
                .map(|(&k, v)| (k, v.parse::<Uri>().unwrap())),
        );
    }

    /// Convert an id in an Uri
    pub fn id_to_uri(&self, id: EntityId) -> &Uri {
        &self.id_to_uri[&id]
    }

    /// Generate a valid random position
    pub fn generate_position(&self) -> Position {
        let (xmin, xmax, ymin, ymax) = self.correct_neighbours.iter().fold(
            (i64::MAX, i64::MIN, i64::MAX, i64::MIN),
            |(xmin, xmax, ymin, ymax), neigh| {
                (
                    xmin.min(neigh.position.0),
                    xmax.max(neigh.position.0),
                    ymin.min(neigh.position.1),
                    ymax.max(neigh.position.1),
                )
            },
        );

        let mut rng = rand::thread_rng();
        Position(
            rng.gen_range(xmin..(xmax + 1)),
            rng.gen_range(ymin..(ymax + 1)),
        )
    }

    /// Generate a valid random position and commit to it
    pub fn choose_position(&mut self) -> Position {
        if self.position.is_none() {
            self.position = Some(self.generate_position());
        }
        self.position()
    }

    /// Getter for server faults
    pub fn server_faults(&self) -> u64 {
        self.server_faults
    }

    /// Getter for neighbour_faults
    pub fn neighbour_faults(&self) -> u64 {
        self.neighbour_faults
    }

    /// Return the position
    /// Panic: if there is no position
    pub fn position(&self) -> Position {
        self.position.unwrap()
    }

    /// Return the type of malicious user
    pub fn malicious_type(&self) -> MaliciousType {
        self.malicious_type
    }

    /// Iterator over the neighbourhood of a position
    pub fn neighbourhood<'this>(
        &'this self,
        position: Position,
    ) -> impl Iterator<Item = EntityId> + 'this {
        self.correct_neighbours
            .iter()
            .filter(move |n| are_neighbours(n.position, position))
            .map(|n| &n.id)
            .chain(self.malicious_neighbours.iter())
            .copied()
    }
}
