use model::{keys::EntityId, Position};
/// Client State
use std::collections::HashMap;
use tonic::transport::Uri;

/// State of a correct client
#[derive(Debug, Default)]
pub struct CorrectClientState {
    /// Current Epoch
    epoch: u64,

    /// Current position
    position: Position,

    /// Visible neighbours
    visible_neighbours: Vec<EntityId>,

    /// Map of the Uris for all users in the system
    id_to_uri: HashMap<EntityId, Uri>,

    /// Upper bound on faults in the neighbourhood
    max_faults: u64,
}

impl CorrectClientState {
    /// Create a new state
    pub fn new() -> Self {
        CorrectClientState {
            epoch: 0,
            position: Position(0, 0),
            visible_neighbours: vec![],
            max_faults: 0,
            id_to_uri: HashMap::new(),
        }
    }

    /// Update state with information from the driver
    pub fn update(
        &mut self,
        epoch: u64,
        position: Position,
        neighbours: Vec<EntityId>,
        max_faults: u64,
    ) {
        self.epoch = epoch;
        self.position = position;
        self.visible_neighbours = neighbours;
        self.max_faults = max_faults;
    }

    /// Getter for epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Getter for position
    pub fn position(&self) -> &Position {
        &self.position
    }

    /// Getter for max_faults
    pub fn max_faults(&self) -> u64 {
        self.max_faults
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
    pub fn neighbourhood(&self) -> impl Iterator<Item = &EntityId> {
        self.visible_neighbours.iter()
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

/// State of a malicious client
#[derive(Debug, Default)]
pub struct MaliciousClientState {
    /// Current Epoch
    epoch: u64,

    /// Correct users are in the system
    correct_neighbours: Vec<Neighbour>,

    /// Malicious users in the system
    malicious_neighbours: Vec<EntityId>,

    /// Map of the Uris for all users in the system
    id_to_uri: HashMap<EntityId, Uri>,
}

impl MaliciousClientState {
    /// Create a new state
    pub fn new() -> Self {
        MaliciousClientState {
            epoch: 0,
            correct_neighbours: vec![],
            malicious_neighbours: vec![],
            id_to_uri: HashMap::new(),
        }
    }

    /// Update state with information from the driver
    pub fn update(&mut self, epoch: u64, correct: Vec<Neighbour>, malicious: Vec<EntityId>) {
        self.epoch = epoch;
        self.correct_neighbours = correct;
        self.malicious_neighbours = malicious;
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
}
