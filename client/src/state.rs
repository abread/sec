use std::collections::HashMap;

/// Client State
use model::keys::EntityId;
use model::Position;
use tonic::transport::Uri;

#[derive(Debug, Default)]
pub struct CorrectClientState {
    epoch: u64,
    position: Position,
    visible_neighbours: Vec<EntityId>,
    id_to_uri: HashMap<EntityId, Uri>,
    max_faults: u64,
}

impl CorrectClientState {
    pub fn new() -> Self {
        CorrectClientState {
            epoch: 0,
            position: Position(0, 0),
            visible_neighbours: vec![],
            max_faults: 0,
            id_to_uri: HashMap::new(),
        }
    }

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

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_neighbour(&self, _neighbour_id: EntityId) -> bool {
        todo!()
    }

    pub fn add_mappings(&mut self, hash_map: HashMap<EntityId, String>) {
        self.id_to_uri.extend(
            hash_map
                .iter()
                .map(|(&k, v)| (k, v.parse::<Uri>().unwrap())),
        );
    }
}

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

#[derive(Debug, Default)]
pub struct MaliciousClientState {
    epoch: u64,
    correct_neighbours: Vec<Neighbour>,
    malicious_neighbours: Vec<EntityId>,
    id_to_uri: HashMap<EntityId, Uri>,
}

impl MaliciousClientState {
    pub fn new() -> Self {
        MaliciousClientState {
            epoch: 0,
            correct_neighbours: vec![],
            malicious_neighbours: vec![],
            id_to_uri: HashMap::new(),
        }
    }

    pub fn update(&mut self, epoch: u64, correct: Vec<Neighbour>, malicious: Vec<EntityId>) {
        self.epoch = epoch;
        self.correct_neighbours = correct;
        self.malicious_neighbours = malicious;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_neighbour(&self, _neighbour_id: EntityId) -> bool {
        todo!()
    }

    pub fn add_mappings(&mut self, hash_map: HashMap<EntityId, String>) {
        self.id_to_uri.extend(
            hash_map
                .iter()
                .map(|(&k, v)| (k, v.parse::<Uri>().unwrap())),
        );
    }
}
