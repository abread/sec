/// Client State
use model::Position;

#[derive(Debug, Default)]
pub struct CorrectClientState {
    epoch: u64,
    position: Position,
    visible_neighbours: Vec<tonic::transport::Uri>,
    max_faults: u64,
}

impl CorrectClientState {
    pub fn new() -> Self {
        CorrectClientState {
            epoch: 0,
            position: Position(0, 0),
            visible_neighbours: vec![],
            max_faults: 0,
        }
    }

    pub fn update(
        &mut self,
        epoch: u64,
        position: Position,
        neighbours: Vec<tonic::transport::Uri>,
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

    pub fn position(&self) -> &Position {
        &self.position
    }
}

#[derive(Debug)]
pub struct Neighbour {
    pub position: Position,
    pub uri: tonic::transport::Uri,
}

impl Neighbour {
    pub fn from_proto(proto: protos::util::Neighbour) -> Self {
        let pos = proto.pos.unwrap();
        Neighbour {
            position: Position(pos.x, pos.y),
            uri: proto.uri.parse().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
pub struct MaliciousClientState {
    epoch: u64,
    correct_neighbours: Vec<Neighbour>,
    malicious_neighbours: Vec<tonic::transport::Uri>,
}

impl MaliciousClientState {
    pub fn new() -> Self {
        MaliciousClientState {
            epoch: 0,
            correct_neighbours: vec![],
            malicious_neighbours: vec![],
        }
    }

    pub fn update(
        &mut self,
        epoch: u64,
        correct: Vec<Neighbour>,
        malicious: Vec<tonic::transport::Uri>,
    ) {
        self.epoch = epoch;
        self.correct_neighbours = correct;
        self.malicious_neighbours = malicious;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
