/// Client State
use model::keys::EntityId;
use model::Position;

#[derive(Debug, Default)]
pub struct CorrectClientState {
    epoch: u64,
    position: Position,
    visible_neighbours: Vec<tonic::transport::Uri>,
}

impl CorrectClientState {
    pub fn new() -> Self {
        CorrectClientState {
            epoch: 0,
            position: Position(0, 0),
            visible_neighbours: vec![],
        }
    }

    pub fn update(
        &mut self,
        epoch: u64,
        position: Position,
        neighbours: Vec<tonic::transport::Uri>,
    ) {
        self.epoch = epoch;
        self.position = position;
        self.visible_neighbours = neighbours;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_neighbour(&self, _neighbour_id: EntityId) -> bool {
        todo!()
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
}
