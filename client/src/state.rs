/// Client State
///

#[derive(Debug)]
pub struct CorrectClientState {
    epoch: usize,
    position: (usize, usize),
    visible_neighbours: Vec<tonic::transport::Uri>,
}

impl CorrectClientState {
    pub fn new() -> Self {
        CorrectClientState {
            epoch: 0,
            position: (0, 0),
            visible_neighbours: vec![],
        }
    }

    pub fn update(&mut self, epoch: usize, position: (usize, usize), neighbours: Vec<tonic::transport::Uri>) {
        self.epoch = epoch;
        self.position = position;
        self.visible_neighbours = neighbours;
    }
}

#[derive(Debug)]
pub struct Neighbour {
    pub position: (usize, usize),
    pub uri: tonic::transport::Uri,
}

impl Neighbour {
    pub fn from_proto(proto: protos::util::Neighbour) -> Self {
        let pos = proto.pos.unwrap();
        Neighbour {
            position: (pos.x as usize, pos.y as usize),
            uri: proto.uri.parse().unwrap()
        }
    }
}

#[derive(Debug)]
pub struct MaliciousClientState {
    epoch: usize,
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

    pub fn update(&mut self, epoch: usize, correct: Vec<Neighbour>, malicious: Vec<tonic::transport::Uri>) {
        self.epoch = epoch;
        self.correct_neighbours = correct;
        self.malicious_neighbours = malicious;
    }
}
