use eyre::eyre;
use json::JsonValue;
use model::keys::EntityId;
use std::{collections::HashMap, convert::TryFrom};
use tonic::transport::Uri;

#[derive(Clone)]
pub struct Conf {
    /// width x height
    pub dims: (usize, usize),

    /// Neighbourhood fault tolerance
    pub max_neighbourhood_faults: usize,

    /// Server fault tolerance
    pub max_server_faults: usize,

    /// Servers
    pub correct_servers: Vec<EntityId>,

    /// Correct Users
    pub correct_users: Vec<EntityId>,

    /// Malicious Users
    ///
    /// Vec of (user id, type code)
    pub malicious_users: Vec<(EntityId, u32)>,

    /// Mapping of IDs to URIs
    pub id_to_uri: HashMap<EntityId, Uri>,
}

impl Conf {
    /// number of correct users
    pub fn n_correct_users(&self) -> usize {
        self.correct_users.len()
    }

    /// Get all malicious users except the user itself
    /// Also returns the users's type code
    /// Panic: if user_idx is not a valid index
    pub fn get_malicious_neighbours(&self, id: EntityId) -> (Vec<EntityId>, u32) {
        let neigh = self
            .malicious_users
            .iter()
            .filter(|(nid, _)| *nid != id)
            .map(|(nid, _)| *nid)
            .collect();

        let type_code = self
            .malicious_users
            .iter()
            .find(|(uid, _)| *uid == id)
            .map(|(_, type_code)| *type_code)
            .unwrap();
        (neigh, type_code)
    }

    pub fn id_to_uri(&self, id: EntityId) -> &Uri {
        &self.id_to_uri[&id]
    }
}

impl TryFrom<&JsonValue> for Conf {
    type Error = eyre::Report;

    fn try_from(json: &JsonValue) -> eyre::Result<Conf> {
        if !json.has_key("width") {
            return Err(eyre!("configuration requires a width"));
        }
        if !json.has_key("height") {
            return Err(eyre!("configuration requires a height"));
        }
        if !json.has_key("max_neighbourhood_faults") {
            return Err(eyre!("configuration requires the maximum number of faults in the neighbourhood of a node"));
        }
        if !json.has_key("max_server_faults") {
            return Err(eyre!(
                "configuration requires the maximum number of faults in the server set"
            ));
        }
        if !json.has_key("users") {
            return Err(eyre!("configuration requires a list of users"));
        }

        if json["width"].as_usize().is_none() {
            return Err(eyre!("width needs to be an unsigned integer"));
        }
        if json["height"].as_usize().is_none() {
            return Err(eyre!("height needs to be an unsigned integer"));
        }
        let dims = (
            json["width"].as_usize().unwrap(),
            json["height"].as_usize().unwrap(),
        );

        if json["max_neighbourhood_faults"].as_usize().is_none() {
            return Err(eyre!(
                "max_neighbourhood_faults needs to be an unsigned integer"
            ));
        }
        let max_neighbourhood_faults = json["max_neighbourhood_faults"].as_usize().unwrap();

        if json["max_server_faults"].as_usize().is_none() {
            return Err(eyre!("max_server_faults needs to be an unsigned integer"));
        }
        let max_server_faults = json["max_server_faults"].as_usize().unwrap();

        if !json["users"].is_array() {
            return Err(eyre!("users needs to be an array"));
        }

        let mut correct_users = Vec::with_capacity(json["users"].len());
        let mut malicious_users = Vec::with_capacity(json["users"].len());
        let mut id_to_uri = HashMap::new();
        for c in json["users"].members() {
            if !c.has_key("entity_id") {
                return Err(eyre!("user requires an entity_id"));
            }
            if !c["entity_id"].is_number() {
                return Err(eyre!("user entity_id must be a string"));
            }
            if !c.has_key("uri") {
                return Err(eyre!("user requires an uri"));
            }
            if !c["uri"].is_string() {
                return Err(eyre!("user uri must be a string"));
            }

            let entity_id: EntityId = c["entity_id"].as_u32().unwrap();
            if c.has_key("malicious") {
                if !c["malicious"].is_string() {
                    return Err(eyre!("malicious flag must be a string"));
                }
                let m_type = c["malicious"].as_str().unwrap();
                let type_code = match m_type {
                    "honest_omnipresent" | "HbO" => 0,
                    "poor_verifier" | "PV" => 1,
                    "teleporter" | "T" => 2,
                    _ => return Err(eyre!("`malicious` must be one of\n - honest_omnipresent | HbO\n - poor_verifier | PV\n - teleporter | T"))

                };
                malicious_users.push((entity_id, type_code));
            } else {
                correct_users.push(entity_id);
            }

            let uri: Uri = c["uri"].as_str().unwrap().parse()?;
            id_to_uri.insert(entity_id, uri);
        }

        let mut correct_servers = Vec::with_capacity(json["servers"].len());
        for s in json["servers"].members() {
            if !s.has_key("entity_id") {
                return Err(eyre!("server requires an entity_id"));
            }
            if !s["entity_id"].is_number() {
                return Err(eyre!("server entity_id must be a string"));
            }
            if !s.has_key("uri") {
                return Err(eyre!("server requires an uri"));
            }
            if !s["uri"].is_string() {
                return Err(eyre!("server uri must be a string"));
            }

            let entity_id: EntityId = s["entity_id"].as_u32().unwrap();
            let uri: Uri = s["uri"].as_str().unwrap().parse()?;
            correct_servers.push(entity_id);
            id_to_uri.insert(entity_id, uri);
        }

        Ok(Conf {
            dims,
            max_neighbourhood_faults,
            max_server_faults,
            correct_servers,
            correct_users,
            malicious_users,
            id_to_uri,
        })
    }
}
