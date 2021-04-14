use serde::{Deserialize, Serialize};

mod rr_message;
pub use rr_message::*;

use crate::{keys::EntityId, Location, UnverifiedLocationProof};

/// An HDLT Server API request payload.
/// Use [RrMessage] for secure communication.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ApiRequest {
    /// Request to register a new location proof.
    ///
    /// Can be used by any user to register any location proof.
    ///
    /// Successful reply: [ApiReply::Ok]
    /// Error reply: [ApiReply::Error]
    SubmitLocationReport(UnverifiedLocationProof),
    /// Query the location of a given user at a given epoch.
    ///
    /// Regular users may only query their own location. HA clients may query
    /// any user's location.
    ///
    /// Successful reply: [ApiReply::LocationReport]
    /// Error reply: [ApiReply::Error]
    ObtainLocationReport { user_id: EntityId, epoch: u64 },
    /// Query the users present in a given location at a given epoch.
    ///
    /// Only HA clients can request this.
    ///
    /// Successful reply: [ApiReply::LocationReport]
    /// Error reply: [ApiReply::Error]
    ObtainUsersAtLocation { location: Location, epoch: u64 },
}

/// An HDLT Server API reply payload.
/// Use [RrMessage] for secure communication.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ApiReply {
    /// Generic successful indication.
    /// The successful reply for [ApiRequest::SubmitLocationReport].
    Ok,
    /// Location of a given user at a given epoch.
    /// The successful reply for [ApiRequest::ObtainLocationReport].
    LocationReport(Location),
    /// Users in the given location at the given epoch.
    /// The successful reply for [ApiRequest::ObtainUsersAtLocation].
    UsersAtLocation(Vec<EntityId>),
    /// Generic server error message. Can be a reply to any request.
    Error(String),
}
