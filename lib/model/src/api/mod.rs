use serde::{Deserialize, Serialize};

mod rr_message;
pub use rr_message::*;

use crate::{keys::EntityId, Position, UnverifiedPositionProof};

/// An HDLT Server API request payload.
/// Use [RrMessage] for secure communication.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ApiRequest {
    /// Request to register a new position proof.
    ///
    /// Can be used by any user to register any position proof.
    ///
    /// Successful reply: [ApiReply::Ok]
    /// Error reply: [ApiReply::Error]
    SubmitPositionReport(UnverifiedPositionProof),
    /// Query the position of a given user at a given epoch.
    ///
    /// Regular users may only query their own position. HA clients may query
    /// any user's position.
    ///
    /// Successful reply: [ApiReply::PositionReport]
    /// Error reply: [ApiReply::Error]
    ObtainPositionReport { user_id: EntityId, epoch: u64 },
    /// Query the users present in a given position at a given epoch.
    ///
    /// Only HA clients can request this.
    ///
    /// Successful reply: [ApiReply::PositionReport]
    /// Error reply: [ApiReply::Error]
    ObtainUsersAtPosition { position: Position, epoch: u64 },
}

/// An HDLT Server API reply payload.
/// Use [RrMessage] for secure communication.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ApiReply {
    /// Generic successful indication.
    /// The successful reply for [ApiRequest::SubmitPositionReport].
    Ok,
    /// Position of a given user at a given epoch.
    /// The successful reply for [ApiRequest::ObtainPositionReport].
    PositionReport(Position),
    /// Users in the given position at the given epoch.
    /// The successful reply for [ApiRequest::ObtainUsersAtPosition].
    UsersAtPosition(Vec<EntityId>),
    /// Generic server error message. Can be a reply to any request.
    Error(String),
}
