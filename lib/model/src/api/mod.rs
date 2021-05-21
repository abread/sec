use serde::{Deserialize, Serialize};

mod rr_message;
pub use rr_message::*;

mod pow;
pub use pow::*;

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
    SubmitPositionReport(PoWProtected<UnverifiedPositionProof>),

    /// Query the position of a given user at a given epoch.
    ///
    /// Regular users may only query their own position. HA clients may query
    /// any user's position.
    ///
    /// Successful reply: [ApiReply::PositionReport]
    /// Error reply: [ApiReply::Error]
    ObtainPositionReport { user_id: EntityId, epoch: u64 },

    /// Get all position reports from a user in a given epoch range.
    ///
    /// Regular users may only query their own position. HA clients may query
    /// any user's position.
    ///
    /// Successful reply: [ApiReply::PositionReport]
    /// Error reply: [ApiReply::Error]
    RequestPositionReports { epoch_start: u64, epoch_end: u64 },

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
    ///
    /// @bsd: Shouldn't this return the PositionProof (you know, as the name indicates??) (TODO)
    PositionReport(u64, Position),

    /// Position of a given user at a series of epochs.
    /// The successful reply for [ApiRequest::RequestPositionReports].
    PositionReports(Vec<(u64, UnverifiedPositionProof)>),

    /// Users in the given position at the given epoch.
    /// The successful reply for [ApiRequest::ObtainUsersAtPosition].
    UsersAtPosition(Vec<EntityId>),

    /// Generic server error message. Can be a reply to any request.
    Error(String),
}

impl ApiReply {
    pub fn key(&self) -> u64 {
        match self {
            // Timestamp == epoch
            ApiReply::PositionReport(epoch, _) => *epoch,

            // Timestamp == epoch
            ApiReply::PositionReports(v) => *v.iter().map(|(e, _)| e).max().unwrap_or(&0u64),

            // Not a timestamp per se, but this request give a particular epoch either way
            // This however returns the longest list === most recent response
            ApiReply::UsersAtPosition(v) => v.len() as u64,

            _ => 0,
        }
    }
}
