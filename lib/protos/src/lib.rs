pub mod hdlt {
    tonic::include_proto!("hdlt");
}
pub mod driver {
    tonic::include_proto!("driver");
}
pub mod util {
    tonic::include_proto!("util");

    impl From<model::Position> for Position {
        fn from(p: model::Position) -> Self {
            Position {
                x: p.0,
                y: p.1,
            }
        }
    }

    impl From<Position> for model::Position {
        fn from(p: Position) -> Self {
            model::Position(p.x, p.y)
        }
    }
}
pub mod witness {
    use std::convert::{TryFrom, TryInto};
    use model::keys::Signature;
    use thiserror::Error;

    tonic::include_proto!("witness");

    impl From<model::ProximityProofRequest> for ProximityProofRequest {
        fn from(r: model::ProximityProofRequest) -> Self {
            ProximityProofRequest {
                prover_id: *r.prover_id(),
                epoch: r.epoch(),
                prover_position: Some((*r.position()).into()),
                signature: r.signature().0.to_vec(),
            }
        }
    }

    impl From<model::ProximityProof> for ProximityProofResponse {
        fn from(p: model::ProximityProof) -> Self {
            ProximityProofResponse {
                request: Some(p.request().clone().into()),
                witness_id: *p.witness_id(),
                witness_position: Some((*p.witness_position()).into()),
                witness_signature: p.signature().0.to_vec(),
            }
        }
    }

    #[derive(Debug, Error)]
    pub enum ParseError {
        #[error("Signature is of an invalid format")]
        BadSignature,

        #[error("Position field not present")]
        MissingPosition,

        #[error("Position field not present")]
        MissingRequest,
    }

    impl TryFrom<ProximityProofRequest> for model::UnverifiedProximityProofRequest {
        type Error = ParseError;

        fn try_from(r: ProximityProofRequest) -> Result<Self, Self::Error> {
            Ok(model::UnverifiedProximityProofRequest {
                prover_id: r.prover_id,
                position: r.prover_position.ok_or(ParseError::MissingPosition)?.into(),
                epoch: r.epoch,
                signature: Signature::from_slice(&r.signature).ok_or(ParseError::BadSignature)?,
            })
        }
    }

    impl TryFrom<ProximityProofResponse> for model::UnverifiedProximityProof {
        type Error = ParseError;

        fn try_from(p: ProximityProofResponse) -> Result<Self, Self::Error> {
            Ok(model::UnverifiedProximityProof {
                request: p.request.ok_or(ParseError::MissingRequest)?.try_into()?,
                witness_id: p.witness_id,
                witness_position: p.witness_position.ok_or(ParseError::MissingPosition)?.into(),
                signature: Signature::from_slice(&p.witness_signature).ok_or(ParseError::BadSignature)?,
            })
        }
    }
}
