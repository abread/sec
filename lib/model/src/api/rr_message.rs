use serde::{Deserialize, Serialize};
use std::convert::{AsMut, AsRef};
use std::ops::{Deref, DerefMut};
use thiserror::Error;

/// A message in a request-reply protocol, generic over the payload.
///
/// When used in a secure channel (confidential and authenticated),
/// it will prevent replay attacks with a challenge-response protocol and guarantee
/// message freshness from a user-supplied epoch (messages from a previous epoch are rejected).
/// It also guarantees that replies are in response to their respective requests.
///
/// Validation is done when downcasting to the underlying [RrRequest] and [RrReply]
/// types, which represent requests and replies respectively. After downcasting,
/// you can use the inner message by reference (they implement [Deref] and [DerefMut]),
/// or extract it with `into_inner`.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum RrMessage<Inner> {
    Request(RrRequest<Inner>),
    Reply(RrReply<Inner>),
}

/// A request in a request-reply protocol, generic over the payload.
///
/// See [RrMessage] for usage.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct RrRequest<Inner> {
    challenge: u64,
    epoch: u64,
    inner: Inner,
}

/// A reply in a request-reply protocol, generic over the payload.
///
/// See [RrMessage] for usage.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct RrReply<Inner> {
    challenge_response: u64,
    epoch: u64,
    inner: Inner,
}

/// A validation error of an [RrMessage].
#[derive(Error, Debug)]
pub enum RrMessageError {
    #[error("Message is not a request")]
    MessageNotRequest,

    #[error("Message is not a reply")]
    MessageNotReply,

    #[error("Message is stale")]
    StaleMessage,

    #[error("Challenge-response validation failed (expected {}, got {})", .expected, .got)]
    ChallengeResponseFailed { expected: u64, got: u64 },
}

impl<Inner> RrMessage<Inner> {
    /// Create a new request message from the given inner payload and epoch.
    pub fn new_request(epoch: u64, inner: Inner) -> Self {
        RrMessage::Request(RrRequest {
            challenge: rand_u64(),
            epoch,
            inner,
        })
    }

    /// Create a new reply message from the given request, epoch and inner payload.
    ///
    /// The request is required to compute the challenge response expected by the requestor.
    pub fn new_reply<OtherInner>(
        request: &RrRequest<OtherInner>,
        epoch: u64,
        inner: Inner,
    ) -> Self {
        RrMessage::Reply(RrReply {
            challenge_response: request.challenge.wrapping_add(1),
            epoch,
            inner,
        })
    }

    /// Downcast message into the underlying request.
    ///
    /// Will check if the message is actually a request and valid (not stale).
    pub fn downcast_request(self, epoch: u64) -> Result<RrRequest<Inner>, RrMessageError> {
        self.assert_not_stale(epoch)?;

        if let RrMessage::Request(req) = self {
            Ok(req)
        } else {
            Err(RrMessageError::MessageNotRequest)
        }
    }

    /// Downcast message into the underlying reply.
    ///
    /// Requires the corresponding request to verify the challenge response of the reply.
    /// Will also validate that the message is a reply, and not stale.
    pub fn downcast_reply<OtherInner>(
        self,
        request: &RrRequest<OtherInner>,
        epoch: u64,
    ) -> Result<RrReply<Inner>, RrMessageError> {
        self.assert_not_stale(epoch)?;

        if let RrMessage::Reply(rep) = self {
            if rep.challenge_response != request.challenge.wrapping_add(1) {
                return Err(RrMessageError::ChallengeResponseFailed {
                    expected: request.challenge.wrapping_add(1),
                    got: rep.challenge_response,
                });
            }

            Ok(rep)
        } else {
            Err(RrMessageError::MessageNotReply)
        }
    }

    /// Error if message is stale.
    fn assert_not_stale(&self, epoch: u64) -> Result<(), RrMessageError> {
        if self.epoch() < epoch {
            Err(RrMessageError::StaleMessage)
        } else {
            Ok(())
        }
    }

    /// Epoch of the message.
    fn epoch(&self) -> u64 {
        match &self {
            RrMessage::Request(req) => req.epoch,
            RrMessage::Reply(rep) => rep.epoch,
        }
    }
}

macro_rules! msg_impls {
    ($type:ident) => {
        impl<Inner> $type<Inner> {
            /// Extract inner message
            pub fn into_inner(self) -> Inner {
                self.inner
            }
        }
        impl<Inner> Deref for $type<Inner> {
            type Target = Inner;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }
        impl<Inner> DerefMut for $type<Inner> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }
        impl<Inner> AsRef<Inner> for $type<Inner> {
            fn as_ref(&self) -> &Inner {
                &self.inner
            }
        }
        impl<Inner> AsMut<Inner> for $type<Inner> {
            fn as_mut(&mut self) -> &mut Inner {
                &mut self.inner
            }
        }
    };
}
msg_impls!(RrRequest);
msg_impls!(RrReply);

/// Generate a random u64 (cryptographically secure)
fn rand_u64() -> u64 {
    use sodiumoxide::randombytes::randombytes_into;

    // Use native endianess for performance (it's random, we don't care about it)
    let mut bytes = 0u64.to_ne_bytes();
    randombytes_into(&mut bytes);
    u64::from_ne_bytes(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref MSG_REQ: RrMessage<u32> = {
            // manually construct it for a deterministic challenge
            RrMessage::Request(RrRequest {
                epoch: 0,
                challenge: 0,
                inner: 42,
            })
        };
        static ref REQ: RrRequest<u32> = MSG_REQ.clone().downcast_request(0).unwrap();
        static ref MSG_REP: RrMessage<u32> = RrMessage::new_reply(&*REQ, 0, 420);
        static ref REP: RrReply<u32> = MSG_REP.clone().downcast_reply(&*REQ, 0).unwrap();
    }

    #[test]
    fn happy_path() {
        crate::ensure_init();

        let msg_req = RrMessage::new_request(42, "some request");
        let req = msg_req.downcast_request(42).unwrap();
        assert_eq!(*req.as_ref(), "some request");

        let msg_reply = RrMessage::new_reply(&req, 43, "some reply");
        let reply = msg_reply.downcast_reply(&req, 42).unwrap();
        assert_eq!(*reply.as_ref(), "some reply");
    }

    #[test]
    fn challenge_response() {
        let mut reply = REP.clone();

        reply.challenge_response = 123;
        let msg = RrMessage::Reply(reply.clone());
        assert!(matches!(
            msg.downcast_reply(&*REQ, 0).unwrap_err(),
            RrMessageError::ChallengeResponseFailed {
                expected: 1,
                got: 123
            }
        ));

        reply.challenge_response = 0;
        let msg = RrMessage::Reply(reply.clone());
        assert!(matches!(
            msg.downcast_reply(&*REQ, 0).unwrap_err(),
            RrMessageError::ChallengeResponseFailed { .. }
        ));

        reply.challenge_response = 1;
        let msg = RrMessage::Reply(reply.clone());
        assert!(msg.downcast_reply(&*REQ, 0).is_ok());
    }

    #[test]
    fn downcast_type() {
        assert!(matches!(
            MSG_REQ.clone().downcast_reply(&*REQ, 0).unwrap_err(),
            RrMessageError::MessageNotReply
        ));
        assert!(MSG_REQ.clone().downcast_request(0).is_ok());
        assert!(matches!(
            MSG_REP.clone().downcast_request(0).unwrap_err(),
            RrMessageError::MessageNotRequest
        ));
        assert!(MSG_REP.clone().downcast_reply(&*REQ, 0).is_ok());
    }

    #[test]
    fn staleness() {
        let msg = RrMessage::new_request(1, ());
        assert!(
            matches!(
                msg.clone().downcast_request(2).unwrap_err(),
                RrMessageError::StaleMessage
            ),
            "Receiving a message in the next epoch is bad: stale!"
        );
        assert!(
            msg.clone().downcast_request(1).is_ok(),
            "Receiving a message in the same epoch is fine"
        );
        assert!(
            msg.clone().downcast_request(0).is_ok(),
            "Receiving a message from a future epoch is fine: we're just a bit behind in our clock"
        );

        for epoch in std::array::IntoIter::new([1, 5]) {
            let msg = RrMessage::new_reply(&*REQ, epoch, ());
            assert!(
                matches!(
                    msg.clone().downcast_reply(&*REQ, epoch + 1).unwrap_err(),
                    RrMessageError::StaleMessage
                ),
                "Receiving a message in the next epoch is bad: stale!"
            );
            assert!(
                msg.clone().downcast_reply(&*REQ, epoch).is_ok(),
                "Receiving a message in the same epoch is fine"
            );
            assert!(
                msg.clone().downcast_reply(&*REQ, epoch - 1).is_ok(),
                "Receiving a message from a future epoch is fine: we're just a bit behind in our clock"
            );
        }

        let msg = RrMessage::new_reply(&*REQ, 0, ());
        assert!(
            msg.clone().downcast_reply(&*REQ, 0).is_ok(),
            "what? this is totally fine. the epoch just ensures freshness for one message transmission, not the whole exchange"
        );
    }
}
