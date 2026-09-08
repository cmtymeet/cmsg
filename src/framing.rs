//! Bounded byte framing, independent of transport routing or anonymity.
use crate::Error;
use std::{marker::PhantomData, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

/// An owned byte stream with nonzero uint32 big-endian frames.
///
/// This codec does not authenticate a route. Obtain an anonymous application
/// stream from a trusted onion transport before wrapping it. A raw socket alone
/// is not evidence of Tor, and this type never chooses or changes a destination.
/// Framing failures and cancelled operations must make this wrapper unusable.
pub struct FramedStream<S> {
    _stream: PhantomData<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FramedStream<S> {
    /// Require 1..=MAX_WIRE_BYTES and a positive deadline of at most 60 seconds.
    /// Each read or write gets one deadline covering its whole frame; a write
    /// includes flushing. Payload bytes remain opaque to this generic codec.
    pub fn new(
        _stream: S,
        _max_frame_bytes: usize,
        _frame_timeout: Duration,
    ) -> Result<Self, Error> {
        // Fail-first specification; implementation follows real runtime red.
        Err(Error::InvalidState)
    }

    pub async fn send_frame(&mut self, _payload: &[u8]) -> Result<(), Error> {
        Err(Error::Transport)
    }

    pub async fn receive_frame(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Transport)
    }
}
