//! Fail-first boundary for a separately locked, non-published Arti experiment.
use std::{future::Future, path::{Path, PathBuf}, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tor_proto::stream::IncomingStreamRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure { Configuration, Route, Deadline, Closed, Capacity, Protocol, Network }
pub type Result<T> = std::result::Result<T, Failure>;

pub struct OwnedState;
impl OwnedState {
    pub fn create(_parent: &Path) -> Result<Self> { Err(Failure::Configuration) }
    pub fn root(&self) -> &Path { Path::new("") }
    pub fn client_directories(&self, _index: usize) -> Result<(PathBuf, PathBuf)> { Err(Failure::Configuration) }
}

pub struct CheckedOnion;
impl CheckedOnion {
    pub fn host(&self) -> &str { "" }
    pub fn port(&self) -> u16 { 0 }
}
pub async fn dial_checked<T, F, Fut>(_host: &str, _port: u16, _deadline: Duration, _dial: F) -> Result<T>
where F: FnOnce(CheckedOnion) -> Fut, Fut: Future<Output = Result<T>> {
    Err(Failure::Route)
}
pub fn allowed_request(_request: &IncomingStreamRequest, _port: u16) -> bool { false }

#[derive(Clone)]
pub struct SessionScope;
impl SessionScope {
    pub fn new(_lifetime: Duration, _capacity: usize) -> Result<Self> { Err(Failure::Configuration) }
    pub fn close(&self) {}
    pub async fn run<T, F>(&self, _future: F) -> Result<T>
    where F: Future<Output = Result<T>> { Err(Failure::Closed) }
}

pub async fn mls_round_trip<C, S>(_client: C, _service: S, _frame_timeout: Duration) -> Result<()>
where C: AsyncRead + AsyncWrite + Unpin, S: AsyncRead + AsyncWrite + Unpin {
    Err(Failure::Protocol)
}
