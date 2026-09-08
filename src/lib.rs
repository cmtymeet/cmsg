//! Experimental client-side MLS text messaging. No server holds content keys.
use std::net::SocketAddr;

pub const MAX_TEXT_BYTES: usize = 16 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum Error { Unimplemented, InvalidText, InvalidMessage, InvalidStore, InvalidRoute, Transport }
#[derive(Debug)]
pub enum Received { Text(String), MembershipChanged }
pub struct Invitation { pub commit: Vec<u8>, pub welcome: Vec<u8> }
pub struct Member;
impl Member {
    pub fn new() -> Result<Self, Error> { Err(Error::Unimplemented) }
    pub fn create_group(&mut self) -> Result<(), Error> { Err(Error::Unimplemented) }
    pub fn key_package(&self) -> Result<Vec<u8>, Error> { Err(Error::Unimplemented) }
    pub fn add(&mut self, _key_package: &[u8]) -> Result<Invitation, Error> { Err(Error::Unimplemented) }
    pub fn join(&mut self, _welcome: &[u8]) -> Result<(), Error> { Err(Error::Unimplemented) }
    pub fn remove(&mut self, _leaf: u32) -> Result<Vec<u8>, Error> { Err(Error::Unimplemented) }
    pub fn send(&mut self, _text: &[u8]) -> Result<Vec<u8>, Error> { Err(Error::Unimplemented) }
    pub fn receive(&mut self, _wire: &[u8]) -> Result<Received, Error> { Err(Error::Unimplemented) }
    pub fn snapshot(&self, _key: &[u8;32], _context: &[u8]) -> Result<Vec<u8>, Error> { Err(Error::Unimplemented) }
    pub fn restore(_sealed: &[u8], _key: &[u8;32], _context: &[u8]) -> Result<Self, Error> { Err(Error::Unimplemented) }
}
pub fn validate_text(_text: &[u8]) -> Result<&str, Error> { Err(Error::Unimplemented) }
pub struct OnionEndpoint;
impl OnionEndpoint { pub fn parse(_host: &str, _port: u16) -> Result<Self, Error> { Err(Error::Unimplemented) } }
pub struct OnionTransport;
impl OnionTransport {
    pub fn new(_proxy: SocketAddr) -> Result<Self, Error> { Err(Error::Unimplemented) }
    pub async fn connect(&self, _endpoint: &OnionEndpoint) -> Result<tokio::net::TcpStream, Error> { Err(Error::Unimplemented) }
}
