use crate::{validate_text, Error, MAX_WIRE_BYTES};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::fmt;
use tls_codec::{Deserialize as _, Serialize as _};
use zeroize::{Zeroize, Zeroizing};

const SUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const STORE_HEADER: &[u8] = b"cmsg-store-v1\0";

/// The caller must send these over authenticated, anonymous member channels.
/// Welcome data includes the group roster; it must not go to a central log.
pub struct Invitation {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

pub enum Received {
    Text(String),
    MembershipChanged,
}
impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text([redacted])"),
            Self::MembershipChanged => f.write_str("MembershipChanged"),
        }
    }
}

/// One independently generated, conversation-scoped MLS identity.
/// Never reuse it as a global account identifier across communities.
/// Memory storage is client-local; persistence is available only as ciphertext.
pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
}

fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(256)
        .build()
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Randomness)?;
    Ok(value)
}
fn parse(wire: &[u8]) -> Result<MlsMessageIn, Error> {
    if wire.is_empty() || wire.len() > MAX_WIRE_BYTES {
        return Err(Error::InvalidMessage);
    }
    MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| Error::InvalidMessage)
}

impl Member {
    pub fn new() -> Result<Self, Error> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|_| Error::InvalidState)?;
        signer.store(provider.storage()).map_err(|_| Error::InvalidState)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(random::<32>()?.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self { provider, signer, credential, group: None })
    }

    pub fn create_group(&mut self) -> Result<(), Error> {
        if self.group.is_some() { return Err(Error::InvalidState); }
        self.group = Some(MlsGroup::new(
            &self.provider, &self.signer, &config(), self.credential.clone(),
        ).map_err(|_| Error::InvalidState)?);
        Ok(())
    }

    /// A fresh, single-use KeyPackage. Its credential binding must be authenticated
    /// by the integrating application's admission/introduction protocol.
    pub fn key_package(&self) -> Result<Vec<u8>, Error> {
        KeyPackage::builder()
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(|_| Error::InvalidState)?
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| Error::InvalidMessage)
    }

    /// The caller is responsible for authenticated authorization of this member.
    pub fn add(&mut self, key_package: &[u8]) -> Result<Invitation, Error> {
        if key_package.len() > MAX_WIRE_BYTES { return Err(Error::InvalidMessage); }
        let package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|_| Error::InvalidMessage)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::InvalidMessage)?;
        let group = self.group.as_mut().ok_or(Error::InvalidState)?;
        let (commit, welcome, _) = group.add_members(&self.provider, &self.signer, &[package])
            .map_err(|_| Error::InvalidMessage)?;
        let invitation = Invitation {
            commit: commit.tls_serialize_detached().map_err(|_| Error::InvalidMessage)?,
            welcome: welcome.tls_serialize_detached().map_err(|_| Error::InvalidMessage)?,
        };
        group.merge_pending_commit(&self.provider).map_err(|_| Error::InvalidState)?;
        Ok(invitation)
    }

    pub fn join(&mut self, welcome: &[u8]) -> Result<(), Error> {
        if self.group.is_some() { return Err(Error::InvalidState); }
        let welcome = match parse(welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::InvalidMessage),
        };
        self.group = Some(StagedWelcome::new_from_welcome(
            &self.provider, config().join_config(), welcome, None,
        ).map_err(|_| Error::InvalidMessage)?
            .into_group(&self.provider).map_err(|_| Error::InvalidState)?);
        Ok(())
    }

    pub fn remove(&mut self, leaf: u32) -> Result<Vec<u8>, Error> {
        let group = self.group.as_mut().ok_or(Error::InvalidState)?;
        let (commit, _, _) = group.remove_members(
            &self.provider, &self.signer, &[LeafNodeIndex::new(leaf)],
        ).map_err(|_| Error::InvalidMessage)?;
        let wire = commit.tls_serialize_detached().map_err(|_| Error::InvalidMessage)?;
        group.merge_pending_commit(&self.provider).map_err(|_| Error::InvalidState)?;
        Ok(wire)
    }

    pub fn send(&mut self, text: &[u8]) -> Result<Vec<u8>, Error> {
        validate_text(text)?;
        self.group.as_mut().ok_or(Error::InvalidState)?
            .create_message(&self.provider, &self.signer, text)
            .map_err(|_| Error::InvalidMessage)?
            .tls_serialize_detached().map_err(|_| Error::InvalidMessage)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Received, Error> {
        let message = parse(wire)?.try_into_protocol_message().map_err(|_| Error::InvalidMessage)?;
        let group = self.group.as_mut().ok_or(Error::InvalidState)?;
        let processed = group.process_message(&self.provider, message)
            .map_err(|_| Error::InvalidMessage)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = Zeroizing::new(application.into_bytes());
                Ok(Received::Text(validate_text(&bytes)?.to_owned()))
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group.merge_staged_commit(&self.provider, *commit)
                    .map_err(|_| Error::InvalidMessage)?;
                Ok(Received::MembershipChanged)
            }
            _ => Err(Error::InvalidMessage),
        }
    }

    /// Encrypt all ratchet state using a fresh data key, then wrap that key with
    /// cvld's 32-byte PRF-derived material. The caller holds wrapping material only
    /// locally. `context` binds this envelope to the intended wallet/community.
    /// No password derivation, server escrow or plaintext persistence is provided.
    pub fn snapshot(&self, wrapping_key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        let aad = store_aad(context)?;
        let storage = self.provider.storage().values.read().map_err(|_| Error::InvalidStore)?;
        let snapshot = SnapshotRef {
            storage: storage.iter().collect(),
            signer: &self.signer,
            credential: &self.credential,
            group_id: self.group.as_ref().map(|g| g.group_id()),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Error::InvalidStore)?);
        if plaintext.len() > MAX_STORE_BYTES - 128 { return Err(Error::InvalidStore); }
        let data_key = Zeroizing::new(random::<32>()?);
        let wrap_nonce = random::<24>()?;
        let data_nonce = random::<24>()?;
        let wrapped = XChaCha20Poly1305::new(wrapping_key.into())
            .encrypt(XNonce::from_slice(&wrap_nonce), Payload { msg: data_key.as_ref(), aad: &aad })
            .map_err(|_| Error::InvalidStore)?;
        let encrypted = XChaCha20Poly1305::new((&*data_key).into())
            .encrypt(XNonce::from_slice(&data_nonce), Payload { msg: &plaintext, aad: &aad })
            .map_err(|_| Error::InvalidStore)?;
        let mut output = STORE_HEADER.to_vec();
        output.extend_from_slice(&wrap_nonce);
        output.extend_from_slice(&wrapped);
        output.extend_from_slice(&data_nonce);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    /// Restores the exact saved ratchet state. Authenticating an old valid snapshot
    /// cannot detect rollback: monotonic local persistence is an integration need.
    pub fn restore(sealed: &[u8], wrapping_key: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        let aad = store_aad(context)?;
        let offset = STORE_HEADER.len();
        if sealed.len() < offset + 24 + 48 + 24 + 16 || sealed.len() > MAX_STORE_BYTES
            || !sealed.starts_with(STORE_HEADER) { return Err(Error::InvalidStore); }
        let key = Zeroizing::new(XChaCha20Poly1305::new(wrapping_key.into())
            .decrypt(XNonce::from_slice(&sealed[offset..offset+24]), Payload {
                msg: &sealed[offset+24..offset+72], aad: &aad,
            }).map_err(|_| Error::InvalidStore)?);
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::InvalidStore)?;
        let plaintext = Zeroizing::new(cipher.decrypt(
            XNonce::from_slice(&sealed[offset+72..offset+96]),
            Payload { msg: &sealed[offset+96..], aad: &aad },
        ).map_err(|_| Error::InvalidStore)?);
        let mut snapshot: Snapshot = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut storage = provider.storage().values.write().map_err(|_| Error::InvalidStore)?;
            storage.extend(snapshot.storage.drain(..));
        }
        let group = snapshot.group_id.as_ref().map(|id|
            MlsGroup::load(provider.storage(), id).map_err(|_| Error::InvalidStore)?
                .ok_or(Error::InvalidStore)
        ).transpose()?;
        Ok(Self {
            provider,
            signer: snapshot.signer.take().ok_or(Error::InvalidStore)?,
            credential: snapshot.credential.clone(),
            group,
        })
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Ok(mut storage) = self.provider.storage().values.write() {
            for value in storage.values_mut() { value.zeroize(); }
            storage.clear();
        }
    }
}
#[derive(Serialize)]
struct SnapshotRef<'a> {
    storage: Vec<(&'a Vec<u8>, &'a Vec<u8>)>,
    signer: &'a SignatureKeyPair,
    credential: &'a CredentialWithKey,
    group_id: Option<&'a GroupId>,
}
#[derive(Deserialize)]
struct Snapshot {
    storage: Vec<(Vec<u8>, Vec<u8>)>,
    signer: Option<SignatureKeyPair>,
    credential: CredentialWithKey,
    group_id: Option<GroupId>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        for (_, value) in &mut self.storage { value.zeroize(); }
    }
}
fn store_aad(context: &[u8]) -> Result<Vec<u8>, Error> {
    if context.is_empty() || context.len() > 128 { return Err(Error::InvalidStore); }
    let mut aad = STORE_HEADER.to_vec();
    aad.extend_from_slice(context);
    Ok(aad)
}
