use ed25519::{pkcs8::EncodePublicKey, signature::Verifier, Signature};

pub trait Identifier: Eq {
    /// A representation of a Vid encoded as an UTF8 string.
    fn display(&self) -> ascii::AsciiString;

    /// The endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The public key associated with this Vid
    fn public_key(&self) -> &(impl Verifier<Signature> + EncodePublicKey + AsRef<[u8]>);

    /// Parse the display representation (as generated by [Self::display])
    fn parse(display_string: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

use thiserror::Error;

/// The error type for `Identifier::Parse`
#[derive(Error, Debug)]
pub enum Error {
    #[error("Encoding error: {0}")]
    Encoding(#[from] base64ct::Error), // we should abstract from base64ct at some point
    #[error("Verification failure: {0}")]
    VerificationFailed(#[from] ed25519::Error),
    #[error("Invalid transport layer location: {0}")]
    Transport(#[from] url::ParseError),
}
