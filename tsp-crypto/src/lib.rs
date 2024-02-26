use tsp_definitions::{
    Ciphertext, Error, NonConfidentialData, Payload, Receiver, ResolvedVid, Sender,
};
mod tsp_hpke;

pub type Aead = hpke::aead::ChaCha20Poly1305;
pub type Kdf = hpke::kdf::HkdfSha256;
pub type Kem = hpke::kem::X25519HkdfSha256;

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn Sender,
    receiver: &dyn ResolvedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    message: Payload,
) -> Result<Ciphertext, Error> {
    tsp_hpke::seal::<Aead, Kdf, Kem>(sender, receiver, nonconfidential_data, message)
}

/// Decode a CESR Authentic Confidential Message, verify the signature and decrypt its contents
pub fn open<'a>(
    receiver: &dyn Receiver,
    sender: &dyn ResolvedVid,
    message: &'a mut [u8],
) -> Result<(Option<NonConfidentialData<'a>>, Payload<'a>), Error> {
    tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, message)
}

#[cfg(test)]
mod tests {
    use hpke::{Kem, Serializable};
    use rand::{rngs::StdRng, SeedableRng};
    use tsp_definitions::{Receiver, ResolvedVid, Sender};

    use crate::{open, seal};

    struct BobOrAlice {
        vid: String,
        decryption_key: [u8; 32],
        encryption_key: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
        verifying_key: ed25519_dalek::VerifyingKey,
    }

    impl BobOrAlice {
        fn new(vid: &str) -> Self {
            let mut csprng = StdRng::from_entropy();
            let (decryption_key, encryption_key) =
                hpke::kem::X25519HkdfSha256::gen_keypair(&mut csprng);
            let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();

            Self {
                vid: vid.to_string(),
                decryption_key: decryption_key.to_bytes().into(),
                encryption_key: encryption_key.to_bytes().into(),
                signing_key,
                verifying_key,
            }
        }
    }

    impl ResolvedVid for BobOrAlice {
        fn vid(&self) -> tsp_definitions::VidData {
            self.vid.as_bytes()
        }

        fn verifying_key(&self) -> tsp_definitions::PublicKeyData {
            &self.verifying_key.as_bytes()
        }

        fn encryption_key(&self) -> tsp_definitions::PublicKeyData {
            &self.encryption_key
        }
    }

    impl Receiver for BobOrAlice {
        fn decryption_key(&self) -> tsp_definitions::PrivateKeyData {
            &self.decryption_key
        }
    }

    impl Sender for BobOrAlice {
        fn signing_key(&self) -> tsp_definitions::PrivateKeyData {
            &self.signing_key.as_bytes()
        }
    }

    #[test]
    fn seal_open_message() {
        let bob = BobOrAlice::new("did:test:bob");
        let alice = BobOrAlice::new("did:test:alice");

        let secret_message = b"hello world";
        let nonconfidential_data = b"extra header data";

        let mut message = seal(&bob, &alice, Some(nonconfidential_data), secret_message).unwrap();

        let (received_nonconfidential_data, received_secret_message) =
            open(&alice, &bob, &mut message).unwrap();

        assert_eq!(received_nonconfidential_data.unwrap(), nonconfidential_data);
        assert_eq!(received_secret_message, secret_message);
    }
}
