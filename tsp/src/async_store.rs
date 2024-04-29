use crate::{
    crypto::CryptoError,
    definitions::{Digest, Payload, ReceivedTspMessage, VerifiedVid},
    error::Error,
    store::{RelationshipStatus, Store},
    vid::VidError,
    PrivateVid,
};
use futures::StreamExt;
use tokio::sync::mpsc::{self, Receiver};

/// Holds private ands verified VID's
/// A Store contains verified vid's, our relationship status to them,
/// as well as the private vid's that this application has control over.
///
/// # Example
///
/// ```no_run
/// use tsp::{AsyncStore, OwnedVid, Error, ReceivedTspMessage};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Error> {
///     // alice database
///     let mut db = AsyncStore::new();
///     let alice_vid = OwnedVid::from_file("../examples/test/bob.json").await?;
///     db.add_private_vid(alice_vid)?;
///     db.verify_vid("did:web:did.tsp-test.org:user:bob").await?;
///
///     // send a message
///     db.send(
///         "did:web:did.tsp-test.org:user:alice",
///         "did:web:did.tsp-test.org:user:bob",
///         Some(b"extra non-confidential data"),
///         b"hello world",
///     ).await?;
///
///     Ok(())
/// }
/// ```
#[derive(Default)]
pub struct AsyncStore {
    inner: Store,
}

impl AsyncStore {
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds a relation to an already existing vid, making it a nested Vid
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.inner.set_relation_for_vid(vid, relation_vid)
    }

    pub(super) fn set_relation_status_for_vid(
        &self,
        vid: &str,
        relation_status: RelationshipStatus,
    ) -> Result<(), Error> {
        self.inner.set_relation_status_for_vid(vid, relation_status)
    }

    /// Adds a route to an already existing vid, making it a nested Vid
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        self.inner.set_route_for_vid(vid, route)
    }

    pub fn set_parent_for_vid(&self, vid: &str, parent: Option<&str>) -> Result<(), Error> {
        self.inner.set_parent_for_vid(vid, parent)
    }

    pub fn list_vids(&self) -> Result<Vec<String>, Error> {
        self.inner.list_vids()
    }

    /// Adds `private_vid` to the database
    pub fn add_private_vid(
        &self,
        private_vid: impl PrivateVid + Clone + 'static,
    ) -> Result<(), Error> {
        self.inner.add_private_vid(private_vid)
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: impl VerifiedVid + 'static) -> Result<(), Error> {
        self.inner.add_verified_vid(verified_vid)
    }

    /// Check whether the [PrivateVid] identified by `vid` exists inthe database
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        self.inner.has_private_vid(vid)
    }

    /// Resolve and verify public key material for a VID identified by `vid` and add it to the database as a relationship
    pub async fn verify_vid(&mut self, vid: &str) -> Result<(), Error> {
        let verified_vid = crate::vid::verify_vid(vid).await?;

        self.inner.add_verified_vid(verified_vid)?;

        Ok(())
    }

    /// Send a TSP message given earlier resolved VID's
    /// Encodes, encrypts, signs and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    /// * `nonconfidential_data` - Optional extra non-confidential data
    /// * `payload`              - The raw message payload as byte slice
    ///
    /// # Example
    ///
    /// ```
    /// use tsp::{AsyncStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = OwnedVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
    ///
    ///     let result = db.send(sender, receiver, None, b"hello world").await;
    /// }
    /// ```
    pub async fn send(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (endpoint, message) =
            self.inner
                .seal_message(sender, receiver, nonconfidential_data, message)?;

        crate::transport::send_message(&endpoint, &message).await?;

        Ok(message)
    }

    /// Request a direct relationship with a resolved VID using the TSP
    /// Encodes the control message, encrypts, signs and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tsp::{AsyncStore, OwnedVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = OwnedVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
    ///
    ///     let result = db.send_relationship_request(sender, receiver).await;
    /// }
    /// ```
    pub async fn send_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let (tsp_message, thread_id) =
            crate::crypto::seal_and_hash(&*sender, &*receiver, None, Payload::RequestRelationship)?;

        crate::transport::send_message(receiver.endpoint(), &tsp_message).await?;

        self.set_relation_status_for_vid(
            receiver.identifier(),
            RelationshipStatus::Unidirectional(thread_id),
        )?;

        Ok(())
    }

    /// Accept a direct relationship between the resolved VID's identifier by `sender` and `receiver`.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let (transport, message) = self.inner.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::AcceptRelationship { thread_id },
        )?;

        crate::transport::send_message(&transport, &message).await?;

        self.set_relation_status_for_vid(receiver, RelationshipStatus::Bidirectional(thread_id))?;

        Ok(())
    }

    /// Cancels a direct relationship between the resolved `sender` and `receiver` VID's.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        self.set_relation_status_for_vid(receiver, RelationshipStatus::Unrelated)?;

        let thread_id = Default::default(); // FNORD

        let (transport, message) = self.inner.seal_message_payload(
            sender,
            receiver,
            None,
            Payload::CancelRelationship { thread_id },
        )?;

        crate::transport::send_message(&transport, &message).await?;

        Ok(())
    }

    // Receive, open and forward a TSP message
    pub async fn route_message(
        &self,
        sender: &str,
        receiver: &str,
        message: &mut [u8],
    ) -> Result<(), Error> {
        let Ok(receiver) = self.inner.get_private_vid(receiver) else {
            return Err(CryptoError::UnexpectedRecipient.into());
        };

        let Ok(sender) = self.inner.get_verified_vid(sender) else {
            return Err(Error::UnverifiedVid(sender.to_string()));
        };

        let (_, payload, _) = crate::crypto::open(&*receiver, &*sender, message)?;

        let Payload::RoutedMessage(hops, inner_message) = payload else {
            return Err(Error::InvalidRoute("expected a routed message".to_string()));
        };

        let next_hop = std::str::from_utf8(hops[0])?;

        let Ok(next_hop) = self.inner.get_verified_vid(next_hop) else {
            return Err(Error::UnverifiedVid(next_hop.to_string()));
        };

        let path = hops[1..].to_vec();

        self.forward_routed_message(next_hop.identifier(), path, inner_message)
            .await
    }

    /// Pass along a in-transit routed TSP `opaque_message` that is not meant for us, given earlier resolved VID's.
    /// The message is routed through the route that has been established with `receiver`.
    pub async fn forward_routed_message(
        &self,
        next_hop: &str,
        path: Vec<&[u8]>,
        opaque_message: &[u8],
    ) -> Result<(), Error> {
        if path.is_empty() {
            // we are the final delivery point, we should be the 'next_hop'
            let sender = self.inner.get_private_vid(next_hop)?;

            //TODO: we cannot user 'sender.relation_vid()', since the relationship status of this cannot be set
            let recipient = match self.inner.get_vid(sender.identifier())?.get_relation_vid() {
                Some(destination) => self.inner.get_verified_vid(destination)?,
                None => return Err(VidError::ResolveVid("no relation for drop-off VID").into()),
            };

            let tsp_message = crate::crypto::seal(
                &*sender,
                &*recipient,
                None,
                Payload::NestedMessage(opaque_message),
            )?;

            Ok(crate::transport::send_message(recipient.endpoint(), &tsp_message).await?)
        } else {
            // we are an intermediary, continue sending the message
            // let next_hop = self.inner.get_vid(next_hop)?;
            let next_bop_vid = self.inner.get_verified_vid(next_hop)?;

            let sender = match self.inner.get_vid(next_hop)?.get_relation_vid() {
                Some(first_sender) => self.inner.get_private_vid(first_sender)?,
                None => return Err(VidError::ResolveVid("missing sender VID for first hop").into()),
            };

            let tsp_message = crate::crypto::seal(
                &*sender,
                &*next_bop_vid,
                None,
                Payload::RoutedMessage(path, opaque_message),
            )?;

            Ok(crate::transport::send_message(next_bop_vid.endpoint(), &tsp_message).await?)
        }
    }

    /// Receive TSP messages for the private VID identified by `vid`, using the appropriate transport mechanism for it.
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage, Error>>, Error> {
        let receiver = self.inner.get_private_vid(vid)?;

        let (tx, rx) = mpsc::channel(16);
        let mut messages = crate::transport::receive_messages(receiver.endpoint()).await?;

        let db = self.inner.clone();
        tokio::task::spawn(async move {
            while let Some(message) = messages.next().await {
                let result = match message {
                    Ok(mut m) => db.clone().open_message(&mut m),
                    Err(e) => Err(e.into()),
                };

                let _ = tx.send(result).await;
            }
        });

        Ok(rx)
    }
}
