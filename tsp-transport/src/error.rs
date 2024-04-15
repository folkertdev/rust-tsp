#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error fetching '{0}': {1}")]
    Http(String, reqwest::Error),
    #[error("connection error '{0}': {1}")]
    Connection(String, std::io::Error),
    #[error("invalid address: {0}")]
    InvalidTransportAddress(String),
    #[error("invalid transport scheme: {0}")]
    InvalidTransportScheme(String),
    #[error("websocket '{0}': {1}")]
    Websocket(String, tokio_tungstenite::tungstenite::Error),
    #[error("invalid message received: {0}")]
    InvalidMessageReceived(String),
}
