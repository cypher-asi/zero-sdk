//! Real GRID client implementation.
//!
//! Wraps the upstream `the-grid` crate. Until the git dependency is pinned
//! and available, methods return [`NetworkError::Other`] indicating the
//! upstream is not yet linked.

use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;

use crate::client::{GridClient, SectorBytes};
use crate::error::NetworkError;

/// A GRID client backed by the real upstream library.
///
/// Construct via [`RealGridClient::connect`], which accepts a multiaddr
/// string such as `"/ip4/0.0.0.0/udp/3690/quic-v1"`.
pub struct RealGridClient {
    multiaddr: String,
}

impl RealGridClient {
    /// Connect to a GRID node at the given multiaddr.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Other`] until the upstream `the-grid` crate is
    /// linked. Once linked, returns connection-level errors from the upstream.
    pub async fn connect(multiaddr: &str) -> Result<Self, NetworkError> {
        // TODO: delegate to the_grid::GridClient::connect once the dep is available.
        Ok(Self {
            multiaddr: multiaddr.to_owned(),
        })
    }

    /// The multiaddr this client was connected to.
    pub fn multiaddr(&self) -> &str {
        &self.multiaddr
    }
}

#[async_trait]
impl GridClient for RealGridClient {
    async fn publish(&self, topic: &str, sector_bytes: SectorBytes) -> Result<(), NetworkError> {
        Err(NetworkError::Other(format!(
            "the-grid upstream not linked: publish {} bytes to topic '{}' on node {}",
            sector_bytes.len(),
            topic,
            self.multiaddr,
        )))
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>, NetworkError>
    {
        Err(NetworkError::Other(format!(
            "the-grid upstream not linked: subscribe to topic '{}' on node {}",
            topic, self.multiaddr,
        )))
    }

    async fn unsubscribe(&self, topic: &str) -> Result<(), NetworkError> {
        Err(NetworkError::Other(format!(
            "the-grid upstream not linked: unsubscribe from topic '{}' on node {}",
            topic, self.multiaddr,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_grid_client<T: GridClient>() {}

    #[test]
    fn real_grid_client_satisfies_trait_bounds() {
        assert_grid_client::<RealGridClient>();
    }

    #[tokio::test]
    async fn connect_stores_multiaddr() {
        let client = RealGridClient::connect("/ip4/127.0.0.1/udp/3690/quic-v1")
            .await
            .expect("connect should succeed");
        assert_eq!(client.multiaddr(), "/ip4/127.0.0.1/udp/3690/quic-v1");
    }

    #[tokio::test]
    async fn publish_returns_not_linked_error() {
        let client = RealGridClient::connect("/ip4/127.0.0.1/udp/3690/quic-v1")
            .await
            .unwrap();
        let err = client
            .publish("test-topic", vec![1, 2, 3])
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not linked"), "unexpected error: {msg}");
    }
}
