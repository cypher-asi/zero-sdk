//! `GridClient` async trait definition.

use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;

use crate::error::NetworkError;

/// A sector received or published on the network.
pub type SectorBytes = Vec<u8>;

/// Async interface to the GRID network.
///
/// Implementors include [`crate::real::RealGridClient`] (live network) and
/// [`crate::mock::MockGridClient`] (in-memory broker for tests).
#[async_trait]
pub trait GridClient: Send + Sync + 'static {
    /// Publish raw sector bytes to a topic.
    async fn publish(&self, topic: &str, sector_bytes: SectorBytes) -> Result<(), NetworkError>;

    /// Subscribe to a topic, returning a stream of inbound sectors.
    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>, NetworkError>;

    /// Unsubscribe from a previously subscribed topic.
    async fn unsubscribe(&self, topic: &str) -> Result<(), NetworkError>;
}
