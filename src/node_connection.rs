//! One authenticated connection to one node.
//!
//! Wraps the WebRTC transport plus the established PQC session and offers
//! the typed request surface the client needs: chunk GET/quote/PUT on the
//! 0x01 lane and closest-peers discovery on the 0x02 lane. Requests on one
//! connection are issued sequentially (one in flight), which keeps the
//! response correlation trivial; parallelism comes from talking to many
//! nodes at once through the pool.

use crate::discovery::{
    ClosestPeers