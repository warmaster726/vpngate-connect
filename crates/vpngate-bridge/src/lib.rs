//! Zero-codegen C-ABI & Rust FFI crate exposing `vpngate-core` to Flutter (`dart:ffi`),
//! Android `VpnService` (`JNI` + user-space `IKEv1/ESP/L2TP/PPP`), and iOS `NEPacketTunnelProvider`.

pub mod api;
pub mod ffi;

pub use api::*;
pub use ffi::*;
