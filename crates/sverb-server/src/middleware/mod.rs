//! HTTP middleware (SPEC §10.4, §10.5, §20).

pub mod client_ip;
pub mod errors;
pub mod proto_version;
pub mod rate_limit;
pub mod request_id;
