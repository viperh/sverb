//! Transports: ssh, local pty; forwarding; agent.
//!
//! Everything that opens a connection or spawns a process for a session
//! lives here, behind UI-agnostic interfaces.

// Session actor, state machine, manager and the `Transport` trait (SPEC §2.1, §6).
// Local terminal transport over portable-pty (SPEC §6.2).
pub mod local;
pub mod manager;
#[cfg(any(test, feature = "test-util"))]
pub mod mock;
pub mod panic_scope;
pub mod session;
// SSH over russh (SPEC §6.1). All russh usage stays in `ssh`.
pub mod ssh;
pub mod transport;

pub use bytes::Bytes;
pub use local::{LocalConnector, LocalOptions, LocalTransport};
pub use manager::{
    EmulatorFactory, OpenError, OpenOptions, SessionManager, SessionRegistry, ShutdownReport,
};
pub use session::SshSessionInfo;
pub use session::{
    AuthAnswer, AuthMethod, AuthPrompt, Decision, DisconnectReason, EventSink, LocalSpec, MockSpec,
    SessionCmd, SessionEvent, SessionHandle, SessionId, SessionSpec, SessionState, SharedEmulator,
    SshSpec, StateInput, Verification,
};
pub use session::{OVERFLOW_WARN_BYTES, SendOutcome, UiSender};
pub use ssh::{SshConnector, SshTransport};
pub use transport::{ConnectCtx, ConnectError, Connector, Transport, TransportKind};
pub use transport::{SessionEmitter, TransportFailure};
pub mod agent_client;
pub use session::{PromptKind, PromptLine};
// Connection-attempt hooks (ConnLog).
pub mod connlog;
pub use connlog::{Attempt, AttemptEnd, AttemptOutcome, ConnLogSink, NoConnLog, conn_result};
// Proxies for the first hop (SOCKS5, HTTP CONNECT, ProxyCommand; SPEC §6.1.5).
pub mod proxy;
// Port forwarding (SPEC §9.6): -L / -R / -D (SOCKS), the forward manager.
pub mod forward;
// Agent forwarding, the built-in agent, the local agent and control sockets.
pub mod agent;
