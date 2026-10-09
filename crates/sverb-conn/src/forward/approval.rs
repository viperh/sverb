//! Rule values that act locally, and their confirmation (§9.6, §17.1).
//!
//! - **Which values** ([`risky_values`]): a non-loopback `bind_addr` of a
//!   Local/Dynamic rule, a non-loopback `dest_host` of a Remote rule. The
//!   classification is M2-10's (`sverb_core::resolve::approval::forward_actions`).
//! - **Approval** is an explicit device-local row per `(rule, field, value)`
//!   (`local_approvals`, M2-10). Values saved through a form on this device get their
//!   row at save time; synced or remotely changed values have none and are asked
//!   for. The authorship of a stamp is never trusted on its own.
//!
//! Both §9.6 (first non-loopback bind) and §17.1 are answered by the same
//! confirmation ("This forward listens on 0.0.0.0:8080. Allow?"). The store is an
//! [`ApprovalStore`]; sverb uses the store-backed
//! [`sverb_core::resolve::approval::DeviceApprovals`], and
//! [`MemoryApprovals`] remains for tests.

use std::{collections::HashSet, fmt};

use parking_lot::Mutex;
use sverb_core::model::{ItemId, PortForward};
use sverb_core::resolve::approval::{ActionKind, DeviceApprovals, forward_actions};

use super::ForwardRule;

/// A value that acts locally.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RiskyValue {
    /// The rule.
    pub rule: ItemId,
    /// `bind_addr` or `dest_host` (the §17.1 field).
    pub field: &'static str,
    /// The exact value shown to the user (`0.0.0.0:8080`, `10.0.0.5:5432`).
    pub value: String,
    /// The value was not last written by this device (informational: the dialog
    /// wording). Approval itself depends only on the explicit rows (M2-10).
    pub synced: bool,
}

impl RiskyValue {
    /// The §17.1 kind of this value.
    pub fn kind(&self) -> ActionKind {
        ActionKind::from_field(self.field).unwrap_or(ActionKind::ForwardBind)
    }

    /// The question for the confirmation dialog.
    pub fn question(&self) -> String {
        if self.field == "dest_host" {
            format!(
                "This forward connects from this machine to {}. Allow?",
                self.value
            )
        } else {
            format!(
                "This forward listens on {} (reachable from other machines). Allow?",
                self.value
            )
        }
    }
}

impl fmt::Display for RiskyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.field, self.value)
    }
}

/// The values of `rule` that act locally (§9.6, §17.1).
pub fn risky_values(rule: &ForwardRule) -> Vec<RiskyValue> {
    let pf = PortForward {
        label: rule.label.clone(),
        kind: rule.kind,
        host_id: rule.host_id,
        bind_addr: rule.bind_addr.clone(),
        bind_port: rule.bind_port,
        dest_host: rule.dest_host.clone(),
        dest_port: rule.dest_port,
        auto_start: rule.auto_start,
        read_only: false,
    };
    forward_actions(rule.id, &pf)
        .into_iter()
        .map(|a| RiskyValue {
            rule: a.item_id,
            field: a.field(),
            value: a.value,
            synced: !rule.typed_here,
        })
        .collect()
}

/// Where confirmations are remembered: [`DeviceApprovals`] (M2-10, `local_approvals`).
pub trait ApprovalStore: Send + Sync + fmt::Debug {
    /// Whether `value` was confirmed before.
    fn is_approved(&self, value: &RiskyValue) -> bool;
    /// Remember a confirmation.
    fn approve(&self, value: &RiskyValue);
    /// Remember a denial for this session (M2-10: not persisted).
    fn deny(&self, _value: &RiskyValue) {}
    /// Whether `value` was denied in this session: fail without asking again.
    fn is_denied(&self, _value: &RiskyValue) -> bool {
        false
    }
}

// M2-10: the device's approvals.
impl ApprovalStore for DeviceApprovals {
    fn is_approved(&self, value: &RiskyValue) -> bool {
        DeviceApprovals::is_approved(self, value.rule, value.field, &value.value)
    }

    fn approve(&self, value: &RiskyValue) {
        DeviceApprovals::approve(self, value.rule, value.field, &value.value);
    }

    fn deny(&self, value: &RiskyValue) {
        DeviceApprovals::deny(self, value.rule, value.field, &value.value);
    }

    fn is_denied(&self, value: &RiskyValue) -> bool {
        DeviceApprovals::is_denied(self, value.rule, value.field, &value.value)
    }
}

/// An in-memory store for tests (confirmations last for the process).
#[derive(Debug, Default)]
pub struct MemoryApprovals {
    approved: Mutex<HashSet<(ItemId, &'static str, String)>>,
}

impl ApprovalStore for MemoryApprovals {
    fn is_approved(&self, value: &RiskyValue) -> bool {
        self.approved
            .lock()
            .contains(&(value.rule, value.field, value.value.clone()))
    }

    fn approve(&self, value: &RiskyValue) {
        self.approved
            .lock()
            .insert((value.rule, value.field, value.value.clone()));
    }
}

/// The values of `rule` still needing confirmation in `store`.
pub fn needs_confirmation(rule: &ForwardRule, store: &dyn ApprovalStore) -> Vec<RiskyValue> {
    risky_values(rule)
        .into_iter()
        .filter(|v| !store.is_approved(v))
        .collect()
}

#[cfg(test)]
mod tests {
    use sverb_core::model::{ForwardKind, ItemId};

    use super::*;

    fn rule(kind: ForwardKind, bind: &str, dest: Option<&str>, typed_here: bool) -> ForwardRule {
        ForwardRule {
            id: ItemId::new(),
            label: "r".into(),
            kind,
            host_id: ItemId::new(),
            bind_addr: bind.into(),
            bind_port: 8080,
            dest_host: dest.map(Into::into),
            dest_port: dest.map(|_| 80),
            auto_start: false,
            typed_here,
        }
    }

    #[test]
    fn classification() {
        assert!(risky_values(&rule(ForwardKind::Local, "127.0.0.2", Some("db"), false)).is_empty());
        assert!(risky_values(&rule(ForwardKind::Dynamic, "::1", None, false)).is_empty());
        assert!(risky_values(&rule(ForwardKind::Local, "localhost", Some("x"), false)).is_empty());
        let v = risky_values(&rule(ForwardKind::Local, "0.0.0.0", Some("db"), true));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].value, "0.0.0.0:8080");
        assert!(!v[0].synced);
        let v = risky_values(&rule(ForwardKind::Dynamic, "*", None, false));
        assert!(v[0].synced);
        // Remote: a non-loopback local destination of a synced rule.
        assert!(risky_values(&rule(ForwardKind::Remote, "*", Some("127.0.0.1"), false)).is_empty());
        let v = risky_values(&rule(ForwardKind::Remote, "*", Some("10.0.0.5"), false));
        assert_eq!(v[0].field, "dest_host");
        // M2-10: typed here or not, only an explicit approval row exempts it.
        let v = risky_values(&rule(ForwardKind::Remote, "*", Some("10.0.0.5"), true));
        assert_eq!(v.len(), 1);
        assert!(!v[0].synced);
    }

    // M2-10: the device store answers like the memory stub, plus session denials.
    #[test]
    fn device_store_is_per_value_and_denies_for_the_session() {
        let store = DeviceApprovals::new();
        let mut r = rule(ForwardKind::Remote, "*", Some("10.0.0.5"), false);
        let pending = needs_confirmation(&r, &store);
        assert_eq!(pending.len(), 1);
        ApprovalStore::deny(&store, &pending[0]);
        assert!(ApprovalStore::is_denied(&store, &pending[0]));
        ApprovalStore::approve(&store, &pending[0]);
        assert!(needs_confirmation(&r, &store).is_empty());
        r.dest_port = Some(81);
        assert_eq!(needs_confirmation(&r, &store).len(), 1);
    }

    #[test]
    fn memory_store_is_per_value() {
        let store = MemoryApprovals::default();
        let mut r = rule(ForwardKind::Local, "0.0.0.0", Some("db"), true);
        let pending = needs_confirmation(&r, &store);
        assert_eq!(pending.len(), 1);
        store.approve(&pending[0]);
        assert!(needs_confirmation(&r, &store).is_empty());
        // A changed value asks again.
        r.bind_port = 9090;
        assert_eq!(needs_confirmation(&r, &store).len(), 1);
    }
}
