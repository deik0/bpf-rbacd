//! YAML-based policy engine for eBPF RBAC.
//!
//! The policy system controls which eBPF operations each role is allowed to
//! perform. Policies are **allow-list only** and always **fail closed** —
//! anything not explicitly permitted is denied.
//!
//! # Policy dimensions
//!
//! Each role specifies permissions across three dimensions:
//!
//! | Dimension | Example values |
//! |-----------|---------------|
//! | **bpf() commands** | `PROG_LOAD`, `MAP_CREATE`, `LINK_CREATE`, … |
//! | **Program types** | `kprobe: [load, attach]`, `xdp: [load, attach, detach]` |
//! | **Map types** | `hash: [create, read, write]`, `ringbuf: [create, read]` |
//!
//! # System-policy intersection
//!
//! An optional `system_policy` section defines the **maximum allowable
//! operations** on the system. The effective policy for any role is the
//! **set intersection** of the role's policy and the system policy. This
//! means a role can never exceed the system-wide limits, even if its own
//! definition is more permissive.
//!
//! # Example
//!
//! ```yaml
//! system_policy:
//!   commands: [PROG_LOAD, MAP_CREATE]
//!   prog_types:
//!     kprobe: [load, attach]
//!   map_types:
//!     hash: [create, read]
//!
//! roles:
//!   ebpf:
//!     groups: [ebpf]
//!     commands: [PROG_LOAD, MAP_CREATE, LINK_CREATE]
//!     prog_types:
//!       kprobe: [load, attach]
//!     map_types:
//!       hash: [create, read, write]
//! ```
//!
//! In this example, the `ebpf` role requests `LINK_CREATE` and hash map
//! `write`, but neither is in the system policy, so both are denied.
//!
//! # Bitmap generation
//!
//! The policy engine can convert role permissions into `u32` bitmaps
//! suitable for the eBPF map shared with the LSM programs. Each bit
//! position corresponds to the kernel's enum value for that program type,
//! map type, or command.

use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::protocol::Request;

/// Top-level policy configuration, deserialized from YAML.
///
/// Contains an optional [`SystemPolicy`] that caps all roles, and a map of
/// named [`Role`] definitions.
#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    /// System-wide policy ceiling. When present, every role's effective
    /// permissions are intersected with this.
    #[serde(default)]
    pub system_policy: Option<SystemPolicy>,
    /// Named roles, keyed by role name (e.g. `"ebpf"`, `"ebpf-net"`).
    pub roles: HashMap<String, Role>,
}

/// System-wide policy that defines the maximum allowable operations.
///
/// Role-specific policies cannot exceed these limits — the effective policy
/// for any role is the intersection of its own definition and this.
#[derive(Debug, Deserialize, Clone)]
pub struct SystemPolicy {
    /// Allowed `bpf()` syscall commands (e.g. `"PROG_LOAD"`, `"MAP_CREATE"`).
    #[serde(default)]
    pub commands: Vec<String>,
    /// Allowed program types with per-type operations.
    /// Keys are program type names, values are lists of allowed operations.
    #[serde(default)]
    pub prog_types: HashMap<String, Vec<String>>,
    /// Allowed map types with per-type operations.
    /// Keys are map type names, values are lists of allowed operations.
    #[serde(default)]
    pub map_types: HashMap<String, Vec<String>>,
}

/// A named role that maps Unix groups to a set of eBPF permissions.
///
/// Users whose group membership matches any entry in [`groups`](Role::groups)
/// are granted this role's permissions (subject to system-policy intersection).
///
/// The special value `"any"` in commands, prog_types, or map_types acts as
/// a wildcard that matches all values.
#[derive(Debug, Deserialize, Clone)]
pub struct Role {
    /// Human-readable description of the role's purpose.
    pub description: Option<String>,
    /// Unix groups that grant this role.
    pub groups: Vec<String>,
    /// Allowed `bpf()` syscall commands. Use `"any"` for unrestricted.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Allowed program types and their permitted operations.
    ///
    /// Format: `{ "kprobe": ["load", "attach"], "xdp": ["load", "attach", "detach"] }`
    ///
    /// Use `{ "any": ["any"] }` for unrestricted access.
    #[serde(default, deserialize_with = "deserialize_type_ops")]
    pub prog_types: HashMap<String, Vec<String>>,
    /// Allowed map types and their permitted operations.
    ///
    /// Format: `{ "hash": ["create", "read", "write"], "ringbuf": ["create", "read"] }`
    ///
    /// Use `{ "any": ["any"] }` for unrestricted access.
    #[serde(default, deserialize_with = "deserialize_type_ops")]
    pub map_types: HashMap<String, Vec<String>>,
}

/// Deserializes type operations from either:
/// - A map: `{kprobe: [load, attach], xdp: [load, attach, detach]}`
/// - The special value: `{any: [any]}`
fn deserialize_type_ops<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    HashMap::<String, Vec<String>>::deserialize(deserializer)
}

/// The runtime policy engine.
///
/// Wraps a [`PolicyConfig`] and provides query methods that automatically
/// apply system-policy intersection. All permission checks go through this
/// type rather than accessing [`Role`] fields directly.
///
/// # Example
///
/// ```rust
/// use bpf_rbacd::policy::Policy;
///
/// let policy = Policy::default();
/// let role = policy.roles().get("ebpf").unwrap();
///
/// assert!(policy.is_command_allowed(role, "PROG_LOAD"));
/// assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
/// assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
/// ```
#[derive(Debug, Clone)]
pub struct Policy {
    /// The underlying deserialized configuration.
    pub config: PolicyConfig,
}

impl Policy {
    /// Load a policy from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the YAML is malformed.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&contents)?;
        Ok(Policy { config })
    }

    /// Returns a reference to the map of role name to [`Role`].
    pub fn roles(&self) -> &HashMap<String, Role> {
        &self.config.roles
    }

    /// Resolve a user's role from their Unix group membership.
    ///
    /// Checks well-known roles in priority order (`ebpf-admin` > `ebpf-net` >
    /// `ebpf`), then falls back to any matching role. Returns `None` if no
    /// role matches.
    pub fn get_role_for_groups(&self, user_groups: &[String]) -> Option<String> {
        let user_groups_set: HashSet<_> = user_groups.iter().collect();

        let priority = ["ebpf-admin", "ebpf-net", "ebpf"];

        for role_name in priority {
            if let Some(role) = self.config.roles.get(role_name) {
                for group in &role.groups {
                    if user_groups_set.contains(group) {
                        return Some(role_name.to_string());
                    }
                }
            }
        }

        for (role_name, role) in &self.config.roles {
            for group in &role.groups {
                if user_groups_set.contains(group) {
                    return Some(role_name.clone());
                }
            }
        }

        None
    }

    /// Check whether a role is allowed to perform a proxy-mode [`Request`].
    ///
    /// This is the high-level entry point used by the proxy handler. It
    /// combines command-level and type-level checks in a single call.
    pub fn is_allowed(&self, role_name: &str, request: &Request) -> bool {
        let role = match self.config.roles.get(role_name) {
            Some(r) => r,
            None => return false,
        };

        match request {
            Request::LoadProgram { prog_type, .. } => {
                self.is_command_allowed(role, "PROG_LOAD")
                    && self.is_prog_op_allowed(role, prog_type, "load")
            }
            Request::CreateMap { map_type, .. } => {
                self.is_command_allowed(role, "MAP_CREATE")
                    && self.is_map_op_allowed(role, map_type, "create")
            }
            Request::Attach { attach_type, .. } => {
                self.is_command_allowed(role, "PROG_ATTACH")
                    && self.is_prog_op_allowed(role, attach_type, "attach")
            }
        }
    }

    /// Check if a `bpf()` syscall command is allowed for this role.
    ///
    /// Applies system-policy intersection: the command must be present in
    /// **both** the role's `commands` list and the system policy's `commands`
    /// list (if a system policy is configured).
    pub fn is_command_allowed(&self, role: &Role, command: &str) -> bool {
        let role_allows = role.commands.iter().any(|c| c == "any" || c == command);
        if !role_allows {
            return false;
        }

        if let Some(ref system) = self.config.system_policy {
            system.commands.iter().any(|c| c == "any" || c == command)
        } else {
            true
        }
    }

    /// Check if a program type + operation is allowed for this role.
    ///
    /// For example, `is_prog_op_allowed(role, "kprobe", "load")` checks
    /// whether the role can load kprobe programs.
    pub fn is_prog_op_allowed(&self, role: &Role, prog_type: &str, operation: &str) -> bool {
        let role_allows = check_type_op(&role.prog_types, prog_type, operation);
        if !role_allows {
            return false;
        }

        if let Some(ref system) = self.config.system_policy {
            check_type_op(&system.prog_types, prog_type, operation)
        } else {
            true
        }
    }

    /// Check if a map type + operation is allowed for this role.
    ///
    /// For example, `is_map_op_allowed(role, "hash", "create")` checks
    /// whether the role can create hash maps.
    pub fn is_map_op_allowed(&self, role: &Role, map_type: &str, operation: &str) -> bool {
        let role_allows = check_type_op(&role.map_types, map_type, operation);
        if !role_allows {
            return false;
        }

        if let Some(ref system) = self.config.system_policy {
            check_type_op(&system.map_types, map_type, operation)
        } else {
            true
        }
    }

    /// Convert a role's allowed program types into a `u32` bitmap.
    ///
    /// Each bit position corresponds to the kernel's `BPF_PROG_TYPE_*` enum
    /// value. The result is intersected with the system policy if one exists.
    /// This bitmap is written to the eBPF map for LSM enforcement.
    pub fn prog_types_bitmap(&self, role: &Role) -> u32 {
        if role.prog_types.contains_key("any") {
            return 0xFFFFFFFF;
        }

        let mut bitmap: u32 = 0;
        for prog_type in role.prog_types.keys() {
            if let Some(bit) = prog_type_to_bit(prog_type) {
                bitmap |= 1 << bit;
            }
        }

        if let Some(ref system) = self.config.system_policy {
            let system_bitmap = if system.prog_types.contains_key("any") {
                0xFFFFFFFF
            } else {
                let mut b: u32 = 0;
                for pt in system.prog_types.keys() {
                    if let Some(bit) = prog_type_to_bit(pt) {
                        b |= 1 << bit;
                    }
                }
                b
            };
            bitmap &= system_bitmap;
        }

        bitmap
    }

    /// Convert a role's allowed map types into a `u32` bitmap.
    ///
    /// Each bit position corresponds to the kernel's `BPF_MAP_TYPE_*` enum
    /// value. The result is intersected with the system policy if one exists.
    pub fn map_types_bitmap(&self, role: &Role) -> u32 {
        if role.map_types.contains_key("any") {
            return 0xFFFFFFFF;
        }

        let mut bitmap: u32 = 0;
        for map_type in role.map_types.keys() {
            if let Some(bit) = map_type_to_bit(map_type) {
                bitmap |= 1 << bit;
            }
        }

        if let Some(ref system) = self.config.system_policy {
            let system_bitmap = if system.map_types.contains_key("any") {
                0xFFFFFFFF
            } else {
                let mut b: u32 = 0;
                for mt in system.map_types.keys() {
                    if let Some(bit) = map_type_to_bit(mt) {
                        b |= 1 << bit;
                    }
                }
                b
            };
            bitmap &= system_bitmap;
        }

        bitmap
    }

    /// Convert a role's allowed commands into a `u32` bitmap.
    ///
    /// Each bit position corresponds to the kernel's `BPF_*` command enum
    /// value (e.g. `BPF_MAP_CREATE` = bit 0, `BPF_PROG_LOAD` = bit 5).
    pub fn commands_bitmap(&self, role: &Role) -> u32 {
        if role.commands.iter().any(|c| c == "any") {
            return 0xFFFFFFFF;
        }

        let mut bitmap: u32 = 0;
        for cmd in &role.commands {
            if let Some(bit) = command_to_bit(cmd) {
                bitmap |= 1 << bit;
            }
        }

        if let Some(ref system) = self.config.system_policy {
            let system_bitmap = if system.commands.iter().any(|c| c == "any") {
                0xFFFFFFFF
            } else {
                let mut b: u32 = 0;
                for cmd in &system.commands {
                    if let Some(bit) = command_to_bit(cmd) {
                        b |= 1 << bit;
                    }
                }
                b
            };
            bitmap &= system_bitmap;
        }

        bitmap
    }
}

/// Check if a type+operation is allowed in a type map.
fn check_type_op(type_map: &HashMap<String, Vec<String>>, type_name: &str, op: &str) -> bool {
    if let Some(ops) = type_map.get("any") {
        return ops.iter().any(|o| o == "any" || o == op);
    }
    if let Some(ops) = type_map.get(type_name) {
        return ops.iter().any(|o| o == "any" || o == op);
    }
    false
}

/// Map program type name to kernel BPF_PROG_TYPE_* enum value.
fn prog_type_to_bit(name: &str) -> Option<u32> {
    match name {
        "socket_filter" => Some(1),
        "kprobe" | "kretprobe" => Some(2),
        "sched_cls" => Some(3),
        "sched_act" => Some(4),
        "tracepoint" => Some(5),
        "xdp" => Some(6),
        "perf_event" => Some(7),
        "cgroup_skb" => Some(8),
        "cgroup_sock" => Some(9),
        "lwt_in" => Some(10),
        "lwt_out" => Some(11),
        "lwt_xmit" => Some(12),
        "sock_ops" => Some(13),
        "sk_skb" => Some(14),
        "cgroup_device" => Some(15),
        "sk_msg" => Some(16),
        "raw_tracepoint" => Some(17),
        "cgroup_sock_addr" => Some(18),
        "lwt_seg6local" => Some(19),
        "lirc_mode2" => Some(20),
        "sk_reuseport" => Some(21),
        "flow_dissector" => Some(22),
        "cgroup_sysctl" => Some(23),
        "raw_tracepoint_writable" => Some(24),
        "cgroup_sockopt" => Some(25),
        "tracing" | "fentry" | "fexit" => Some(26),
        "struct_ops" => Some(27),
        "ext" => Some(28),
        "lsm" => Some(29),
        "sk_lookup" => Some(30),
        "uprobe" | "uretprobe" => Some(2), // kprobe type in kernel
        _ => None,
    }
}

/// Map map type name to kernel BPF_MAP_TYPE_* enum value.
fn map_type_to_bit(name: &str) -> Option<u32> {
    match name {
        "hash" => Some(1),
        "array" => Some(2),
        "prog_array" => Some(3),
        "perf_event_array" => Some(4),
        "percpu_hash" => Some(5),
        "percpu_array" => Some(6),
        "stack_trace" => Some(7),
        "cgroup_array" => Some(8),
        "lru_hash" => Some(9),
        "lru_percpu_hash" => Some(10),
        "lpm_trie" => Some(11),
        "array_of_maps" => Some(12),
        "hash_of_maps" => Some(13),
        "devmap" => Some(14),
        "sockmap" => Some(15),
        "cpumap" => Some(16),
        "xskmap" => Some(17),
        "sockhash" => Some(18),
        "cgroup_storage" => Some(19),
        "reuseport_sockarray" => Some(20),
        "percpu_cgroup_storage" => Some(21),
        "queue" => Some(22),
        "stack" => Some(23),
        "sk_storage" => Some(24),
        "devmap_hash" => Some(25),
        "struct_ops" => Some(26),
        "ringbuf" => Some(27),
        "inode_storage" => Some(28),
        "task_storage" => Some(29),
        "bloom_filter" => Some(30),
        _ => None,
    }
}

/// Map BPF command name to kernel BPF_* command number.
fn command_to_bit(name: &str) -> Option<u32> {
    match name {
        "MAP_CREATE" => Some(0),
        "MAP_LOOKUP_ELEM" => Some(1),
        "MAP_UPDATE_ELEM" => Some(2),
        "MAP_DELETE_ELEM" => Some(3),
        "MAP_GET_NEXT_KEY" => Some(4),
        "PROG_LOAD" => Some(5),
        "OBJ_PIN" => Some(6),
        "OBJ_GET" => Some(7),
        "PROG_ATTACH" => Some(8),
        "PROG_DETACH" => Some(9),
        "PROG_TEST_RUN" => Some(10),
        "PROG_GET_NEXT_ID" => Some(11),
        "MAP_GET_NEXT_ID" => Some(12),
        "PROG_GET_FD_BY_ID" => Some(13),
        "MAP_GET_FD_BY_ID" => Some(14),
        "OBJ_GET_INFO_BY_FD" => Some(15),
        "PROG_QUERY" => Some(16),
        "RAW_TRACEPOINT_OPEN" => Some(17),
        "BTF_LOAD" => Some(18),
        "BTF_GET_FD_BY_ID" => Some(19),
        "TASK_FD_QUERY" => Some(20),
        "MAP_LOOKUP_AND_DELETE_ELEM" => Some(21),
        "MAP_FREEZE" => Some(22),
        "BTF_GET_NEXT_ID" => Some(23),
        "MAP_LOOKUP_BATCH" => Some(24),
        "MAP_LOOKUP_AND_DELETE_BATCH" => Some(25),
        "MAP_UPDATE_BATCH" => Some(26),
        "MAP_DELETE_BATCH" => Some(27),
        "LINK_CREATE" => Some(28),
        "LINK_UPDATE" => Some(29),
        "LINK_GET_FD_BY_ID" => Some(30),
        "LINK_GET_NEXT_ID" => Some(31),
        _ => None,
    }
}

impl Default for Policy {
    fn default() -> Self {
        let mut roles = HashMap::new();

        let mut ebpf_progs = HashMap::new();
        ebpf_progs.insert("kprobe".to_string(), vec!["load".to_string(), "attach".to_string()]);
        ebpf_progs.insert("uprobe".to_string(), vec!["load".to_string(), "attach".to_string()]);
        ebpf_progs.insert("tracepoint".to_string(), vec!["load".to_string(), "attach".to_string()]);
        ebpf_progs.insert("perf_event".to_string(), vec!["load".to_string(), "attach".to_string()]);
        ebpf_progs.insert("raw_tracepoint".to_string(), vec!["load".to_string(), "attach".to_string()]);

        let mut ebpf_maps = HashMap::new();
        ebpf_maps.insert("hash".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);
        ebpf_maps.insert("array".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);
        ebpf_maps.insert("perf_event_array".to_string(), vec!["create".to_string(), "read".to_string()]);
        ebpf_maps.insert("ringbuf".to_string(), vec!["create".to_string(), "read".to_string()]);

        roles.insert(
            "ebpf".to_string(),
            Role {
                description: Some("Tracing workloads".to_string()),
                groups: vec!["ebpf".to_string()],
                commands: vec![
                    "PROG_LOAD".to_string(),
                    "MAP_CREATE".to_string(),
                    "MAP_LOOKUP_ELEM".to_string(),
                    "MAP_UPDATE_ELEM".to_string(),
                    "LINK_CREATE".to_string(),
                    "BTF_LOAD".to_string(),
                ],
                prog_types: ebpf_progs,
                map_types: ebpf_maps,
            },
        );

        let mut net_progs = HashMap::new();
        net_progs.insert("xdp".to_string(), vec!["load".to_string(), "attach".to_string(), "detach".to_string()]);
        net_progs.insert("sched_cls".to_string(), vec!["load".to_string(), "attach".to_string(), "detach".to_string()]);
        net_progs.insert("socket_filter".to_string(), vec!["load".to_string(), "attach".to_string()]);

        let mut net_maps = HashMap::new();
        net_maps.insert("hash".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);
        net_maps.insert("array".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);
        net_maps.insert("devmap".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);
        net_maps.insert("lru_hash".to_string(), vec!["create".to_string(), "read".to_string(), "write".to_string()]);

        roles.insert(
            "ebpf-net".to_string(),
            Role {
                description: Some("Networking workloads".to_string()),
                groups: vec!["ebpf-net".to_string()],
                commands: vec![
                    "PROG_LOAD".to_string(),
                    "MAP_CREATE".to_string(),
                    "MAP_LOOKUP_ELEM".to_string(),
                    "MAP_UPDATE_ELEM".to_string(),
                    "LINK_CREATE".to_string(),
                    "PROG_ATTACH".to_string(),
                    "BTF_LOAD".to_string(),
                ],
                prog_types: net_progs,
                map_types: net_maps,
            },
        );

        let mut admin_progs = HashMap::new();
        admin_progs.insert("any".to_string(), vec!["any".to_string()]);
        let mut admin_maps = HashMap::new();
        admin_maps.insert("any".to_string(), vec!["any".to_string()]);

        roles.insert(
            "ebpf-admin".to_string(),
            Role {
                description: Some("Full BPF access".to_string()),
                groups: vec!["ebpf-admin".to_string()],
                commands: vec!["any".to_string()],
                prog_types: admin_progs,
                map_types: admin_maps,
            },
        );

        Policy {
            config: PolicyConfig {
                system_policy: None,
                roles,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_allows_tracing() {
        let policy = Policy::default();
        let role = policy.config.roles.get("ebpf").unwrap();
        assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
        assert!(policy.is_prog_op_allowed(role, "tracepoint", "attach"));
        assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
    }

    #[test]
    fn test_default_policy_allows_networking() {
        let policy = Policy::default();
        let role = policy.config.roles.get("ebpf-net").unwrap();
        assert!(policy.is_prog_op_allowed(role, "xdp", "load"));
        assert!(policy.is_prog_op_allowed(role, "xdp", "detach"));
        assert!(!policy.is_prog_op_allowed(role, "kprobe", "load"));
    }

    #[test]
    fn test_admin_allows_all() {
        let policy = Policy::default();
        let role = policy.config.roles.get("ebpf-admin").unwrap();
        assert!(policy.is_prog_op_allowed(role, "xdp", "load"));
        assert!(policy.is_prog_op_allowed(role, "kprobe", "attach"));
        assert!(policy.is_map_op_allowed(role, "hash", "create"));
        assert!(policy.is_command_allowed(role, "PROG_LOAD"));
        assert!(policy.is_command_allowed(role, "MAP_CREATE"));
    }

    #[test]
    fn test_bitmap_generation() {
        let policy = Policy::default();
        let role = policy.config.roles.get("ebpf").unwrap();

        let prog_bitmap = policy.prog_types_bitmap(role);
        // kprobe=2, tracepoint=5, perf_event=7, raw_tracepoint=17, uprobe=2
        assert!(prog_bitmap & (1 << 2) != 0); // kprobe
        assert!(prog_bitmap & (1 << 5) != 0); // tracepoint
        assert!(prog_bitmap & (1 << 6) == 0); // xdp not allowed

        let map_bitmap = policy.map_types_bitmap(role);
        assert!(map_bitmap & (1 << 1) != 0); // hash
        assert!(map_bitmap & (1 << 2) != 0); // array
        assert!(map_bitmap & (1 << 14) == 0); // devmap not allowed
    }

    #[test]
    fn test_system_policy_intersection() {
        let yaml = r#"
system_policy:
  commands: [PROG_LOAD, MAP_CREATE]
  prog_types:
    kprobe: [load, attach]
  map_types:
    hash: [create, read]

roles:
  test:
    groups: [test]
    commands: [PROG_LOAD, MAP_CREATE, LINK_CREATE]
    prog_types:
      kprobe: [load, attach, detach]
      xdp: [load]
    map_types:
      hash: [create, read, write]
      array: [create]
"#;
        let config: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let policy = Policy { config };
        let role = policy.config.roles.get("test").unwrap();

        // LINK_CREATE is in role but not in system → denied
        assert!(!policy.is_command_allowed(role, "LINK_CREATE"));
        // PROG_LOAD is in both → allowed
        assert!(policy.is_command_allowed(role, "PROG_LOAD"));

        // xdp is in role but not in system → denied
        assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
        // kprobe load is in both → allowed
        assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
        // kprobe detach is in role but not system → denied
        assert!(!policy.is_prog_op_allowed(role, "kprobe", "detach"));

        // hash write is in role but not system → denied
        assert!(!policy.is_map_op_allowed(role, "hash", "write"));
        // hash read is in both → allowed
        assert!(policy.is_map_op_allowed(role, "hash", "read"));
        // array is in role but not system → denied
        assert!(!policy.is_map_op_allowed(role, "array", "create"));
    }
}
