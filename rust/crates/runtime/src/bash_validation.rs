//! Bash command validation submodules.
//!
//! Ports the upstream `BashTool` validation pipeline:
//! - `readOnlyValidation` — block write-like commands in read-only mode
//! - `destructiveCommandWarning` — flag dangerous destructive commands
//! - `modeValidation` — enforce permission mode constraints on commands
//! - `sedValidation` — validate sed expressions before execution
//! - `pathValidation` — detect suspicious path patterns
//! - `commandSemantics` — classify command intent

use std::path::Path;

use crate::permissions::PermissionMode;

/// Result of validating a bash command before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Command is safe to execute.
    Allow,
    /// Command should be blocked with the given reason.
    Block { reason: String },
    /// Command requires user confirmation with the given warning.
    Warn { message: String },
}

/// Semantic classification of a bash command's intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandIntent {
    /// Read-only operations: ls, cat, grep, find, etc.
    ReadOnly,
    /// File system writes: cp, mv, mkdir, touch, tee, etc.
    Write,
    /// Destructive operations: rm, shred, truncate, etc.
    Destructive,
    /// Network operations: curl, wget, ssh, etc.
    Network,
    /// Process management: kill, pkill, etc.
    ProcessManagement,
    /// Package management: apt, brew, pip, npm, etc.
    PackageManagement,
    /// System administration: sudo, chmod, chown, mount, etc.
    SystemAdmin,
    /// Unknown or unclassifiable command.
    Unknown,
}

// ---------------------------------------------------------------------------
// readOnlyValidation
// ---------------------------------------------------------------------------

/// Commands that perform write operations and should be blocked in read-only mode.
const WRITE_COMMANDS: &[&str] = &[
    "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "ln", "install", "tee",
    "truncate", "shred", "mkfifo", "mknod", "dd",
];

/// Commands that modify system state and should be blocked in read-only mode.
const STATE_MODIFYING_COMMANDS: &[&str] = &[
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
    "brew",
    "pip",
    "pip3",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "cargo",
    "gem",
    "go",
    "rustup",
    "docker",
    "systemctl",
    "service",
    "mount",
    "umount",
    "kill",
    "pkill",
    "killall",
    "reboot",
    "shutdown",
    "halt",
    "poweroff",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "crontab",
    "at",
];

/// Shell redirection operators that indicate writes.
const WRITE_REDIRECTIONS: &[&str] = &[">", ">>", ">&"];

/// Validate that a command is allowed under read-only mode.
///
/// Corresponds to upstream `tools/BashTool/readOnlyValidation.ts`.
#[must_use]
pub fn validate_read_only(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        return ValidationResult::Allow;
    }

    for segment in split_command_chain(command) {
        let result = validate_read_only_segment(segment, mode);
        if result != ValidationResult::Allow {
            return result;
        }
    }

    ValidationResult::Allow
}

fn validate_read_only_segment(command: &str, mode: PermissionMode) -> ValidationResult {
    let first_command = extract_first_command(command);

    for &write_cmd in WRITE_COMMANDS {
        if first_command == write_cmd {
            return ValidationResult::Block {
                reason: format!(
                    "Command '{write_cmd}' modifies the filesystem and is not allowed in read-only mode"
                ),
            };
        }
    }

    for &state_cmd in STATE_MODIFYING_COMMANDS {
        if first_command == state_cmd {
            return ValidationResult::Block {
                reason: format!(
                    "Command '{state_cmd}' modifies system state and is not allowed in read-only mode"
                ),
            };
        }
    }

    if first_command == "sudo" {
        let inner = extract_sudo_inner(command);
        if !inner.is_empty() {
            let inner_result = validate_read_only_segment(inner, mode);
            if inner_result != ValidationResult::Allow {
                return inner_result;
            }
        }
    }

    for &redir in WRITE_REDIRECTIONS {
        if command.contains(redir) {
            return ValidationResult::Block {
                reason: format!(
                    "Command contains write redirection '{redir}' which is not allowed in read-only mode"
                ),
            };
        }
    }

    if first_command == "git" {
        return validate_git_read_only(command);
    }

    ValidationResult::Allow
}

/// Git subcommands that are read-only safe.
const GIT_READ_ONLY_SUBCOMMANDS: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "branch",
    "tag",
    "stash",
    "remote",
    "fetch",
    "ls-files",
    "ls-tree",
    "cat-file",
    "rev-parse",
    "describe",
    "shortlog",
    "blame",
    "bisect",
    "reflog",
    "config",
];

fn validate_git_read_only(command: &str) -> ValidationResult {
    let parts: Vec<&str> = command.split_whitespace().collect();
    // Skip past "git" and any flags (e.g., "git -C /path")
    let subcommand = parts.iter().skip(1).find(|p| !p.starts_with('-'));

    match subcommand {
        Some(&sub) if GIT_READ_ONLY_SUBCOMMANDS.contains(&sub) => ValidationResult::Allow,
        Some(&sub) => ValidationResult::Block {
            reason: format!(
                "Git subcommand '{sub}' modifies repository state and is not allowed in read-only mode"
            ),
        },
        None => ValidationResult::Allow, // bare "git" is fine
    }
}

// ---------------------------------------------------------------------------
// destructiveCommandWarning
// ---------------------------------------------------------------------------

/// Patterns that indicate potentially destructive commands.
const DESTRUCTIVE_PATTERNS: &[(&str, &str)] = &[
    (
        "rm -rf /",
        "Recursive forced deletion at root — this will destroy the system",
    ),
    ("rm -rf ~", "Recursive forced deletion of home directory"),
    (
        "rm -rf *",
        "Recursive forced deletion of all files in current directory",
    ),
    ("rm -rf .", "Recursive forced deletion of current directory"),
    (
        "mkfs",
        "Filesystem creation will destroy existing data on the device",
    ),
    (
        "dd if=",
        "Direct disk write — can overwrite partitions or devices",
    ),
    ("> /dev/sd", "Writing to raw disk device"),
    (
        "chmod -R 777",
        "Recursively setting world-writable permissions",
    ),
    ("chmod -R 000", "Recursively removing all permissions"),
    (":(){ :|:& };:", "Fork bomb — will crash the system"),
];

/// Commands that are always destructive regardless of arguments.
const ALWAYS_DESTRUCTIVE_COMMANDS: &[&str] = &["shred", "wipefs"];

/// Warn if a command looks destructive.
///
/// Corresponds to upstream `tools/BashTool/destructiveCommandWarning.ts`.
#[must_use]
pub fn check_destructive(command: &str) -> ValidationResult {
    // Check known destructive patterns.
    for &(pattern, warning) in DESTRUCTIVE_PATTERNS {
        if command.contains(pattern) {
            return ValidationResult::Warn {
                message: format!("Destructive command detected: {warning}"),
            };
        }
    }

    // Check always-destructive commands + rm -rf in any chained segment.
    for segment in split_command_chain(command) {
        let first = extract_first_command(segment);
        for &cmd in ALWAYS_DESTRUCTIVE_COMMANDS {
            if first == cmd {
                return ValidationResult::Warn {
                    message: format!(
                        "Command '{cmd}' is inherently destructive and may cause data loss"
                    ),
                };
            }
        }
        if first == "rm" && (segment.contains("-r") || segment.contains("-R"))
            && segment.contains("-f")
        {
            return ValidationResult::Warn {
                message: "Recursive forced deletion detected — verify the target path is correct"
                    .to_string(),
            };
        }
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// modeValidation
// ---------------------------------------------------------------------------

/// Validate that a command is consistent with the given permission mode.
///
/// Corresponds to upstream `tools/BashTool/modeValidation.ts`.
#[must_use]
pub fn validate_mode(command: &str, mode: PermissionMode) -> ValidationResult {
    match mode {
        PermissionMode::ReadOnly => validate_read_only(command, mode),
        PermissionMode::WorkspaceWrite => {
            // In workspace-write mode, check for system-level destructive
            // operations that go beyond workspace scope.
            if command_targets_outside_workspace(command) {
                return ValidationResult::Warn {
                    message:
                        "Command appears to target files outside the workspace — requires elevated permission"
                            .to_string(),
                };
            }
            ValidationResult::Allow
        }
        PermissionMode::DangerFullAccess | PermissionMode::Allow | PermissionMode::Prompt => {
            ValidationResult::Allow
        }
    }
}

/// Heuristic: does the command reference absolute paths outside typical workspace dirs?
fn command_targets_outside_workspace(command: &str) -> bool {
    let system_paths = [
        "/etc/", "/usr/", "/var/", "/boot/", "/sys/", "/proc/", "/dev/", "/sbin/", "/lib/", "/opt/",
    ];

    for segment in split_command_chain(command) {
        let first = extract_first_command(segment);
        let is_write_cmd = WRITE_COMMANDS.contains(&first.as_str())
            || STATE_MODIFYING_COMMANDS.contains(&first.as_str());
        if !is_write_cmd {
            continue;
        }
        for sys_path in &system_paths {
            if segment.contains(sys_path) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// sedValidation
// ---------------------------------------------------------------------------

/// Validate sed expressions for safety.
///
/// Corresponds to upstream `tools/BashTool/sedValidation.ts`.
#[must_use]
pub fn validate_sed(command: &str, mode: PermissionMode) -> ValidationResult {
    if mode != PermissionMode::ReadOnly {
        // Still return Allow when not read-only; in-place is only restricted there.
        return ValidationResult::Allow;
    }

    for segment in split_command_chain(command) {
        if segment_uses_sed_inplace(segment) {
            return ValidationResult::Block {
                reason: "sed -i (in-place editing) is not allowed in read-only mode".to_string(),
            };
        }
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// pathValidation
// ---------------------------------------------------------------------------

/// Validate that command paths don't include suspicious traversal patterns.
///
/// Corresponds to upstream `tools/BashTool/pathValidation.ts`.
#[must_use]
pub fn validate_paths(command: &str, workspace: &Path) -> ValidationResult {
    // Check for directory traversal attempts.
    if command.contains("../") {
        let workspace_str = workspace.to_string_lossy();
        // Allow traversal if it resolves within workspace (heuristic).
        if !command.contains(&*workspace_str) {
            return ValidationResult::Warn {
                message: "Command contains directory traversal pattern '../' — verify the target path resolves within the workspace".to_string(),
            };
        }
    }

    // Check for home directory references that could escape workspace.
    if command.contains("~/") || command.contains("$HOME") {
        return ValidationResult::Warn {
            message:
                "Command references home directory — verify it stays within the workspace scope"
                    .to_string(),
        };
    }

    ValidationResult::Allow
}

// ---------------------------------------------------------------------------
// commandSemantics
// ---------------------------------------------------------------------------

/// Commands that are read-only (no filesystem or state modification).
const SEMANTIC_READ_ONLY_COMMANDS: &[&str] = &[
    "ls",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "sort",
    "uniq",
    "grep",
    "egrep",
    "fgrep",
    "find",
    "which",
    "whereis",
    "whatis",
    "man",
    "info",
    "file",
    "stat",
    "du",
    "df",
    "free",
    "uptime",
    "uname",
    "hostname",
    "whoami",
    "id",
    "groups",
    "env",
    "printenv",
    "echo",
    "printf",
    "date",
    "cal",
    "bc",
    "expr",
    "test",
    "true",
    "false",
    "pwd",
    "tree",
    "diff",
    "cmp",
    "md5sum",
    "sha256sum",
    "sha1sum",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "readlink",
    "realpath",
    "basename",
    "dirname",
    "seq",
    "yes",
    "tput",
    "column",
    "jq",
    "yq",
    "xargs",
    "tr",
    "cut",
    "paste",
    "awk",
    "sed",
];

/// Commands that perform network operations.
const NETWORK_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "ftp",
    "sftp",
    "nc",
    "ncat",
    "telnet",
    "ping",
    "traceroute",
    "dig",
    "nslookup",
    "host",
    "whois",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
    "nmap",
];

/// Commands that manage processes.
const PROCESS_COMMANDS: &[&str] = &[
    "kill", "pkill", "killall", "ps", "top", "htop", "bg", "fg", "jobs", "nohup", "disown", "wait",
    "nice", "renice",
];

/// Commands that manage packages.
const PACKAGE_COMMANDS: &[&str] = &[
    "apt", "apt-get", "yum", "dnf", "pacman", "brew", "pip", "pip3", "npm", "yarn", "pnpm", "bun",
    "cargo", "gem", "go", "rustup", "snap", "flatpak",
];

/// Commands that require system administrator privileges.
const SYSTEM_ADMIN_COMMANDS: &[&str] = &[
    "sudo",
    "su",
    "chroot",
    "mount",
    "umount",
    "fdisk",
    "parted",
    "lsblk",
    "blkid",
    "systemctl",
    "service",
    "journalctl",
    "dmesg",
    "modprobe",
    "insmod",
    "rmmod",
    "iptables",
    "ufw",
    "firewall-cmd",
    "sysctl",
    "crontab",
    "at",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "passwd",
    "visudo",
];

/// Classify the semantic intent of a bash command.
///
/// Corresponds to upstream `tools/BashTool/commandSemantics.ts`.
#[must_use]
pub fn classify_command(command: &str) -> CommandIntent {
    let first = extract_first_command(command);
    classify_by_first_command(&first, command)
}

fn classify_by_first_command(first: &str, command: &str) -> CommandIntent {
    if SEMANTIC_READ_ONLY_COMMANDS.contains(&first) {
        if first == "sed" && command.contains(" -i") {
            return CommandIntent::Write;
        }
        return CommandIntent::ReadOnly;
    }

    if ALWAYS_DESTRUCTIVE_COMMANDS.contains(&first) || first == "rm" {
        return CommandIntent::Destructive;
    }

    if WRITE_COMMANDS.contains(&first) {
        return CommandIntent::Write;
    }

    if NETWORK_COMMANDS.contains(&first) {
        return CommandIntent::Network;
    }

    if PROCESS_COMMANDS.contains(&first) {
        return CommandIntent::ProcessManagement;
    }

    if PACKAGE_COMMANDS.contains(&first) {
        return CommandIntent::PackageManagement;
    }

    if SYSTEM_ADMIN_COMMANDS.contains(&first) {
        return CommandIntent::SystemAdmin;
    }

    if first == "git" {
        return classify_git_command(command);
    }

    CommandIntent::Unknown
}

fn classify_git_command(command: &str) -> CommandIntent {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let subcommand = parts.iter().skip(1).find(|p| !p.starts_with('-'));
    match subcommand {
        Some(&sub) if GIT_READ_ONLY_SUBCOMMANDS.contains(&sub) => CommandIntent::ReadOnly,
        _ => CommandIntent::Write,
    }
}

// ---------------------------------------------------------------------------
// Pipeline: run all validations
// ---------------------------------------------------------------------------

/// Run the full validation pipeline on a bash command.
///
/// Returns the first non-Allow result, or Allow if all validations pass.
#[must_use]
pub fn validate_command(command: &str, mode: PermissionMode, workspace: &Path) -> ValidationResult {
    // 1. Mode-level validation (includes read-only checks).
    let result = validate_mode(command, mode);
    if result != ValidationResult::Allow {
        return result;
    }

    // 2. Sed-specific validation.
    let result = validate_sed(command, mode);
    if result != ValidationResult::Allow {
        return result;
    }

    // 3. Destructive command warnings.
    let result = check_destructive(command);
    if result != ValidationResult::Allow {
        return result;
    }

    // 4. Path validation.
    validate_paths(command, workspace)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the first bare command from a pipeline/chain, stripping env vars and sudo.
fn extract_first_command(command: &str) -> String {
    let trimmed = command.trim();

    // Skip leading environment variable assignments (KEY=val cmd ...).
    let mut remaining = trimmed;
    loop {
        let next = remaining.trim_start();
        if let Some(eq_pos) = next.find('=') {
            let before_eq = &next[..eq_pos];
            // Valid env var name: alphanumeric + underscore, no spaces.
            if !before_eq.is_empty()
                && before_eq
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                // Skip past the value (might be quoted).
                let after_eq = &next[eq_pos + 1..];
                if let Some(space) = find_end_of_value(after_eq) {
                    remaining = &after_eq[space..];
                    continue;
                }
                // No space found means value goes to end of string — no actual command.
                return String::new();
            }
        }
        break;
    }

    remaining
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Extract the command following "sudo" (skip sudo flags).
fn extract_sudo_inner(command: &str) -> &str {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let sudo_idx = parts.iter().position(|&p| p == "sudo");
    match sudo_idx {
        Some(idx) => {
            // Skip flags after sudo.
            let rest = &parts[idx + 1..];
            for &part in rest {
                if !part.starts_with('-') {
                    // Found the inner command — return from here to end.
                    let offset = command.find(part).unwrap_or(0);
                    return &command[offset..];
                }
            }
            ""
        }
        None => "",
    }
}

/// Find the end of a value in `KEY=value rest` (handles basic quoting).
fn find_end_of_value(s: &str) -> Option<usize> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }

    let first = s.as_bytes()[0];
    if first == b'"' || first == b'\'' {
        let quote = first;
        let mut i = 1;
        while i < s.len() {
            if s.as_bytes()[i] == quote && (i == 0 || s.as_bytes()[i - 1] != b'\\') {
                // Skip past quote.
                i += 1;
                // Find next whitespace.
                while i < s.len() && !s.as_bytes()[i].is_ascii_whitespace() {
                    i += 1;
                }
                return if i < s.len() { Some(i) } else { None };
            }
            i += 1;
        }
        None
    } else {
        s.find(char::is_whitespace)
    }
}

/// Split a bash command string into individual command segments along
/// top-level separators: `;`, `|`, `||`, `&&`, `&`.
///
/// Honors single quotes, double quotes (with backslash escapes), backticks,
/// `$(...)` subshells, and `${...}` parameter expansions so separators inside
/// those are ignored. Also skips `>&` / `&>` redirection operators so they do
/// not split as background `&`.
#[must_use]
pub fn split_command_chain(command: &str) -> Vec<&str> {
    let bytes = command.as_bytes();
    let mut out = Vec::new();
    let mut seg_start = 0usize;
    let mut i = 0usize;

    let mut in_single = false;
    let mut in_double = false;
    let mut depth_paren = 0i32; // $(...)
    let mut depth_brace = 0i32; // ${...}
    let mut depth_backtick = 0i32;

    while i < bytes.len() {
        let b = bytes[i];

        // Inside single-quoted string: nothing escapes except the closing quote.
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }

        // Inside double-quoted string: backslash escapes next char.
        if in_double {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
                i += 1;
                continue;
            }
            // $( still opens a subshell inside double quotes
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                depth_paren += 1;
                i += 2;
                continue;
            }
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                depth_brace += 1;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if depth_backtick > 0 {
            if b == b'`' {
                depth_backtick -= 1;
            }
            i += 1;
            continue;
        }

        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_double = true;
            i += 1;
            continue;
        }
        if b == b'`' {
            depth_backtick += 1;
            i += 1;
            continue;
        }
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            depth_paren += 1;
            i += 2;
            continue;
        }
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            depth_brace += 1;
            i += 2;
            continue;
        }
        if b == b')' && depth_paren > 0 {
            depth_paren -= 1;
            i += 1;
            continue;
        }
        if b == b'}' && depth_brace > 0 {
            depth_brace -= 1;
            i += 1;
            continue;
        }

        if depth_paren > 0 || depth_brace > 0 {
            i += 1;
            continue;
        }

        // Skip redirection operators that contain `&`: `>&`, `&>`, `1>&2`, etc.
        // Treat `N>&M` as a single token so we do not split on the `&`.
        if b == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'>' {
            i += 2;
            continue;
        }
        if b == b'>' && i + 1 < bytes.len() && bytes[i + 1] == b'&' {
            i += 2;
            continue;
        }

        // Separator detection.
        let sep_len = match b {
            b';' => 1,
            b'|' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    2
                } else {
                    1
                }
            }
            b'&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    2
                } else {
                    1
                }
            }
            _ => 0,
        };

        if sep_len > 0 {
            let seg = command[seg_start..i].trim();
            if !seg.is_empty() {
                out.push(seg);
            }
            i += sep_len;
            seg_start = i;
            continue;
        }

        i += 1;
    }

    let tail = command[seg_start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Detect sed in-place editing flags in a single command segment.
fn segment_uses_sed_inplace(segment: &str) -> bool {
    let mut tokens = segment.split_whitespace();
    let first = match tokens.next() {
        Some(t) => t,
        None => return false,
    };
    if first != "sed" {
        return false;
    }
    for tok in tokens {
        if tok == "-i" || tok == "--in-place" {
            return true;
        }
        if let Some(rest) = tok.strip_prefix("--in-place=") {
            let _ = rest;
            return true;
        }
        if let Some(rest) = tok.strip_prefix("-i") {
            // -i<suffix>  (BSD sed style)
            let _ = rest;
            return true;
        }
        if let Some(rest) = tok.strip_prefix('-') {
            // Bundled short flags like -Ei, -nEi
            if !rest.starts_with('-') && rest.contains('i') {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- readOnlyValidation ---

    #[test]
    fn blocks_rm_in_read_only() {
        assert!(matches!(
            validate_read_only("rm -rf /tmp/x", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("rm")
        ));
    }

    #[test]
    fn allows_rm_in_workspace_write() {
        assert_eq!(
            validate_read_only("rm -rf /tmp/x", PermissionMode::WorkspaceWrite),
            ValidationResult::Allow
        );
    }

    #[test]
    fn blocks_write_redirections_in_read_only() {
        assert!(matches!(
            validate_read_only("echo hello > file.txt", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("redirection")
        ));
    }

    #[test]
    fn allows_read_commands_in_read_only() {
        assert_eq!(
            validate_read_only("ls -la", PermissionMode::ReadOnly),
            ValidationResult::Allow
        );
        assert_eq!(
            validate_read_only("cat /etc/hosts", PermissionMode::ReadOnly),
            ValidationResult::Allow
        );
        assert_eq!(
            validate_read_only("grep -r pattern .", PermissionMode::ReadOnly),
            ValidationResult::Allow
        );
    }

    #[test]
    fn blocks_sudo_write_in_read_only() {
        assert!(matches!(
            validate_read_only("sudo rm -rf /tmp/x", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("rm")
        ));
    }

    #[test]
    fn blocks_git_push_in_read_only() {
        assert!(matches!(
            validate_read_only("git push origin main", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("push")
        ));
    }

    #[test]
    fn allows_git_status_in_read_only() {
        assert_eq!(
            validate_read_only("git status", PermissionMode::ReadOnly),
            ValidationResult::Allow
        );
    }

    #[test]
    fn blocks_package_install_in_read_only() {
        assert!(matches!(
            validate_read_only("npm install express", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("npm")
        ));
    }

    // --- destructiveCommandWarning ---

    #[test]
    fn warns_rm_rf_root() {
        assert!(matches!(
            check_destructive("rm -rf /"),
            ValidationResult::Warn { message } if message.contains("root")
        ));
    }

    #[test]
    fn warns_rm_rf_home() {
        assert!(matches!(
            check_destructive("rm -rf ~"),
            ValidationResult::Warn { message } if message.contains("home")
        ));
    }

    #[test]
    fn warns_shred() {
        assert!(matches!(
            check_destructive("shred /dev/sda"),
            ValidationResult::Warn { message } if message.contains("destructive")
        ));
    }

    #[test]
    fn warns_fork_bomb() {
        assert!(matches!(
            check_destructive(":(){ :|:& };:"),
            ValidationResult::Warn { message } if message.contains("Fork bomb")
        ));
    }

    #[test]
    fn allows_safe_commands() {
        assert_eq!(check_destructive("ls -la"), ValidationResult::Allow);
        assert_eq!(check_destructive("echo hello"), ValidationResult::Allow);
    }

    // --- modeValidation ---

    #[test]
    fn workspace_write_warns_system_paths() {
        assert!(matches!(
            validate_mode("cp file.txt /etc/config", PermissionMode::WorkspaceWrite),
            ValidationResult::Warn { message } if message.contains("outside the workspace")
        ));
    }

    #[test]
    fn workspace_write_allows_local_writes() {
        assert_eq!(
            validate_mode("cp file.txt ./backup/", PermissionMode::WorkspaceWrite),
            ValidationResult::Allow
        );
    }

    // --- sedValidation ---

    #[test]
    fn blocks_sed_inplace_in_read_only() {
        assert!(matches!(
            validate_sed("sed -i 's/old/new/' file.txt", PermissionMode::ReadOnly),
            ValidationResult::Block { reason } if reason.contains("sed -i")
        ));
    }

    #[test]
    fn allows_sed_stdout_in_read_only() {
        assert_eq!(
            validate_sed("sed 's/old/new/' file.txt", PermissionMode::ReadOnly),
            ValidationResult::Allow
        );
    }

    // --- pathValidation ---

    #[test]
    fn warns_directory_traversal() {
        let workspace = PathBuf::from("/workspace/project");
        assert!(matches!(
            validate_paths("cat ../../../etc/passwd", &workspace),
            ValidationResult::Warn { message } if message.contains("traversal")
        ));
    }

    #[test]
    fn warns_home_directory_reference() {
        let workspace = PathBuf::from("/workspace/project");
        assert!(matches!(
            validate_paths("cat ~/.ssh/id_rsa", &workspace),
            ValidationResult::Warn { message } if message.contains("home directory")
        ));
    }

    // --- commandSemantics ---

    #[test]
    fn classifies_read_only_commands() {
        assert_eq!(classify_command("ls -la"), CommandIntent::ReadOnly);
        assert_eq!(classify_command("cat file.txt"), CommandIntent::ReadOnly);
        assert_eq!(
            classify_command("grep -r pattern ."),
            CommandIntent::ReadOnly
        );
        assert_eq!(
            classify_command("find . -name '*.rs'"),
            CommandIntent::ReadOnly
        );
    }

    #[test]
    fn classifies_write_commands() {
        assert_eq!(classify_command("cp a.txt b.txt"), CommandIntent::Write);
        assert_eq!(classify_command("mv old.txt new.txt"), CommandIntent::Write);
        assert_eq!(classify_command("mkdir -p /tmp/dir"), CommandIntent::Write);
    }

    #[test]
    fn classifies_destructive_commands() {
        assert_eq!(
            classify_command("rm -rf /tmp/x"),
            CommandIntent::Destructive
        );
        assert_eq!(
            classify_command("shred /dev/sda"),
            CommandIntent::Destructive
        );
    }

    #[test]
    fn classifies_network_commands() {
        assert_eq!(
            classify_command("curl https://example.com"),
            CommandIntent::Network
        );
        assert_eq!(classify_command("wget file.zip"), CommandIntent::Network);
    }

    #[test]
    fn classifies_sed_inplace_as_write() {
        assert_eq!(
            classify_command("sed -i 's/old/new/' file.txt"),
            CommandIntent::Write
        );
    }

    #[test]
    fn classifies_sed_stdout_as_read_only() {
        assert_eq!(
            classify_command("sed 's/old/new/' file.txt"),
            CommandIntent::ReadOnly
        );
    }

    #[test]
    fn classifies_git_status_as_read_only() {
        assert_eq!(classify_command("git status"), CommandIntent::ReadOnly);
        assert_eq!(
            classify_command("git log --oneline"),
            CommandIntent::ReadOnly
        );
    }

    #[test]
    fn classifies_git_push_as_write() {
        assert_eq!(
            classify_command("git push origin main"),
            CommandIntent::Write
        );
    }

    // --- validate_command (full pipeline) ---

    #[test]
    fn pipeline_blocks_write_in_read_only() {
        let workspace = PathBuf::from("/workspace");
        assert!(matches!(
            validate_command("rm -rf /tmp/x", PermissionMode::ReadOnly, &workspace),
            ValidationResult::Block { .. }
        ));
    }

    #[test]
    fn pipeline_warns_destructive_in_write_mode() {
        let workspace = PathBuf::from("/workspace");
        assert!(matches!(
            validate_command("rm -rf /", PermissionMode::WorkspaceWrite, &workspace),
            ValidationResult::Warn { .. }
        ));
    }

    #[test]
    fn pipeline_allows_safe_read_in_read_only() {
        let workspace = PathBuf::from("/workspace");
        assert_eq!(
            validate_command("ls -la", PermissionMode::ReadOnly, &workspace),
            ValidationResult::Allow
        );
    }

    // --- extract_first_command ---

    #[test]
    fn extracts_command_from_env_prefix() {
        assert_eq!(extract_first_command("FOO=bar ls -la"), "ls");
        assert_eq!(extract_first_command("A=1 B=2 echo hello"), "echo");
    }

    #[test]
    fn extracts_plain_command() {
        assert_eq!(extract_first_command("grep -r pattern ."), "grep");
    }

    // --- split_command_chain ---

    #[test]
    fn splits_pipeline_and_chains() {
        assert_eq!(
            split_command_chain("cat foo | grep bar"),
            vec!["cat foo", "grep bar"]
        );
        assert_eq!(
            split_command_chain("a ; b && c || d & e"),
            vec!["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn split_respects_quoting() {
        // `;` inside quotes must not split.
        assert_eq!(
            split_command_chain("echo 'a;b' ; rm -rf /tmp/x"),
            vec!["echo 'a;b'", "rm -rf /tmp/x"]
        );
        assert_eq!(
            split_command_chain("echo \"a|b\" | wc"),
            vec!["echo \"a|b\"", "wc"]
        );
    }

    #[test]
    fn split_respects_subshells_and_backticks() {
        assert_eq!(
            split_command_chain("echo $(date ; whoami) && ls"),
            vec!["echo $(date ; whoami)", "ls"]
        );
        assert_eq!(
            split_command_chain("echo `date ; whoami` && ls"),
            vec!["echo `date ; whoami`", "ls"]
        );
    }

    #[test]
    fn split_ignores_redirection_ampersands() {
        assert_eq!(
            split_command_chain("cmd 2>&1 | grep foo"),
            vec!["cmd 2>&1", "grep foo"]
        );
        assert_eq!(
            split_command_chain("cmd &> log && ls"),
            vec!["cmd &> log", "ls"]
        );
    }

    #[test]
    fn read_only_rejects_trailing_write_segment() {
        assert!(matches!(
            validate_read_only("cat foo ; rm -rf /tmp/x", PermissionMode::ReadOnly),
            ValidationResult::Block { .. }
        ));
        assert!(matches!(
            validate_read_only("ls | tee out.log", PermissionMode::ReadOnly),
            ValidationResult::Block { .. }
        ));
    }

    #[test]
    fn destructive_catches_chained_rm() {
        assert!(matches!(
            check_destructive("echo start ; rm -rf /tmp/x"),
            ValidationResult::Warn { .. }
        ));
    }

    #[test]
    fn workspace_write_catches_chained_system_write() {
        assert!(matches!(
            validate_mode(
                "echo hi ; cp x /etc/config",
                PermissionMode::WorkspaceWrite
            ),
            ValidationResult::Warn { .. }
        ));
    }

    #[test]
    fn sed_inplace_detection_variants() {
        assert!(segment_uses_sed_inplace("sed -i s/a/b/ f"));
        assert!(segment_uses_sed_inplace("sed -i.bak s/a/b/ f"));
        assert!(segment_uses_sed_inplace("sed --in-place s/a/b/ f"));
        assert!(segment_uses_sed_inplace("sed --in-place=.bak s/a/b/ f"));
        assert!(segment_uses_sed_inplace("sed -Ei s/a/b/ f"));
        assert!(!segment_uses_sed_inplace("sed s/a/b/ f"));
        assert!(!segment_uses_sed_inplace("sed -n 5p f"));
    }

    #[test]
    fn sed_inplace_detected_in_chain() {
        assert!(matches!(
            validate_sed("cat x ; sed -i s/a/b/ f", PermissionMode::ReadOnly),
            ValidationResult::Block { .. }
        ));
    }
}
