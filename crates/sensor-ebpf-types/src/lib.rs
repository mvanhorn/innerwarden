//! Shared types between eBPF kernel programs and the userspace sensor.
//!
//! These structs are sent through eBPF ring buffers from kernel space
//! to userspace. They must be `#[repr(C)]` for cross-boundary compatibility.

#![no_std]

/// Maximum blocked IPs in XDP blocklist map.
pub const XDP_BLOCKLIST_MAX: u32 = 10_000;

/// Maximum command line length captured from execve.
pub const MAX_COMM_LEN: usize = 64;
/// Maximum filename/path length.
pub const MAX_FILENAME_LEN: usize = 256;
/// Maximum number of argv entries captured.
pub const MAX_ARGS: usize = 8;
/// Maximum length of each argv entry.
pub const MAX_ARG_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Capability bits for fine-grained guard mode policy
// ---------------------------------------------------------------------------
//
// Used in CGROUP_CAPABILITIES and COMM_CAPABILITIES BPF maps.
// Each bit grants permission for a specific action when guard mode is on.
// If the bit is NOT set, the action is blocked (when guard mode is enabled).

/// Allow execution from /tmp, /dev/shm, /var/tmp
pub const CAP_EXEC_TMP: u32 = 1 << 0;
/// Allow write to /etc/shadow, /etc/passwd, /etc/gshadow
pub const CAP_WRITE_CREDENTIALS: u32 = 1 << 1;
/// Allow write to ~/.ssh/authorized_keys, ~/.ssh/id_*
pub const CAP_WRITE_SSH: u32 = 1 << 2;
/// Allow write to /etc/sudoers, /etc/sudoers.d/
pub const CAP_WRITE_SUDO: u32 = 1 << 3;
/// Allow write to /etc/cron*, /var/spool/cron/
pub const CAP_WRITE_CRON: u32 = 1 << 4;
/// Allow write to /etc/systemd/system/, /etc/init.d/
pub const CAP_WRITE_PERSISTENCE: u32 = 1 << 5;
/// Allow write to /etc/ld.so.preload, /etc/ld.so.conf*
pub const CAP_WRITE_LDPRELOAD: u32 = 1 << 6;
/// Allow write to /etc/pam.d/
pub const CAP_WRITE_PAM: u32 = 1 << 7;
/// Allow io_uring usage
pub const CAP_IO_URING: u32 = 1 << 8;
/// Allow execution from overlayfs upper layer (container drift)
pub const CAP_OVERLAY_DRIFT: u32 = 1 << 9;

// ---------------------------------------------------------------------------
// Syscall event types
// ---------------------------------------------------------------------------

/// Identifies which syscall triggered the event.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SyscallKind {
    /// Process execution (execve / execveat)
    Execve = 1,
    /// Outbound network connection (connect)
    Connect = 2,
    /// File open (openat)
    FileOpen = 3,
    /// Write to sensitive path
    FileWrite = 4,
    /// Privilege escalation (commit_creds: uid changed to root)
    PrivEsc = 5,
    /// LSM blocked execution (bprm_check_security denied /tmp, /dev/shm)
    LsmBlocked = 6,
    /// Process exit (sched_process_exit)
    ProcessExit = 7,
    /// Process injection (ptrace ATTACH/POKETEXT)
    Ptrace = 8,
    /// Privilege change (setuid/setgid/setresuid/setresgid → root)
    SetUid = 9,
    /// Network bind+listen (reverse shell setup)
    SocketBind = 10,
    /// Filesystem mount (container escape indicator)
    Mount = 11,
    /// Anonymous memory-backed file (fileless malware)
    MemfdCreate = 12,
    /// Kernel module loading (rootkit insertion)
    InitModule = 13,
    /// File descriptor duplication (reverse shell fd redirection)
    Dup = 14,
    /// Socket listen (confirms reverse shell / backdoor setup)
    Listen = 15,
    /// Memory protection change (shellcode - mprotect RWX)
    Mprotect = 16,
    /// Process fork/clone (fork bombs, process tree)
    Clone = 17,
    /// File deletion (evidence destruction, log wipe)
    Unlink = 18,
    /// File rename (binary replacement, config tampering)
    Rename = 19,
    /// Signal send (killing security processes)
    Kill = 20,
    /// Process control (name spoofing, no_new_privs bypass)
    Prctl = 21,
    /// Accept incoming connection
    Accept = 22,
    /// EFI Runtime Services call (EXPERIMENTAL — firmware behavioral baseline)
    EfiCall = 23,
    /// io_uring SQE submission (detect io_uring-based evasion)
    IoUring = 24,
    /// io_uring ring creation (track which processes use io_uring)
    IoUringCreate = 25,
    /// Container drift: binary executed from overlayfs upper layer (not in original image)
    ContainerDrift = 26,

    // ── Phase 2: Firmware hooks ────────────────────────────────────────
    /// MSR write (kprobe on native_write_msr) — detect SMRR/LSTAR tampering
    MsrWrite = 27,
    /// I/O port access request (ioperm syscall) — detect SPI controller probing
    Ioperm = 28,
    /// I/O privilege level elevation (iopl syscall) — detect direct hardware access
    Iopl = 29,
    /// ACPI method evaluation (kprobe on acpi_evaluate_object) — detect ACPI rootkit
    AcpiEval = 30,
    /// BPF program loading (LSM bpf hook) — detect eBPF weaponization (VoidLink)
    BpfLoad = 31,
    /// Kernel function timing probe (kprobe/kretprobe delta for Trace of the Times)
    TimingProbe = 32,

    // ── Phase 3: Red team gap hooks ───────────────────────────────────
    /// File timestamp modification (vfs_utimes kprobe) — detect timestomp (T1070.006)
    Utimensat = 33,
    /// File truncation (do_truncate kprobe) — detect log tampering (T1070.003)
    Truncate = 34,

    // ── Spec 052 Phase 1: minimal LSM hook ─────────────────────────────
    /// Emitted by `innerwarden_lsm_exec_min` on a kernel-side block.
    /// Distinct from `LsmBlocked` (= 6) which the legacy hook uses with
    /// the larger `ExecveEvent` shape — this kind always carries a
    /// fixed-shape `LsmDecisionEvent` (24 bytes).
    LsmDecision = 35,
}

/// Identifies which kernel function a timing probe measured.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimingTarget {
    IterateDir = 1,
    Filldir64 = 2,
    Tcp4SeqShow = 3,
    ProcPidReaddir = 4,
}

/// Event emitted by the eBPF `execve` tracepoint.
///
/// Captures: who executed what, with which arguments, from which parent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    /// Syscall type (always SyscallKind::Execve)
    pub kind: u32,
    /// Process ID of the new process
    pub pid: u32,
    /// Thread group ID
    pub tgid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    /// Process name (comm)
    pub comm: [u8; MAX_COMM_LEN],
    /// Filename being executed
    pub filename: [u8; MAX_FILENAME_LEN],
    /// First N argv entries (null-terminated within each slot)
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGS],
    /// Number of argv entries actually captured
    pub argc: u32,
    /// Timestamp (nanoseconds since boot)
    pub ts_ns: u64,
}

/// Event emitted by the `connect` tracepoint.
///
/// Captures: who connected where (IP + port).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    /// Destination IPv4 address (network byte order)
    pub dst_addr: u32,
    /// Destination port (host byte order)
    pub dst_port: u16,
    /// Address family (AF_INET = 2, AF_INET6 = 10)
    pub family: u16,
    pub ts_ns: u64,
}

/// Event emitted by `openat` tracepoint for sensitive paths.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    pub flags: u32,
    pub ts_ns: u64,
}

/// Event emitted by the `commit_creds` kprobe - privilege escalation detection.
///
/// Fires when a process's UID transitions from non-root to root
/// through a path other than legitimate login (sudo, su, sshd, login).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivEscEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    /// UID before the transition (the current uid at kprobe entry)
    pub old_uid: u32,
    /// UID after the transition (read from new cred struct)
    pub new_uid: u32,
    /// Cgroup ID (container awareness)
    pub cgroup_id: u64,
    /// Process name
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `sched:sched_process_exit` tracepoint.
///
/// Fires when any process exits. Used by the rootkit detector to track
/// process lifecycle - a process seen by execve but never by exit + missing
/// from /proc is a strong rootkit indicator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub exit_code: i32,
    pub ts_ns: u64,
}

/// Reasons a PID gets registered in BLOCKED_PIDS by the agent.
/// Pre-Spec-053 these were intended for `LsmDecisionEvent.reason`. With
/// PR-A (2026-05-22) the `reason` field is now repurposed as `hook_id`
/// (see `LSM_HOOK_*` below) — the kernel hook always knows WHICH hook
/// fired but does NOT know WHY the agent decided to block. The original
/// reason now lives in agent-side logging only.
pub const LSM_REASON_KILL_CHAIN: u32 = 1;
pub const LSM_REASON_MANUAL: u32 = 2;
pub const LSM_REASON_RULE: u32 = 3;

/// Identifies WHICH LSM hook fired a block decision. Encoded in the
/// (otherwise unused) `LsmDecisionEvent.reason` field so the userspace
/// agent can distinguish blocks from different hooks without needing
/// separate SyscallKind variants for each. The constants are stable
/// part of the wire format — never renumber, only append.
pub const LSM_HOOK_BPRM_CHECK_SECURITY: u32 = 1;
pub const LSM_HOOK_CREATE_USER_NS: u32 = 2;
pub const LSM_HOOK_PTRACE_ACCESS_CHECK: u32 = 3;
pub const LSM_HOOK_MMAP_FILE: u32 = 4;
pub const LSM_HOOK_BPF_PROG_LOAD: u32 = 5;

/// Emitted by `innerwarden_lsm_exec_min` when a process is denied at
/// `bprm_check_security`. Allow decisions are NOT emitted (every execve
/// would generate one — high volume; the absence of this event for an
/// observed execve means the LSM hook allowed it). The userspace agent
/// joins this event with the existing `innerwarden_execve` tracepoint
/// stream by PID to recover {comm, filename, uid} context.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LsmDecisionEvent {
    /// Always SyscallKind::LsmDecision (= 35). Distinct from LsmBlocked
    /// (= 6) which the legacy hook uses with the larger ExecveEvent shape.
    pub kind: u32,
    /// Thread PID of the calling task at hook time.
    pub pid: u32,
    /// Thread group ID of the calling task at hook time.
    pub tgid: u32,
    /// PR-A semantic shift: this field now encodes WHICH LSM hook fired
    /// the block (see `LSM_HOOK_*` constants), not the abstract "reason"
    /// it was originally named for. The kernel hook knows which hook IT
    /// is — the kernel doesn't know WHY the agent decided to block.
    /// Kept as `reason` for wire-format stability; userspace dispatch
    /// at `crates/sensor/src/collectors/ebpf_syscall.rs:1870` reads
    /// this field as `hook_id`.
    pub reason: u32,
    /// Timestamp (nanoseconds since boot).
    pub ts_ns: u64,
}

#[cfg(test)]
mod lsm_hook_id_anchors {
    //! Spec 053 / PR-A anchors. These pin the LSM_HOOK_* constants as
    //! part of the wire format so an accidental renumber is caught by
    //! `cargo test` before it ships to prod and confuses dispatch arms.
    //! See `crates/sensor/src/collectors/ebpf_syscall.rs:1870` for the
    //! consumer; the constants are also encoded into LsmDecisionEvent's
    //! `reason` field by the kernel-side hooks in
    //! `crates/sensor-ebpf/src/main.rs`.

    use super::{
        LSM_HOOK_BPF_PROG_LOAD, LSM_HOOK_BPRM_CHECK_SECURITY, LSM_HOOK_CREATE_USER_NS,
        LSM_HOOK_MMAP_FILE, LSM_HOOK_PTRACE_ACCESS_CHECK,
    };

    #[test]
    fn lsm_hook_ids_are_stable_wire_format() {
        // Renumbering these is a wire-format break — kernel-side .o emits
        // these constants; userspace dispatches by them. Add NEW values
        // only by appending. Never reuse a freed slot.
        assert_eq!(LSM_HOOK_BPRM_CHECK_SECURITY, 1);
        assert_eq!(LSM_HOOK_CREATE_USER_NS, 2);
        assert_eq!(LSM_HOOK_PTRACE_ACCESS_CHECK, 3);
        assert_eq!(LSM_HOOK_MMAP_FILE, 4);
        assert_eq!(LSM_HOOK_BPF_PROG_LOAD, 5);
    }

    #[test]
    fn lsm_hook_ids_are_unique() {
        let all = [
            LSM_HOOK_BPRM_CHECK_SECURITY,
            LSM_HOOK_CREATE_USER_NS,
            LSM_HOOK_PTRACE_ACCESS_CHECK,
            LSM_HOOK_MMAP_FILE,
            LSM_HOOK_BPF_PROG_LOAD,
        ];
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            all.len(),
            "LSM_HOOK_* constants must be unique"
        );
    }

    #[test]
    fn lsm_hook_ids_never_reuse_zero() {
        // 0 is reserved as "unknown / sentinel" so dispatch arms can
        // detect uninitialised reads or older sensors that didn't tag.
        let all = [
            LSM_HOOK_BPRM_CHECK_SECURITY,
            LSM_HOOK_CREATE_USER_NS,
            LSM_HOOK_PTRACE_ACCESS_CHECK,
            LSM_HOOK_MMAP_FILE,
            LSM_HOOK_BPF_PROG_LOAD,
        ];
        for h in all {
            assert_ne!(h, 0, "LSM_HOOK_* may never use 0 (reserved sentinel)");
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 2 event types - kernel-level detection expansion
// ---------------------------------------------------------------------------

/// Event emitted by `ptrace` tracepoint - process injection detection.
///
/// Only fires for dangerous operations: PTRACE_ATTACH (16), PTRACE_SEIZE (0x4206),
/// PTRACE_POKETEXT (4), PTRACE_POKEDATA (5). Ignores PTRACE_TRACEME (benign).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub request: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by setuid/setgid/setresuid/setresgid handlers.
///
/// Only fires when a non-root process sets uid to 0 (root).
/// Legitimate escalation (sudo, su) is filtered in userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetUidEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub target_uid: u32,
    pub syscall_nr: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `bind` tracepoint - reverse shell setup detection.
///
/// Captures socket bind operations. A process binding to 0.0.0.0 on a port
/// and then listening is a strong reverse shell indicator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketBindEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub protocol: u16,
    pub family: u16,
    pub port: u16,
    pub _pad: u16,
    pub addr: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `mount` tracepoint - container escape detection.
///
/// Inside a container, mount syscalls are almost always malicious.
/// Captures source, target, and filesystem type.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub source: [u8; MAX_FILENAME_LEN],
    pub target: [u8; MAX_FILENAME_LEN],
    pub fs_type: [u8; 32],
    pub ts_ns: u64,
}

/// Event emitted by `memfd_create` tracepoint - fileless malware detection.
///
/// memfd_create creates an anonymous memory-backed file. Legitimate uses are
/// rare (mainly JIT compilers). Malware uses it to avoid touching disk.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdCreateEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub name: [u8; MAX_FILENAME_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `init_module`/`finit_module` tracepoint - rootkit loading.
///
/// Kernel module loading is extremely rare in normal operation.
/// Always security-relevant.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleLoadEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub syscall_nr: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

// ---------------------------------------------------------------------------
// Phase 3 event types - complete syscall coverage
// ---------------------------------------------------------------------------

/// Event emitted by `dup2`/`dup3` - fd redirection for reverse shells.
/// Reverse shells redirect stdin/stdout/stderr to a socket fd.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DupEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub oldfd: u32,
    pub newfd: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `listen` - confirms a bind as a server socket.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub backlog: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `mprotect` - making memory executable (shellcode).
/// Only fires when adding PROT_EXEC to a page (RWX transition).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MprotectEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub prot: u32,
    pub addr: u64,
    pub len: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `clone`/`clone3` - process creation.
/// Filtered: only emits for suspicious flags or high fork rates.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloneEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub clone_flags: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `unlink`/`unlinkat` - file deletion.
/// Filtered: only sensitive paths (/var/log, /etc, evidence files).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `rename`/`renameat` - file rename/replacement.
/// Filtered: only sensitive paths.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub oldname: [u8; MAX_FILENAME_LEN],
    pub newname: [u8; MAX_FILENAME_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `kill`/`tkill` - sending signals to processes.
/// Filtered: only SIGKILL/SIGTERM/SIGSTOP to security-relevant processes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KillEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub signal: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `prctl` - process control operations.
/// Filtered: only PR_SET_NAME (name spoofing) and PR_SET_NO_NEW_PRIVS.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrctlEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub option: u32,
    pub arg2: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `accept`/`accept4` - incoming connection accepted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcceptEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// EXPERIMENTAL: Event emitted by the EFI Runtime Services kprobe.
///
/// Monitors calls to UEFI runtime services (GetVariable, SetVariable, etc.)
/// from the OS. Establishes a behavioral baseline of normal firmware activity.
/// Deviations may indicate firmware-level compromise (UEFI implants, bootkits).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiCallEvent {
    pub kind: u32,
    /// PID of the calling process
    pub pid: u32,
    /// UID of the calling process
    pub uid: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// Cgroup ID
    pub cgroup_id: u64,
    /// Process name
    pub comm: [u8; MAX_COMM_LEN],
    /// Timestamp (nanoseconds since boot)
    pub ts_ns: u64,
}

// ---------------------------------------------------------------------------
// io_uring monitoring events
// ---------------------------------------------------------------------------

/// Event emitted by the `io_uring:io_uring_submit_sqe` tracepoint.
///
/// Captures io_uring SQE submissions. Security-relevant opcodes:
///   OPENAT(18), CONNECT(16), ACCEPT(13), SEND(26), RECV(27),
///   SENDMSG(9), RECVMSG(10), SOCKET(45), URING_CMD(46).
/// Most legitimate workloads don't use io_uring — its presence
/// in non-database/non-webserver processes is suspicious.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// io_uring opcode (IORING_OP_*)
    pub opcode: u8,
    /// SQE flags
    pub sqe_flags: u8,
    pub _pad: u16,
    /// File descriptor (for OPENAT, CONNECT, etc.)
    pub fd: i32,
    /// Cgroup ID (container awareness)
    pub cgroup_id: u64,
    /// Process name
    pub comm: [u8; MAX_COMM_LEN],
    /// Timestamp (nanoseconds since boot)
    pub ts_ns: u64,
}

/// Event emitted by `io_uring:io_uring_create` tracepoint.
///
/// Fires when a process creates an io_uring instance. The mere act
/// of creating an io_uring ring is a signal worth tracking.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringCreateEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// Ring file descriptor
    pub ring_fd: i32,
    /// Number of submission queue entries
    pub sq_entries: u32,
    /// Number of completion queue entries
    pub cq_entries: u32,
    /// io_uring_setup flags
    pub flags: u32,
    /// Cgroup ID
    pub cgroup_id: u64,
    /// Process name
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

// ---------------------------------------------------------------------------
// Phase 2: Firmware event types
// ---------------------------------------------------------------------------

/// MSR write event — emitted when a process writes to a sensitive MSR.
/// Sensitive MSRs: LSTAR (syscall entry), STAR, CSTAR, APIC_BASE, SMRR.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsrWriteEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    /// MSR address being written (e.g., 0xc0000082 = LSTAR).
    pub msr_address: u64,
    /// Value written (lower 32 bits).
    pub msr_value_lo: u32,
    /// Value written (upper 32 bits).
    pub msr_value_hi: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// I/O port access event — emitted on ioperm() syscall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IopermEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    /// Starting I/O port number.
    pub port_from: u64,
    /// Number of ports requested.
    pub port_num: u64,
    /// 1 = enable access, 0 = disable.
    pub turn_on: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// I/O privilege level event — emitted on iopl() syscall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoplEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    /// Requested IOPL level (0-3).
    pub level: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// ACPI method evaluation event — emitted on acpi_evaluate_object().
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcpiEvalEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    /// ACPI method pathname (e.g., "\\_SB.PCI0._STA").
    pub pathname: [u8; MAX_COMM_LEN],
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// BPF program load event — emitted on bpf() syscall (LSM hook).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfLoadEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// BPF command (BPF_PROG_LOAD=5, BPF_MAP_CREATE=0, etc.).
    pub bpf_cmd: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Kernel function timing measurement (kprobe entry → kretprobe return delta).
/// Used by Trace of the Times rootkit detection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TimingProbeEvent {
    pub kind: u32,
    pub pid: u32,
    /// Which kernel function was timed (TimingTarget enum).
    pub target: u32,
    pub _pad: u32,
    /// Execution time in nanoseconds (return_ts - entry_ts).
    pub delta_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

// ── Phase 3: Red team gap events ─────────────────────────────────────

/// File timestamp modification (timestomp detection).
/// Emitted by kprobe on vfs_utimes / utimensat.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UtimensatEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub ts_ns: u64,
}

/// File truncation (log tampering detection).
/// Emitted by kprobe on do_truncate / sys_truncate.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TruncateEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub new_size: u64,
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub ts_ns: u64,
}

// ---------------------------------------------------------------------------
// Helpers (usable in both kernel and userspace)
// ---------------------------------------------------------------------------

/// Extract a null-terminated string from a fixed-size byte array.
/// Returns the bytes up to (not including) the first null byte.
pub fn bytes_to_str(buf: &[u8]) -> &[u8] {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_str_returns_prefix_before_first_nul() {
        assert_eq!(bytes_to_str(b"bash\0ignored"), b"bash");
        assert_eq!(bytes_to_str(b"/usr/bin/python\0--flag"), b"/usr/bin/python");
    }

    #[test]
    fn bytes_to_str_keeps_full_slice_when_no_nul_exists() {
        let filename = b"/tmp/payload.sh";
        assert_eq!(bytes_to_str(filename), filename);
    }

    #[test]
    fn bytes_to_str_handles_leading_nul_and_empty_input() {
        assert_eq!(bytes_to_str(b"\0hidden"), b"");
        assert_eq!(bytes_to_str(b""), b"");
    }

    #[test]
    fn constants_match_kernel_buffer_contract() {
        assert_eq!(MAX_COMM_LEN, 64);
        assert_eq!(MAX_FILENAME_LEN, 256);
        assert_eq!(MAX_ARGS, 8);
        assert_eq!(MAX_ARG_LEN, 128);
        assert_eq!(XDP_BLOCKLIST_MAX, 10_000);
    }

    #[test]
    fn syscall_kind_discriminants_are_stable_for_ebpf_abi() {
        assert_eq!(SyscallKind::Execve as u32, 1);
        assert_eq!(SyscallKind::Connect as u32, 2);
        assert_eq!(SyscallKind::FileOpen as u32, 3);
        assert_eq!(SyscallKind::FileWrite as u32, 4);
        assert_eq!(SyscallKind::Truncate as u32, 34);
    }

    #[test]
    fn timing_target_discriminants_are_stable_for_ebpf_abi() {
        assert_eq!(TimingTarget::IterateDir as u32, 1);
        assert_eq!(TimingTarget::Filldir64 as u32, 2);
        assert_eq!(TimingTarget::Tcp4SeqShow as u32, 3);
        assert_eq!(TimingTarget::ProcPidReaddir as u32, 4);
    }
}
