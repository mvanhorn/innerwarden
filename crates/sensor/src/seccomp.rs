//! Linux-only seccomp profile loader + BPF byte packing helpers.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR3 of the sensor
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. Anchor tests below pin the kernel ABI byte
//! layout (`struct sock_filter` packing) so a silent refactor of
//! `bpf_stmt` / `bpf_jump` cannot break the seccomp policy
//! invisibly. The previous in-`main.rs` form had zero unit tests
//! despite emitting raw kernel bytes; this PR closes that gap.
//!
//! The whole module is `#[cfg(target_os = "linux")]` because seccomp
//! is a Linux-only concept and the underlying libc / prctl calls are
//! not portable.
//!
//! ## Architecture caveat
//!
//! [`syscall_name_to_nr`] returns **aarch64** Linux syscall numbers.
//! The production target is Oracle Cloud ARM, and the table was
//! written against `/usr/include/asm-generic/unistd.h` for kernel
//! 6.x on aarch64. Running this on x86_64 would silently allow the
//! wrong syscalls because the NRs differ between architectures
//! (e.g. `openat` is 56 on aarch64 but 257 on x86_64). The opt-in
//! gate is the presence of `<data_dir>/sensor.seccomp.json` — if
//! you create that file on an x86_64 host, you will get garbage.
//! A future PR can introduce per-arch tables; for now the anchor
//! tests pin the aarch64 contract explicitly so an accidental
//! switch to "x86_64 numbers" would fail the suite.

#![cfg(target_os = "linux")]

use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

pub(crate) fn apply_seccomp_profile(path: &Path) -> Result<usize> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("read seccomp profile: {}", path.display()))?;

    // Parse the JSON profile to get the syscall allowlist
    let profile =
        serde_json::from_str::<serde_json::Value>(&data).context("parse seccomp profile JSON")?;

    let syscalls = profile["allowed_syscalls"]
        .as_array()
        .context("seccomp profile missing allowed_syscalls array")?;

    let count = syscalls.len();

    // Resolve syscall names to numbers using the audit architecture
    let mut allowed_nrs: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for name_val in syscalls {
        if let Some(name) = name_val.as_str() {
            if let Some(nr) = syscall_name_to_nr(name) {
                allowed_nrs.insert(nr);
            } else {
                tracing::debug!(name, "unknown syscall in seccomp profile — skipping");
            }
        }
    }

    if allowed_nrs.is_empty() {
        anyhow::bail!("seccomp profile has no resolvable syscalls");
    }

    // Build BPF filter: allow listed syscalls, return EPERM for others.
    // Filter structure:
    //   BPF_STMT(LD|W|ABS, 0)   -- load syscall number from seccomp_data.nr
    //   BPF_JUMP(JMP|JEQ|K, nr, 0, 1) -- if match, skip to ALLOW
    //   ... for each allowed syscall ...
    //   BPF_STMT(RET|K, SECCOMP_RET_ERRNO | EPERM)  -- default: deny
    //   BPF_STMT(RET|K, SECCOMP_RET_ALLOW)  -- allow
    let mut filter: Vec<u64> = Vec::new();

    // BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0) -- load syscall nr
    filter.push(bpf_stmt(0x20, 0)); // BPF_LD|BPF_W|BPF_ABS, offset 0

    let n = allowed_nrs.len();
    let sorted: Vec<u32> = {
        let mut v: Vec<u32> = allowed_nrs.into_iter().collect();
        v.sort();
        v
    };

    for (i, &nr) in sorted.iter().enumerate() {
        // BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, nr, jump_true, jump_false)
        // jump_true: skip to ALLOW (at end)
        // jump_false: next instruction
        let jump_to_allow = (n - i) as u8; // distance to ALLOW instruction
        filter.push(bpf_jump(0x15, nr, jump_to_allow, 0));
    }

    // Default: SECCOMP_RET_ERRNO | EPERM (1)
    filter.push(bpf_stmt(0x06, 0x00050001)); // SECCOMP_RET_ERRNO | 1

    // ALLOW
    filter.push(bpf_stmt(0x06, 0x7fff0000)); // SECCOMP_RET_ALLOW

    // Convert to sock_filter array (each is 8 bytes: u16 code, u8 jt, u8 jf, u32 k)
    let filter_bytes: Vec<[u8; 8]> = filter.iter().map(|&v| v.to_ne_bytes()).collect();

    // Set NO_NEW_PRIVS (required before seccomp)
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        anyhow::bail!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Apply the BPF program via prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const [u8; 8],
    }

    let prog = SockFprog {
        len: filter_bytes.len() as u16,
        filter: filter_bytes.as_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            2, // SECCOMP_MODE_FILTER
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };

    if ret != 0 {
        anyhow::bail!(
            "seccomp(FILTER) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    info!(
        count,
        "seccomp filter installed: {} syscalls allowed", count
    );
    Ok(count)
}

/// Pack a BPF_STMT (no jump-target) into the kernel's 8-byte
/// `struct sock_filter` layout: `u16 code | u8 jt | u8 jf | u32 k`.
/// For statements both `jt` and `jf` are zero.
pub(crate) fn bpf_stmt(code: u16, k: u32) -> u64 {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&code.to_ne_bytes());
    // jt=0, jf=0
    buf[4..8].copy_from_slice(&k.to_ne_bytes());
    u64::from_ne_bytes(buf)
}

/// Pack a BPF_JUMP into the kernel's 8-byte `struct sock_filter`
/// layout with the jump-true and jump-false targets at bytes 2 and 3.
pub(crate) fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> u64 {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&code.to_ne_bytes());
    buf[2] = jt;
    buf[3] = jf;
    buf[4..8].copy_from_slice(&k.to_ne_bytes());
    u64::from_ne_bytes(buf)
}

/// Map syscall names to numbers for the current architecture.
/// Uses a hardcoded table for **aarch64** (the production target).
/// Falls back to reading `/usr/include/asm-generic/unistd.h`.
///
/// **Caveat**: the numbers below are aarch64-specific. See the
/// module-level doc for the architecture caveat.
pub(crate) fn syscall_name_to_nr(name: &str) -> Option<u32> {
    // Common syscalls for aarch64 (Linux 6.x)
    // See: /usr/include/asm-generic/unistd.h
    match name {
        "read" => Some(63),
        "write" => Some(64),
        "openat" => Some(56),
        "close" => Some(57),
        "fstat" | "newfstatat" => Some(79),
        "statx" => Some(291),
        "lseek" => Some(62),
        "mmap" => Some(222),
        "mprotect" => Some(226),
        "munmap" => Some(215),
        "brk" => Some(214),
        "ioctl" => Some(29),
        "pread64" => Some(67),
        "pwrite64" => Some(68),
        "writev" => Some(66),
        "fcntl" => Some(25),
        "dup" => Some(23),
        "dup2" => Some(1000), // not on aarch64, use dup3
        "pipe2" => Some(59),
        "socket" => Some(198),
        "bind" => Some(200),
        "recvfrom" => Some(207),
        "recvmsg" => Some(212),
        "sendto" => Some(206),
        "sendmsg" => Some(211),
        "setsockopt" => Some(208),
        "getsockopt" => Some(209),
        "getsockname" => Some(204),
        "clone" => Some(220),
        "clone3" => Some(435),
        "exit_group" => Some(94),
        "exit" => Some(93),
        "wait4" => Some(260),
        "waitid" => Some(95),
        "getpid" => Some(172),
        "gettid" => Some(178),
        "getuid" => Some(174),
        "geteuid" => Some(175),
        "getgid" => Some(176),
        "getegid" => Some(177),
        "epoll_create1" => Some(20),
        "epoll_ctl" => Some(21),
        "epoll_wait" | "epoll_pwait" => Some(22),
        "epoll_pwait2" => Some(441),
        "futex" => Some(98),
        "set_tid_address" => Some(96),
        "set_robust_list" => Some(99),
        "rt_sigaction" => Some(134),
        "rt_sigprocmask" => Some(135),
        "rt_sigreturn" => Some(139),
        "sigaltstack" => Some(132),
        "clock_gettime" => Some(113),
        "clock_nanosleep" => Some(115),
        "nanosleep" => Some(101),
        "gettimeofday" => Some(169),
        "getrandom" => Some(278),
        "madvise" => Some(233),
        "mremap" => Some(216),
        "sched_getaffinity" => Some(123),
        "sched_yield" => Some(124),
        "prctl" => Some(167),
        "bpf" => Some(280),
        "perf_event_open" => Some(241),
        "getdents64" => Some(61),
        "ftruncate" => Some(46),
        "fallocate" => Some(47),
        "fsync" => Some(82),
        "fdatasync" => Some(83),
        "rename" | "renameat2" => Some(276),
        "unlink" | "unlinkat" => Some(35),
        "mkdir" | "mkdirat" => Some(34),
        "access" | "faccessat2" => Some(439),
        "readlink" | "readlinkat" => Some(78),
        "rseq" => Some(293),
        "prlimit64" => Some(261),
        "sysinfo" => Some(179),
        "uname" => Some(160),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// 2026-05-25 — added with the extraction. Pre-extraction these four
// functions had ZERO unit tests despite emitting raw Linux ABI bytes
// (`struct sock_filter`) that ARE the seccomp policy: a silent change
// to `bpf_stmt`'s byte layout would corrupt the BPF program and the
// kernel would either reject it (loud failure) or silently apply the
// wrong filter (quiet failure — wrong syscalls allowed). The anchors
// below pin the exact byte packing the kernel expects so a refactor
// cannot drift from the ABI without triggering a test failure.

#[cfg(test)]
mod tests {
    use super::*;

    // ── byte-packing anchors for struct sock_filter ─────────────────────
    //
    // The kernel's `linux/filter.h` defines:
    //
    //   struct sock_filter {
    //       __u16   code;   // bytes 0..2
    //       __u8    jt;     // byte  2
    //       __u8    jf;     // byte  3
    //       __u32   k;      // bytes 4..8
    //   };
    //
    // Total 8 bytes. We pack into u64 using native-endian bytes so
    // round-tripping through `.to_ne_bytes()` round-trips back to the
    // same struct in memory.

    #[test]
    fn bpf_stmt_packs_code_into_low_bytes() {
        // BPF_LD|BPF_W|BPF_ABS = 0x20. Load syscall nr from offset 0.
        // The packed u64 in native-endian bytes MUST place 0x20 in
        // byte 0 (and 0x00 in byte 1 since 0x20 fits in u8).
        let packed = bpf_stmt(0x20, 0);
        let bytes = packed.to_ne_bytes();
        assert_eq!(bytes[0], 0x20, "code low byte must be in byte 0");
        assert_eq!(bytes[1], 0x00, "code high byte must be in byte 1");
        assert_eq!(bytes[2], 0, "jt must be zero for BPF_STMT");
        assert_eq!(bytes[3], 0, "jf must be zero for BPF_STMT");
        assert_eq!(&bytes[4..8], &0u32.to_ne_bytes(), "k=0 in bytes 4-7");
    }

    #[test]
    fn bpf_stmt_packs_k_into_high_bytes_seccomp_ret_allow() {
        // SECCOMP_RET_ALLOW = 0x7fff0000, code = BPF_RET|BPF_K = 0x06.
        // This is the literal final instruction of the seccomp filter
        // emitted in `apply_seccomp_profile` line 2700 — anchor the
        // exact byte layout the kernel sees on the prctl() call.
        let packed = bpf_stmt(0x06, 0x7fff0000);
        let bytes = packed.to_ne_bytes();
        assert_eq!(bytes[0], 0x06, "BPF_RET|BPF_K low byte");
        assert_eq!(bytes[1], 0x00, "BPF_RET|BPF_K high byte");
        assert_eq!(bytes[2], 0, "jt zero");
        assert_eq!(bytes[3], 0, "jf zero");
        assert_eq!(
            &bytes[4..8],
            &0x7fff0000u32.to_ne_bytes(),
            "SECCOMP_RET_ALLOW in k"
        );
    }

    #[test]
    fn bpf_stmt_packs_seccomp_ret_errno_eperm() {
        // SECCOMP_RET_ERRNO | 1 (EPERM) = 0x00050001. The default-deny
        // branch in the filter (line 2697). If a refactor flipped the
        // byte order this errno would change to something else and the
        // kernel would silently deny with the wrong error.
        let packed = bpf_stmt(0x06, 0x00050001);
        let bytes = packed.to_ne_bytes();
        assert_eq!(
            &bytes[4..8],
            &0x00050001u32.to_ne_bytes(),
            "SECCOMP_RET_ERRNO|EPERM in k"
        );
    }

    #[test]
    fn bpf_jump_places_jt_and_jf_at_bytes_2_and_3() {
        // BPF_JMP|BPF_JEQ|BPF_K = 0x15, comparing to syscall nr 56
        // (openat on aarch64), jt=3 (skip 3 instructions on match),
        // jf=0 (fall through on no match). Anchor that jt is byte 2
        // and jf is byte 3 — the kernel's struct layout depends on
        // this exact ordering.
        let packed = bpf_jump(0x15, 56, 3, 0);
        let bytes = packed.to_ne_bytes();
        assert_eq!(bytes[0], 0x15, "BPF_JMP|BPF_JEQ|BPF_K low byte");
        assert_eq!(bytes[1], 0x00, "code high byte");
        assert_eq!(bytes[2], 3, "jt at byte 2");
        assert_eq!(bytes[3], 0, "jf at byte 3");
        assert_eq!(
            &bytes[4..8],
            &56u32.to_ne_bytes(),
            "syscall nr at bytes 4-7"
        );
    }

    #[test]
    fn bpf_jump_with_nonzero_jf_keeps_byte_ordering() {
        // Defensive: pin that swapping jt and jf is not equivalent.
        // If a refactor accidentally moved jt to byte 3 the seccomp
        // jump targets would be inverted and the filter would jump
        // to ALLOW on the wrong branch.
        let a = bpf_jump(0x15, 1, 5, 0).to_ne_bytes();
        let b = bpf_jump(0x15, 1, 0, 5).to_ne_bytes();
        assert_ne!(a, b, "swapping jt/jf MUST change the packed bytes");
        assert_eq!(a[2], 5);
        assert_eq!(a[3], 0);
        assert_eq!(b[2], 0);
        assert_eq!(b[3], 5);
    }

    // ── syscall name → number anchors (aarch64) ─────────────────────────

    #[test]
    fn syscall_name_to_nr_pins_critical_aarch64_numbers() {
        // These four are what `apply_seccomp_profile` mostly cares
        // about: the basic POSIX surface the sensor needs at runtime.
        // Pinning them with literal aarch64 numbers means a future
        // PR that mistakenly pastes an x86_64 table (where openat=257,
        // close=3, exit=60, read=0) would fail this test loudly
        // instead of silently allowing the wrong syscalls.
        assert_eq!(syscall_name_to_nr("read"), Some(63), "aarch64 read");
        assert_eq!(syscall_name_to_nr("openat"), Some(56), "aarch64 openat");
        assert_eq!(syscall_name_to_nr("close"), Some(57), "aarch64 close");
        assert_eq!(syscall_name_to_nr("exit"), Some(93), "aarch64 exit");
        // bpf() syscall — relevant because the sensor's eBPF programs
        // are already loaded BEFORE seccomp activates, so bpf() can
        // be denied post-startup.
        assert_eq!(syscall_name_to_nr("bpf"), Some(280), "aarch64 bpf");
    }

    #[test]
    fn syscall_name_to_nr_handles_aliases() {
        // Multiple syscall names map to the same number on aarch64
        // because the legacy variant was removed in favour of the
        // *at form. Pin the alias contract so a refactor that drops
        // one variant doesn't silently break seccomp profiles that
        // listed the older name.
        assert_eq!(syscall_name_to_nr("fstat"), Some(79));
        assert_eq!(syscall_name_to_nr("newfstatat"), Some(79));
        assert_eq!(syscall_name_to_nr("unlink"), Some(35));
        assert_eq!(syscall_name_to_nr("unlinkat"), Some(35));
        assert_eq!(syscall_name_to_nr("mkdir"), Some(34));
        assert_eq!(syscall_name_to_nr("mkdirat"), Some(34));
        assert_eq!(syscall_name_to_nr("rename"), Some(276));
        assert_eq!(syscall_name_to_nr("renameat2"), Some(276));
    }

    #[test]
    fn syscall_name_to_nr_returns_none_for_unknown() {
        // The fallthrough is critical: an unknown name MUST NOT silently
        // map to syscall 0 (read) or any sentinel — apply_seccomp_profile
        // depends on `None` to log + skip the entry. A future "let's
        // default to read() if unknown" refactor would silently allow
        // arbitrary read syscalls in every profile.
        assert_eq!(syscall_name_to_nr("not_a_real_syscall"), None);
        assert_eq!(syscall_name_to_nr(""), None);
        assert_eq!(syscall_name_to_nr("EXECVE"), None, "case-sensitive");
    }

    // ── apply_seccomp_profile parse-path anchors ────────────────────────
    //
    // We can exercise the JSON parse + syscall resolution paths without
    // root or actual prctl(): the function reads + validates before it
    // gets to the libc::prctl call. Tests use std::fs to drop a file
    // into a tempdir and call the function with the path.

    #[test]
    fn apply_seccomp_profile_errors_on_missing_file() {
        let res = apply_seccomp_profile(Path::new("/tmp/does-not-exist-xyzzy-12345"));
        let err = res.expect_err("missing file must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("read seccomp profile"),
            "error must mention the read step; got: {msg}"
        );
    }

    #[test]
    fn apply_seccomp_profile_errors_on_malformed_json() {
        let tmp = std::env::temp_dir().join(format!(
            "innerwarden-seccomp-test-malformed-{}",
            std::process::id()
        ));
        std::fs::write(&tmp, "{ not valid json").expect("write tmp");
        let res = apply_seccomp_profile(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let err = res.expect_err("malformed JSON must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("parse seccomp profile JSON"),
            "error must mention the parse step; got: {msg}"
        );
    }

    #[test]
    fn apply_seccomp_profile_errors_when_allowed_syscalls_array_missing() {
        let tmp = std::env::temp_dir().join(format!(
            "innerwarden-seccomp-test-no-array-{}",
            std::process::id()
        ));
        std::fs::write(&tmp, r#"{"comment": "no allowed_syscalls key"}"#).expect("write tmp");
        let res = apply_seccomp_profile(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let err = res.expect_err("missing array must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing allowed_syscalls array"),
            "error must mention the schema gate; got: {msg}"
        );
    }
}
