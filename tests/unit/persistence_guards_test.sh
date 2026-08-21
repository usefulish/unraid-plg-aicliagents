#!/usr/bin/env bash
# persistence_guards_test.sh — regression tests for task #184 fixes.
#
# Tests guard_path (fault C-1) and home_mount_in_use (fault D) using the
# established injection hooks (AICLI_PROC_MOUNTS, PATH stubs) so no root,
# real mounts, or running plugin is required.
#
# Usage:  bash tests/unit/persistence_guards_test.sh
# Exit:   0 = all pass, 1 = at least one failure
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMON_SH="$REPO_ROOT/src/scripts/storage/common.sh"

# --- Minimal stubs for common.sh dependencies ---
DEBUG_LOG=/dev/null
get_ts() { date +%H:%M:%S 2>/dev/null || echo "00:00:00"; }
export DEBUG_LOG
export -f get_ts

# Source guard_path + _overlay_present_at + _proc_mounts_path + home_mount_in_use +
# _holder_is_infra_daemon from the patched file.
eval "$(sed -n '/^guard_path()/,/^}/p'                "$COMMON_SH")"
eval "$(sed -n '/^_proc_mounts_path()/,/^}/p'         "$COMMON_SH")"
eval "$(sed -n '/^_overlay_present_at()/,/^}/p'       "$COMMON_SH")"
eval "$(sed -n '/^_holder_is_infra_daemon()/,/^}/p'   "$COMMON_SH")"
eval "$(sed -n '/^home_mount_in_use()/,/^}/p'         "$COMMON_SH")"

PASS=0 FAIL=0 TESTS=0

assert_rc() {
    local expect_rc="$1" label="$2"
    shift 2
    ((TESTS++))
    local actual_rc=0
    "$@" 2>/dev/null || actual_rc=$?
    if [ "$actual_rc" -eq "$expect_rc" ]; then
        printf "  PASS  %s\n" "$label"
        ((PASS++))
    else
        printf "  FAIL  %s  (expected rc=%d, got rc=%d)\n" "$label" "$expect_rc" "$actual_rc"
        ((FAIL++))
    fi
}

# ============================================================
echo "=== C-1: guard_path shape table ==="
# ============================================================

# Bare pool roots — THE REGRESSION (must accept)
assert_rc 0 "/mnt/storage (bare pool root)"                guard_path "/mnt/storage" "PERSIST_PATH"
assert_rc 0 "/mnt/cache (bare pool root)"                  guard_path "/mnt/cache" "PERSIST_PATH"
assert_rc 0 "/mnt/cache_nvme (bare pool root)"             guard_path "/mnt/cache_nvme" "PERSIST_PATH"
assert_rc 0 "/mnt/zfs_pool (bare pool root)"               guard_path "/mnt/zfs_pool" "PERSIST_PATH"
assert_rc 0 "/mnt/user (picker rank 6)"                    guard_path "/mnt/user" "PERSIST_PATH"

# Pool subdirectories — must not regress
assert_rc 0 "/mnt/storage/appdata/aicliagents (pool sub)"  guard_path "/mnt/storage/appdata/aicliagents" "PERSIST_PATH"
assert_rc 0 "/mnt/cache/appdata (pool sub)"                guard_path "/mnt/cache/appdata" "PERSIST_PATH"

# Array disks
assert_rc 0 "/mnt/disk1 (array disk)"                     guard_path "/mnt/disk1" "PERSIST_PATH"
assert_rc 0 "/mnt/disk29 (array disk)"                    guard_path "/mnt/disk29" "PERSIST_PATH"

# UD sub-directories (accepted)
assert_rc 0 "/mnt/disks/LABEL/sub (UD sub)"               guard_path "/mnt/disks/LABEL/sub" "PERSIST_PATH"
assert_rc 0 "/mnt/addons/DEV/data (UD addon sub)"         guard_path "/mnt/addons/DEV/data" "PERSIST_PATH"

# Denied roots
assert_rc 1 "/mnt/disks (bare UD root)"                   guard_path "/mnt/disks" "PERSIST_PATH"
assert_rc 1 "/mnt/disks/LABEL (UD mount point)"           guard_path "/mnt/disks/LABEL" "PERSIST_PATH"
assert_rc 1 "/mnt/addons (bare UD root)"                  guard_path "/mnt/addons" "PERSIST_PATH"
assert_rc 1 "/mnt/addons/DEV (UD device mount)"           guard_path "/mnt/addons/DEV" "PERSIST_PATH"
assert_rc 1 "/mnt/remotes (network root)"                 guard_path "/mnt/remotes" "PERSIST_PATH"
assert_rc 1 "/mnt/remotes/nas (network share)"            guard_path "/mnt/remotes/nas" "PERSIST_PATH"
assert_rc 1 "/mnt/rootshare (root export)"                guard_path "/mnt/rootshare" "PERSIST_PATH"
assert_rc 1 "/mnt/rootshare/sub (root export sub)"        guard_path "/mnt/rootshare/sub" "PERSIST_PATH"

# System roots
assert_rc 1 "/ (root)"                                    guard_path "/" "PERSIST_PATH"
assert_rc 1 "/mnt (near-root)"                            guard_path "/mnt" "PERSIST_PATH"
assert_rc 1 "/tmp (near-root)"                            guard_path "/tmp" "PERSIST_PATH"
assert_rc 1 "/usr (near-root)"                            guard_path "/usr" "PERSIST_PATH"
assert_rc 1 "empty string"                                guard_path "" "PERSIST_PATH"

# Plugin-internal prefixes
assert_rc 0 "/tmp/unraid-aicliagents (plugin tmp)"        guard_path "/tmp/unraid-aicliagents" "PERSIST_PATH"
assert_rc 0 "flash persistence path"                      guard_path "/boot/config/plugins/unraid-aicliagents/persistence" "PERSIST_PATH"

echo ""
echo "=== C-1b: path normalization bypass (review fix 33ec1b96) ==="

# Trailing slashes normalized to accepted form
assert_rc 0 "/mnt/storage/ (trailing slash)"              guard_path "/mnt/storage/" "PERSIST_PATH"
assert_rc 0 "/mnt/storage// (double trailing)"            guard_path "/mnt/storage//" "PERSIST_PATH"
assert_rc 0 "/mnt/storage/// (arbitrary trailing)"         guard_path "/mnt/storage///" "PERSIST_PATH"

# Traversal/alias attacks — must reject
assert_rc 1 "/mnt/storage/../remotes (dot-dot)"           guard_path "/mnt/storage/../remotes" "PERSIST_PATH"
assert_rc 1 "/mnt/storage/.. (trailing dot-dot)"          guard_path "/mnt/storage/.." "PERSIST_PATH"
assert_rc 1 "/mnt/storage/./test (dot segment)"           guard_path "/mnt/storage/./test" "PERSIST_PATH"
assert_rc 1 "/mnt/storage/. (trailing dot)"                guard_path "/mnt/storage/." "PERSIST_PATH"
assert_rc 1 "/mnt//storage (repeated sep)"                guard_path "/mnt//storage" "PERSIST_PATH"
assert_rc 1 "/mnt/disks/../storage (deny-zone escape)"    guard_path "/mnt/disks/../storage" "PERSIST_PATH"
assert_rc 1 "/mnt/remotes/../../mnt/storage (deep)"       guard_path "/mnt/remotes/../../mnt/storage" "PERSIST_PATH"

# ============================================================
echo ""
echo "=== D: home_mount_in_use mount scoping ==="
# ============================================================

# We need a tmpdir for proc/mounts fixtures and fuser stubs.
TDIR="$(mktemp -d)"
trap 'rm -rf "$TDIR"' EXIT

MNT="$TDIR/fakemnt"
mkdir -p "$MNT"

# --- Helper: set up a AICLI_PROC_MOUNTS fixture ---
fixture_mounts() {
    local fixture="$TDIR/proc_mounts"
    printf '%s\n' "$@" > "$fixture"
    export AICLI_PROC_MOUNTS="$fixture"
}

# --- Helper: stub fuser in PATH ---
stub_fuser() {
    local rc="$1" pids="${2:-}"
    cat > "$TDIR/fuser" <<STUBEOF
#!/bin/sh
printf '%s' "$pids"
exit $rc
STUBEOF
    chmod +x "$TDIR/fuser"
    export PATH="$TDIR:$PATH"
}
unstub_fuser() {
    rm -f "$TDIR/fuser"
    export PATH="${PATH#"$TDIR":}"
}

# Row 1: no overlay entry, fuser returns 300 PIDs, no ttyd -> NOT BUSY (the fix)
fixture_mounts "proc /proc proc rw 0 0" "sysfs /sys sysfs rw 0 0"
stub_fuser 0 "1 2 3 4 5 6 7 8 9 10"
assert_rc 1 "unmounted + fuser returns PIDs -> idle (THE FIX)" home_mount_in_use "$MNT"
unstub_fuser

# Row 2: no overlay, fuser returns PIDs, BUT ttyd running with AICLI_HOME
# We can't easily fake pgrep+cmdline in a unit test, so we skip this row
# and note the ttyd scan is placement-tested (it runs before the mount check).

# Row 3: overlay present, fuser returns PIDs -> busy
fixture_mounts "overlay $MNT overlay rw,lowerdir=x,upperdir=y,workdir=z 0 0"
stub_fuser 0 "12345"
# Need _holder_is_infra_daemon to reject pid 12345 -> not infra -> busy
assert_rc 0 "mounted + fuser returns non-infra PID -> busy" home_mount_in_use "$MNT"
unstub_fuser

# Row 4: overlay present, fuser rc 1 (no holders) -> not busy
fixture_mounts "overlay $MNT overlay rw,lowerdir=x,upperdir=y,workdir=z 0 0"
stub_fuser 1 ""
assert_rc 1 "mounted + fuser rc 1 (no holders) -> idle" home_mount_in_use "$MNT"
unstub_fuser

# Row 5: overlay present, fuser rc 1, only infra PID
# Skipped: would need /proc/<pid>/cmdline fixture for _holder_is_infra_daemon.

# Row 6: overlay present, fuser rc 2 (error) -> fail safe (busy)
fixture_mounts "overlay $MNT overlay rw,lowerdir=x,upperdir=y,workdir=z 0 0"
stub_fuser 2 ""
assert_rc 0 "mounted + fuser error (rc 2) -> busy (fail-safe)" home_mount_in_use "$MNT"
unstub_fuser

# Verify _overlay_present_at directly
echo ""
echo "=== D-aux: _overlay_present_at unit checks ==="
fixture_mounts "overlay $MNT overlay rw,lowerdir=x,upperdir=y,workdir=z 0 0"
assert_rc 0 "overlay line present -> true"                _overlay_present_at "$MNT"
fixture_mounts "proc /proc proc rw 0 0"
assert_rc 1 "no overlay line -> false"                    _overlay_present_at "$MNT"
fixture_mounts "overlay ${MNT}extra overlay rw 0 0"
assert_rc 1 "overlay at different mount -> false"         _overlay_present_at "$MNT"

# ============================================================
echo ""
echo "=== D-supervisor: standalone busy fallback ==="
# ============================================================

SUPERVISOR_SH="$REPO_ROOT/src/scripts/supervisor/aicli-supervisor.sh"
eval "$(sed -n '/^_supervisor_overlay_busy()/,/^}/p' "$SUPERVISOR_SH")"
unset -f home_mount_in_use

cat > "$TDIR/pgrep" <<'STUBEOF'
#!/bin/sh
: > "$PGREP_MARKER"
exit 1
STUBEOF
cat > "$TDIR/mountpoint" <<'STUBEOF'
#!/bin/sh
[ "${TEST_IS_MOUNTED:-0}" = "1" ]
STUBEOF
cat > "$TDIR/fuser" <<'STUBEOF'
#!/bin/sh
: > "$FUSER_MARKER"
exit "${TEST_FUSER_RC:-1}"
STUBEOF
chmod +x "$TDIR/pgrep" "$TDIR/mountpoint" "$TDIR/fuser"
export PATH="$TDIR:$PATH"
export PGREP_MARKER="$TDIR/pgrep-called"
export FUSER_MARKER="$TDIR/fuser-called"

supervisor_unmounted_probe_order() {
    rm -f "$PGREP_MARKER" "$FUSER_MARKER"
    TEST_IS_MOUNTED=0 TEST_FUSER_RC=0 _supervisor_overlay_busy "$MNT"
    local rc=$?
    [ "$rc" -eq 1 ] && [ -e "$PGREP_MARKER" ] && [ ! -e "$FUSER_MARKER" ]
}
assert_rc 0 "unmounted -> ttyd scan runs, fuser skipped" supervisor_unmounted_probe_order

TEST_IS_MOUNTED=1 TEST_FUSER_RC=0 assert_rc 0 "mounted + fuser holders -> busy" _supervisor_overlay_busy "$MNT"
TEST_IS_MOUNTED=1 TEST_FUSER_RC=1 assert_rc 1 "mounted + no holders -> idle" _supervisor_overlay_busy "$MNT"
TEST_IS_MOUNTED=1 TEST_FUSER_RC=2 assert_rc 0 "mounted + fuser error -> busy" _supervisor_overlay_busy "$MNT"

# ============================================================
echo ""
echo "==========================================="
echo "  TOTAL: $TESTS tests, $PASS passed, $FAIL failed"
echo "==========================================="
[ "$FAIL" -eq 0 ] || exit 1
