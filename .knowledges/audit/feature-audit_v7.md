# Feature Audit v7 — Persistent Filesystem and Process-Crash Tests

**Date:** 2026-10-16

**Scope:** Extend verification of the uncommitted v5 fixes beyond tmpfs and
normal shutdown. The application source remains unchanged from the v5
remediation; this task adds test evidence only.

**Result:** All performed tests passed. Windows runtime and actual machine
power loss remain untested because this environment has no Windows runtime or
VM. Process SIGKILL is not equivalent to losing OS caches or device power.

## Environment

- Linux amd64, Go 1.27.2; all modules still declare minimum Go 1.26.0.
- findmnt reports the workspace mount as **ext4**. Temporary audit and test files
  were created under verification_v7/runtime, on that mount instead of /tmp.
- Native Windows execution, Wine, and qemu-system-x86_64 were unavailable.
  The previous Windows cross-compilation remains recorded in v5; it is not a
  Windows runtime or Windows filesystem durability test.

## All-module verification on ext4

All seven modules completed go test -race -count=1 ./..., go vet ./..., and
go mod tidy -diff successfully. TMPDIR was set to an absolute directory under
the ext4 workspace mount, so filesystem-backed test fixtures used ext4.

| Module | Race result |
| --- | --- |
| core | Passed, 5.677s |
| http | Passed, 1.140s |
| fiber | Passed, 1.148s |
| echo | Passed, 1.133s |
| gin | Passed, 1.125s |
| examples | All five packages compiled; no tests present |
| integration/mysql | Compiled/passed, 1.029s; live test skipped without a DSN |

## Process-crash recovery

A dedicated child writer called FileAuditSink.Emit, then printed an acknowledgment
only after Emit returned nil. A parent process collected 20 acknowledgments
before sending SIGKILL to that child. Only test-owned child processes were killed.

- **10 barrier rounds:** the writer waited for a command after each acknowledged
  event, isolating crashes after acknowledgment from a subsequent append.
- **10 continuous rounds:** the writer continued appending larger records while
  the parent killed it, allowing interruption during a subsequent write.
- **400 acknowledged events** were found intact in the complete JSONL prefix
  after the crashes, without duplicate IDs or changed order.
- **19 files** had complete tails and were reopened in a separate process; a
  recovery event was appended successfully.
- **1 file** had an incomplete trailing record. Constructor reopening rejected
  it without modifying evidence. Its previously acknowledged events remained
  intact in the complete prefix. Explicit repair is required before appending,
  as documented; the test did not silently truncate the partial evidence.
- A deterministic incomplete-tail case also returned rejection without mutation.

[Per-round results](verification_v7/crash-results.json),
[child writer](verification_v7/crash-probe.go.txt), and
[parent harness](verification_v7/run-crash-probe.py.txt) preserve the evidence.
The harness uses absolute paths for this workspace; adjust them when reproducing
elsewhere. No actual power loss, unmount, host reboot, or device interruption
was performed. OS caches remained available to the recovery process.

## Real kernel I/O failures

A separate child probe temporarily set its own soft RLIMIT_FSIZE to the current
audit-file size, leaving the hard limit unchanged. A new audit append then
failed with **EFBIG** from the kernel. The original limit was restored.

The test confirmed:

1. An otherwise permitted authorization decision returned denied with
   AuditWriteError, Committed=false, and the EFBIG cause.
2. Previously persisted audit bytes were unchanged.
3. Restoring the file limit did not implicitly recover the poisoned sink;
   subsequent decisions remained denied.
4. Explicitly closing and reopening the sink restored successful auditing and
   the expected authorization decision.

This simulates a file write limit, not exhaustion of the entire filesystem.

The same probe created a test-owned directory and temporarily removed its read
permission while retaining write/search permission. Opening an audit file could
succeed, but parent-directory initialization failed with **EACCES**. The
constructor returned no sink. After restoring permissions, reopening and
appending succeeded. All permissions were restored before cleanup.

[Kernel failure results](verification_v7/io-failure-results.txt) and
[probe source](verification_v7/io-failure-probe.go.txt).

## Limits and cleanup

- These results establish the observed Linux/ext4 process-crash and failure
  behavior, not universal filesystem or hardware durability.
- Windows runtime, actual power-loss recovery, and live PostgreSQL/MySQL/Redis
  integrations were not tested in this task.
- Temporary audit files and the empty ext4 runtime directory were removed.
  Small reproduction sources and JSON/text results remain as evidence.
- No application source, dependency, or Go-version change was made. No commit,
  push, merge, or remote CI run was performed.
