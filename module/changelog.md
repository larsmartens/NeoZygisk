# v2.3 daily

_Commit titles and messages for `v2.3..v2.3 daily`._

## Update SELinux policy to read mount namespace (#98)

The following SELinux audit logs are observed on AVD emulated devices (based on qemu):
```
auditd  : type=1400 audit(0.0:9): avc:  denied  { read } for  comm="main" path="mnt:[4026532964]" dev="nsfs" ino=4026532964 scontext=u:r:zygote:s0 tcontext=u:object_r
```
which caused the failure of NeoZygisk updating mount namespace of root process.
- Commit: `f779511`
- Author: JingMatrix
- Date: 2026-02-18

## Fix SIGSEGV by skipping non-readable stack guard pages (#95)

This commit fixeas a crash observed on specific devices (e.g., Redmi Note 10 Pro "sweet", Kernel 4.14) where `nativeForkSystemServer_pre` triggered a SIGSEGV (SEGV_ACCERR) when attempting to read the `[anon:stack_and_tls:main]` memory map.

We conjecture that the kernel on these devices includes the Stack Guard Page as part of the VMA range for the main thread's stack. A Guard Page is a memory region allocated at the limit of the stack with `PROT_NONE` permissions (no read/write/exec) to trap stack overflows.

Changes:
- Added a check for `PROT_READ` in the map iteration loop.
- Applied minor clang-format style fixes to pointer alignment in `module.cpp`.
- Commit: `e0c49d7`
- Author: JingMatrix
- Date: 2026-02-19

## Fix name inconsistency in spoofing maps

In NeoZygisk daemon, modules are loaded into memory via `memfd` with name `zygisk-module`.

As these mapped regions are private, it is better to spoof them also as private anonymous memory region.

clang reformatting is applied.

- Commit: `b4d31ab`
- Author: JingMatrix
- Date: 2026-02-20

## Support hierarchical zygote startup via stub processes (#100)

The ptrace monitoring logic has been re-architected to support a new Android startup chain where zygote is not a direct child of the init process. On some devices, the boot sequence is `init -> stub_zygote -> zygote`, which the previous flat monitoring model could not handle.

This change transitions the system from monitoring only direct children of init to a hierarchical model capable of recursively tracing a designated chain of processes.

Key changes include:

1.  Generalized Parent Handling: The logic specific to the `init` process has been refactored into a generic `handleParentEvent`. This function now handles fork events from any designated parent, including `init` or an intermediate stub process.

2.  Stub Process Promotion: When a traced child process executes a known `stub_zygote` binary, it is not detached. Instead, it is "promoted" to a new parent role. Its ptrace options are upgraded to trace forks, and its PID is added to a new `stub_processes_` set for tracking.

3.  Hierarchical Dispatch: The central `handleChildEvent` dispatcher now prioritizes routing events for PIDs in the `stub_processes_` set to the parent handler, allowing the monitor to discover and attach to grandchildren (the real zygote).

4. Fixed calls to `handleNewProcess`: The process might not be ready if it is not discovered via `waitpid` but observed from PTRACE_EVENT_FORK.

This new architecture is more resilient to platform variations in the boot process without sacrificing the precision of the injection mechanism.

- Commit: `aae20a8`
- Author: JingMatrix
- Date: 2026-02-21

## fix: add Magisk Alpha compatibility (late zygote detection)

Fix two issues preventing NeoZygisk from working with Magisk Alpha 30700:

1. NULL TMP_PATH crash: When the binary is invoked without TMP_PATH set
   in the environment, getenv() returns NULL which is passed to
   std::string constructor, causing SIGSEGV. Add NULL guard with
   fallback to default path /data/adb/neozygisk.

2. Late zygote injection: On Magisk Alpha, post-fs-data.sh executes
   AFTER init has already forked the zygote process. Since
   PTRACE_SEIZE with PTRACE_O_TRACEFORK on init only captures future
   fork events, the already-running zygote is never detected.

   Add ScanExistingZygotes() which runs after ptrace handler init to
   scan /proc for processes matching:
   - PPID == 1 (direct child of init)
   - exe == /system/bin/app_process64
   - TracerPid == 0 (not already traced)

   For each found zygote, SIGSTOP it and fork the injector daemon
   using the same handoff sequence as the normal fork-detection path.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

- Commit: `5d53cc6`
- Author: Lars Martens
- Date: 2026-03-01

## feat: add upstream sync workflow and fork update channel

- Add daily sync workflow from JingMatrix/NeoZygisk with -X ours merge
- Point updateJson in build.gradle.kts to larsmartens fork
- Update zygisk.json with fork release URLs
- Auto-build and publish to rolling 'latest' GitHub release

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

- Commit: `77711fe`
- Author: Lars Martens
- Date: 2026-03-02

## chore: update zygisk.json to v2.3 (282)


- Commit: `0f7898e`
- Author: github-actions[bot]
- Date: 2026-03-02

## fix(ci): specify repo for gh release commands

The gh CLI was resolving to the upstream JingMatrix repo instead of our
fork, causing a 403 on release creation. Use ${{ github.repository }}
to explicitly target the correct repo.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

- Commit: `0612df8`
- Author: Lars Martens
- Date: 2026-03-02

## chore: update zygisk.json to v2.3 (284)


- Commit: `8adfac8`
- Author: github-actions[bot]
- Date: 2026-03-02

## Add (de-)constructor symbols fallback for ProtectedData (#104)

The versions C2 and D2 of these two symbols are removed in Android 17 preview.
- Commit: `756b7c7`
- Author: JingMatrix
- Date: 2026-03-06

## chore: update zygisk.json to v2.3 (287)


- Commit: `fcde1c6`
- Author: github-actions[bot]
- Date: 2026-03-07

## Set TMP_PATH env programmatically (#105)

By doing so, we can invoke the binary `bin/zygisk-ptrace64` directly.

The wrapper scirpt `zygisk-ctl.sh` is thus removed.
- Commit: `42715ff`
- Author: JingMatrix
- Date: 2026-03-07

## chore: update zygisk.json to v2.3 (290)


- Commit: `ca7a3a9`
- Author: github-actions[bot]
- Date: 2026-03-08

## docs(fork): document fork maintenance changes


- Commit: `76572a5`
- Author: Lars Martens
- Date: 2026-03-02

## chore: update zygisk.json to v2.3 (292)


- Commit: `53edf1b`
- Author: github-actions[bot]
- Date: 2026-03-14

## fix(neozygisk): stabilize boot-time zygote injection


- Commit: `d3f64d9`
- Author: Lars Martens
- Date: 2026-03-18

## ci(fork): publish daily fork builds


- Commit: `6a0ea0e`
- Author: Lars Martens
- Date: 2026-03-18

## chore: sync fork metadata for daily build


- Commit: `825be17`
- Author: github-actions[bot]
- Date: 2026-03-18

## chore: sync fork metadata for daily build


- Commit: `f08e70f`
- Author: github-actions[bot]
- Date: 2026-03-19

## chore: sync fork metadata for daily build


- Commit: `df50b5c`
- Author: github-actions[bot]
- Date: 2026-03-19

## fix(ci): rebase before pushing synced metadata


- Commit: `ada0ccf`
- Author: Lars Martens
- Date: 2026-03-19

## chore: sync fork metadata for daily build


- Commit: `d2a2ae7`
- Author: github-actions[bot]
- Date: 2026-03-20

## chore: sync fork metadata for daily build


- Commit: `3b9ec87`
- Author: github-actions[bot]
- Date: 2026-03-21

## chore: sync fork metadata for daily build


- Commit: `9015197`
- Author: github-actions[bot]
- Date: 2026-03-22

## chore: sync fork metadata for daily build


- Commit: `dec5d3a`
- Author: github-actions[bot]
- Date: 2026-03-23

## chore: sync fork metadata for daily build


- Commit: `1727052`
- Author: github-actions[bot]
- Date: 2026-03-24

## fix(ci): retry sync push after remote updates


- Commit: `9f55694`
- Author: Lars Martens
- Date: 2026-03-25

## chore: sync fork metadata for daily build


- Commit: `32f014a`
- Author: github-actions[bot]
- Date: 2026-03-25

## chore: sync fork metadata for daily build


- Commit: `2a625d3`
- Author: github-actions[bot]
- Date: 2026-03-25

## feat(update): generate commit changelog for daily releases


- Commit: `a31be70`
- Author: Lars Martens
- Date: 2026-03-25

## chore: sync fork metadata for daily build


- Commit: `dfecdcd`
- Author: github-actions[bot]
- Date: 2026-03-25

## chore: sync fork metadata for daily build


- Commit: `aac3b88`
- Author: github-actions[bot]
- Date: 2026-03-26

## chore: sync fork metadata for daily build


- Commit: `0efdd0c`
- Author: github-actions[bot]
- Date: 2026-03-27

## chore: sync fork metadata for daily build


- Commit: `b5e48ab`
- Author: github-actions[bot]
- Date: 2026-03-28

## chore: sync fork metadata for daily build


- Commit: `80a2878`
- Author: github-actions[bot]
- Date: 2026-03-29

