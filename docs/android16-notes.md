# Android 16 Notes

This fork keeps a narrow compatibility layer on top of upstream `JingMatrix/NeoZygisk`.

## Root Cause We Hit

On Android 16, `zygote64` could abort with:

- `session socket read failed: Connection reset by peer`

The issue was in `loader/src/injector/module.cpp` inside `sanitize_fds()`. Framework-provided `fds_to_ignore` were only preserved when NeoZygisk's own `exempted_fds` list was non-empty. That allowed Android 16 session sockets to be closed during file-descriptor sanitization.

## Fix Shape

The fix is intentionally small:

- always preserve framework `args.app->fds_to_ignore`
- merge NeoZygisk's `exempted_fds` on top of that set

This keeps Android 16 critical sockets alive while preserving the original sanitization behavior for unrelated descriptors.

## Debugging Workflow That Worked

1. Confirm the failure signature in logs before patching.
2. Build from the fork and install only the live files that changed.
3. Back up every overwritten runtime file under `/data/adb/...` first.
4. Re-enable only after a successful staged copy.
5. Verify with:
   - live file hashes
   - `zygote64` / `zygisk*` process state
   - newest tombstone timestamps
   - targeted logcat around the restart window
   - a real app launch such as Settings

## Important Scope Boundary

If Android still boot-loops after this fix, do not assume NeoZygisk is still the primary cause. On this device, later instability came from framework-hooked modules in `system_server`, which showed up in `/data/system/dropbox`, not in tombstones.
