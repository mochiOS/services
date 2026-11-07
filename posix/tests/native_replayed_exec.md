# Authenticated dynamic exec regression

Recorded development-candidate verification: all eight native cases passed,
alongside 127 host tests. See [the results](native_replayed_exec.results.json)
and [guest log](native_replayed_exec.log) for artifact digests and actual exits.
This does not mark the published SDK archive as fixed.

`native_replayed_exec.c` exercises the real C runtime on mochiOS. The child
executable imports `exec_answer()` from a small shared library, so a successful
result requires linking and relocation; executing an unchanged static image
does not satisfy this test.

The old failure was an authorization mismatch: the runtime submitted the digest
of its linked output to a verifier expecting the installed original executable.
The prepared-exec request now supplies original captured inputs and loader
choices. The capability broker authenticates the installed root and complete
dependency catalog, replays the shared loader, and measures the output. Native
image replacement still verifies that digest and attenuates capabilities.

## Build the fixture

Use a development SDK containing the updated `libmochi_user_newlib_runtime.a`
and a capability service built from the matching source. The published
`27.0-dp.1-shared.4` archive is immutable and does **not** contain this fix.
An isolated copy of that SDK with only its runtime archive replaced can be used
for development. Do not overwrite hardlinked files in place.

From the OS checkout:

```sh
python3 services/posix/tests/native_replayed_exec.py \
  --sdk "$EXEC_TEST_SDK" \
  --capability-binary out/rust-std/target/x86_64-unknown-mochios/release/capability \
  --msign out/mmake/host-tools/release/msign \
  --output out/native-replayed-exec
```

The output contains staged System files, their ordinary built-in package
bindings, Data fixtures under `data/tmp/exec-test`, and path-free input digests. Compose
`stage` into System and `data` into Data in a **disposable development image**
through the normal image and boot-module tools. The preseeded files avoid testing
file-copy throughput; the guest still opens and unlinks the retained-FD target.
Preserve fixture permissions: the private `exec-test` directory is writable
without a sticky bit so the logged-in user can unlink the preseeded file. The
OS `/tmp` permissions are unchanged.
Recompute the System digest in the boot module; retain Secure Boot and existing
authentication settings. The fixture replaces the declarative session-startup
file only inside that disposable image. It does not change a production image,
install extra service privileges, or disable signature verification.

The package requests `process.spawn`, `fs.read.all`, `fs.write.tmp`, `ipc.client`,
`ipc.server`, `system.random.read`, and `system.time.read`. Its ordinary targets
declare the same requirements. Only the deliberately forbidden target adds
`net.connect`, which the parent must not hold. The normal package manifest binds
the DSO as library code. The fixture contains no external network dependency.

## Expected results

Read `/tmp/exec-results.log` from the guest Data filesystem:

| Case | Requirement |
| --- | --- |
| 0 | `execv` succeeds; child exits 42 |
| 1 | `execve` succeeds and preserves arguments/environment |
| 2 | `fexecve` succeeds from a retained FD after unlinking its copied pathname |
| 3 | Changing even an unused byte of the root yields `EACCES` |
| 4 | Loading identical DSO bytes from an undeclared `/tmp` path yields `EACCES` |
| 5 | A target requiring a capability absent from the caller yields `EACCES` |
| 6 | `execvp` performs PATH lookup and succeeds |
| spawn | `posix_spawn` successfully executes the same dynamic child |

Every case must report `PASS`, followed by `EXEC-TEST COMPLETE failures=0`.
A timeout, partial log, error launching the app, or an arbitrary nonzero child
exit is not a successful negative test. Negative cases specifically require
`EACCES`. This test does not establish WebKit compatibility or complete POSIX
conformance.

## Host regression tests

```sh
cargo test --offline --manifest-path user/Cargo.toml \
  -p mochios-capability-protocol --lib
cargo test --offline --manifest-path services/Cargo.toml -p posix-service \
  --test replayed_loader --test fexecve_runtime \
  --test signed_image_authorization --test object_image_authorization
```

These exercise the actual shared loader and runtime adapter, transcript
structure/order/bounds, source and library tampering, cleanup on failure, and
complete authenticated identity matching before reusing existing consent.

## Scope

Transformed executions currently require installed package metadata. Unchanged
static images keep their existing authorization path. A different application
requiring an interactive permission is rejected rather than treating caller
authority as new consent; same-application reuse still requires every requested
capability to be held. This change does not introduce a cross-application consent
UI or claim that arbitrary standalone dynamic executables are supported.

The broker accepts bounded native RAM only, never caller Provider callbacks.
Recorded environment controls are filtered using credentials fetched from POSIX
for a pinned native Process. Caller image/security context and credentials are
checked again before publishing the replacement permit. The transcript is capped
at 256 MiB and 8,200 events; event paths and environment values are bounded too.
