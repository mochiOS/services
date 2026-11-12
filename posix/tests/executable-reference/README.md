# Native signed executable references

This opt-in integration fixture exercises the actual AppCore API, libc fork/
spawn runtime, capability broker, signed installed package graph and native
image replacement. It is not part of the production image or SDK.

Build from the mochiOS workspace root with a matching native toolchain and an
SDK assembled from the current libc runtime (published shared.9 is too old):

```sh
make -f services/posix/tests/executable-reference/build.make RUST_SDK=/absolute/path/to/sdk
python3 services/posix/tests/executable-reference/stage.py \
  --stage /absolute/path/to/private-vm-stage \
  --sdk /absolute/path/to/sdk \
  --native-directory out/rust-std/target/x86_64-unknown-mochios/release \
  --msign out/resource-api-tests/debug/msign
```

`stage.py` only writes the supplied private staging directory. It creates the
three fixture packages and development built-in verification records; it never
writes a disk, modifies the installed OS, or publishes a package. Include these
files in a development VM image using the normal image assembly/signing path.
The image must also include matching capability, user, POSIX, filesystem, logger,
core and the feature-built service-manager, each with its own matching manifest
and verification record. Use an empty private Data volume for each run.

The service-manager feature starts the ordinary filesystem, POSIX and account
services before the existing headless test launcher. The trusted launcher uses
its declared `fs.read.all` only to request a normal application launch. The
actual probe has **no `fs.read.all`** and no hard-coded kernel grants. Do not add
such a permission to make this test pass. No helper is loaded from initfs.

The probe checks own-package and publisher-pinned external helper selection,
missing/invalid aliases, ABI mismatch, refusal of a child requiring more
capabilities, empty child environment, pipe output, stable repeated wait, and
an explicitly mapped FD 7 with verified file contents. It also catches failure
to preserve signed Bundle startup keys across fork and to decode packed IPC
reply lengths correctly. The external helper is an exported application binary
inside a library package, rather than an implicitly executable library.

Success requires the exact `EXE-API PASS` line in the Data volume's
`/tmp/executable-api-results.log`, with no `EXE-API FAIL`. Launcher exit status,
a successful boot, a window or a timeout alone must never count as a pass.
Read this file directly from the VM volume; release logging may be disabled.
