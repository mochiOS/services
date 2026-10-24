# keychain.service

An encrypted local vault per OS user. Native operation follows successful OS
login; Keychain.app has no separate password for ordinary operations. The
service owns the encryption keys and storage. AppCore is the application API;
Keychain.app is the built-in management UI. Policy remains in userspace.

## Login and authority

- Native `user.service` verifies the account password and then forwards the
  password, OS UID, current session epoch and account-credential generation tag
  over authenticated IPC. The tag is SHA-256 of the encoded account verifier;
  it selects a credential generation and is never used as an encryption key.
- Credential handoff requires `keychain.authentication`, the built-in
  `org.mochios.user` identity and the exact user-service process pinned at
  keychain startup. Ordinary apps cannot forge an authentication handoff.
- Valid login material is held in a pending state. It does not authorize app
  access until the exact launching service-manager activates that OS UID.
  Pending proofs are admitted for at most 60 seconds; they are discarded on
  lock, activation, replacement and expired-request cleanup. Cleanup on expiry
  is request-driven, not a guarantee of a timer-driven memory wipe.
- Screen lock/logout clears keys, pending proofs and recovery wrapping keys.
  Session epochs begin with CSPRNG output and advance on lock/activation. Old
  approvals and login handoffs cannot reopen a later session. Native startup
  without an authenticated bootstrap controller is rejected.
- Caller package/signer/provenance come from kernel security context. An actual
  sender ProcessHandle is opened with WAIT|TRANSFER; only WAIT is exported to
  POSIX for real/effective UID inspection. The local source is always closed.
  Set-ID callers are rejected. Request fields never choose an app caller's UID.
- Normal reads/writes require `keychain.access` and match the owner or a read
  grant. Management requires the built-in Keychain identity and
  `keychain.manage`; reveal/delete/grant/revoke use the authenticated session,
  its captured epoch and explicit UI actions, without another password prompt.
  Grants do not allow mutation/deletion and cannot cross OS users. Signing-key
  replacement is a different app identity requiring a new grant.
- Native AppCore/user-service clients verify the built-in keychain endpoint
  before sending anything secret and require `process.inspect` for that check.

No password or usable plaintext vault key is written beside the ciphertext.
A hash of the OS password verifier is not a substitute for a decryption key.

## Encrypted format and storage

Files are `/var/lib/keychain/<uid>.vault`; the directory is service-owned 0700,
files are 0600. NOFOLLOW/NONBLOCK and opened-file owner/type/mode/link-count
validation reject unexpected objects. Only ciphertext is written through a
private synced temporary file, atomic rename and directory sync. Storage or
integrity errors clear the affected user's cached keys; cached publication
fingerprints prevent a different on-disk file authorizing in-memory secrets.

`MKEYV002` uses a CSPRNG-generated 32-byte data key. A login password derives a
separate wrapping key with Argon2id v1.3 (64 MiB, three passes, one lane), a
random 16-byte salt, and a 32-byte output. XChaCha20-Poly1305 wraps the data key
with a fresh 24-byte nonce and domain-separated AAD binding UID, credential tag
and salt. The complete header and wrapped-key slots authenticate the encrypted
body, which has its own fresh 24-byte nonce on each publication. Every item,
owner, account, label, service, grant and secret remains encrypted.

The canonical 64-byte v2 header contains magic, UID, version, slot count, body
nonce and ciphertext length; reserved bytes must be zero. Each 120-byte slot is
credential tag (32), salt (16), wrapping nonce (24), wrapped data key/tag (48).
Only one or two distinct slots are accepted. Lengths and parsing are bounded.
The data key remains random when the login password changes. Explicit key,
secret, KDF working-memory and wire buffers use zeroizing ownership.

Limits remain 256 items, 16 read grants/item, 4096 secret bytes/item and 2 MiB
per file. IPC is bounded to the native 8 KiB limit: item pages contain at most
two worst-case records, catalogue pages 32 identities. Revision/count checks
prevent mixed pages. Wire magic is `MKCHN004`; rebuild clients and daemons
together. `MKEYV001` encrypted files are preserved and can be migrated.

## Password changes, migration and failures

Before the account DB changes a password, user.service asks keychain to install
two encrypted wrappers: the wrapper matching the authoritative *current* DB tag
and the proposed new wrapper. The current data key protects the latest data
under either credential. A failed earlier proposal is never mistaken for the
current DB credential. If wrapping cannot be made durable, the account DB is
not updated. The account DB syncs the new file and directory before reporting
success; uncertain save errors stop further authentication/writes until restart.

The next successful login activation consolidates the wrappers to the credential
generation verified by user.service. This supports a crash before or after the
account DB update. Until that activation, both previous and proposed passwords
may decrypt a prepared on-disk vault; historical copies cannot be recalled.
An unlocked v2 vault is required to change a password for an existing protected
account; an unavailable/legacy vault makes that change fail rather than silently
lose the data key. Initial account setup (no vault yet) is supported, and a
successful password-setting operation stages login material for first activation.

For v1 data whose old Keychain password differs from the login password,
Keychain.app asks for the old password once for migration. Successful recovery
rotates the data key and rewraps it using the login-derived key already supplied
by authenticated user.service. Wrong passwords, tampering and storage failures
never replace a vault with an empty one. If the old password already matches
the login password, migration is automatic. A login-password reset outside this
coordinated path may similarly require one-time old-password recovery.

Automatic OS sign-in without password-derived login material does not invent a
key or weaken storage protection. The vault stays unavailable; locking the screen
and authenticating with the OS password supplies the missing material. A
keychain handoff error does not report a false account-password failure: OS
authentication may succeed while the vault remains closed. Account-password
strength (including passwordless accounts) bounds offline protection.

## Linux preview

`mmake preview-keychain` and `mmake ui` run the same encrypted format with an
explicitly disposable development session. A random preview credential exists
only in memory. It is not a stored host password, is not passed in argv/env and
is not a claim of real OS authentication. The launcher pins client executable
inodes/package IDs; SO_PEERCRED checks the host UID. `--auto-session` refuses an
existing vault instead of converting persistent data to an unrecoverable random
credential. Old `out/preview/config/keychain` data is left untouched. Both preview
entrypoints stop the daemon and discard temporary session data on exit.

Host-UID ptrace/preload/binary modification is outside preview isolation. Native
login flow uses the pinned account/session services instead. Restarting either
pinned authority requires a coordinated keychain restart; restart starts closed.

## Validation and remaining boundaries

Tests cover native session gates, forged/stale login proofs, user/owner/signer
isolation, passwordless management through real Unix IPC, restart auto-unlock,
legacy migration preserving entries, wrong-password non-destruction, interrupted
password updates, failed prior proposals, publication consistency during active
sessions, entropy failure with no persisted fallback, and failed writes closing
the correct user's cache. v1 and v2 complete-file fixtures match independent
libargon2/libsodium implementations; malformed headers/wrappers/body tags,
truncation, trailing bytes and cross-user substitution are rejected. The UI has
no normal password fields or standalone password-change/lock buttons; only
explicit migration/recovery exposes an old-password field.

Native builds and host tests do not prove real kernel authority, filesystem
crash durability, hardware behavior or every screen-lock timing. Independent
OS runtime fault injection and adversarial review remain necessary. No
hardware-backed anti-rollback, TPM, swap/core-dump exclusion, cloud sync,
recovery key or account-deletion cleanup is implemented. Managed buffers are
erased; compiler/register copies, raw OS input/IPC buffers and explicitly
revealed rendering/display copies are not all guaranteed scrubbed. Revocation
cannot recall secrets already delivered to an authorized app. C/Kome bindings
remain outside this first Rust API.

## Historical adversarial review, 2026-10-24 (v1 / wire 3)

This was an internal review of our implementation, not an independent security
certification. Concrete weaknesses were reproduced and corrected:

| Finding | Exposure / correction | Regression evidence |
| --- | --- | --- |
| Secret encoder reallocation released unwiped old memory | Memory-residency weakness; allocate separately and zeroize the old allocation before release | Allocator inspects the still-live allocation before free/realloc; test failed before the fix |
| Secure input retained editing/rendering copies | ViewKit's secure display alone did not guarantee buffer erasure; protect stored and temporary values, erase superseded editing buffers, move input ownership | Allocator verifies editing, extraction and destruction; accessibility/clipboard masking remains intact |
| A late reveal reappeared after focus loss | Background RPC completion could restore a secret even after blur/refocus; reject the old exposure generation and clear secret inputs on blur | Delayed-channel completion test failed before the fix |
| Storage trusted pathname metadata and insufficient ownership/link checks | Refuse foreign/non-private directories, use NOFOLLOW/NONBLOCK, validate the opened file's owner/type/mode/link count, and validate the preview lock file | Symlink lock and hard-linked vault were accepted before the fix; regression rejects both |
| Native credential inspection lacked source TRANSFER authority | Correct requests would be denied by the real kernel; open WAIT\|TRANSFER locally, export WAIT only, and close on success/error | A backend contract test enforces the kernel export rule and failed before the fix; native build also passes |
| Metadata replies exceeded the real kernel IPC limit | Native availability failure, hidden by Linux transport; enforce 8 KiB, paginate worst-case item/catalogue replies | Full-size records and catalogue cross AppCore transport under the native size limit |
| Reauthentication was not bound to the cached vault | With storage-write authority, replacing disk data with an older vault could let its password authorize newer cached secrets | Replacement-file test failed before the fix; publication fingerprint now rejects/locks |
| Locking did not invalidate delayed privileged work | A pre-lock unlock/grant request could arrive after locking; disable native access until authenticated activation, bind all password-authorized work to the captured epoch | Tests cover disabled startup, forged activation, stale unlock, cross-user activation and stale reveal/delete/grant/rekey |

Cryptographic format verification uses public, deterministic vectors generated
independently with `libargon2` (`argon2id_hash_raw`) and `libsodium`
(`crypto_aead_xchacha20poly1305_ietf_encrypt`). Derived key and complete serialized
vault bytes match; truncations, trailing bytes and modification of every byte in
the fixture are rejected. Decoder tests exercise 4096 malformed framed inputs;
this is regression coverage, not a sustained fuzzing campaign.

The service's normal runtime dependency graph (including all target adapters)
was compared with the official [RustSec database](https://github.com/RustSec/advisory-db)
snapshot `1645308cb4766561b0b274d8c93f7033a766fc96`. Relevant advisories were
RUSTSEC-2019-0019 (blake2), 2019-0029 (chacha20), 2020-0146 (generic-array),
2019-0035/2021-0023 (rand_core), and 2021-0100 (sha2). The resolved versions
0.10.6, 0.9.1, 0.14.7, 0.6.4 and 0.10.9 are outside their affected ranges.
No applicable advisory was found in that scoped comparison. This does not cover
all OS/UI dependencies, unpublished issues or our local libc/kernel forks.
The [zeroize documentation](https://docs.rs/zeroize/latest/zeroize/)
explicitly describes the reallocation caveat addressed above.

Residual boundaries requiring care:

- Native tests/builds do not establish end-to-end kernel capability, signed-image,
  POSIX credential, real filesystem crash-durability or screen-lock correctness.
  Those need OS runtime fault injection and independent adversarial review.
- Linux preview shares the host UID and does not provide production isolation
  against that UID's ptrace, preload, endpoint replacement or binary modification.
  Do not use preview isolation as evidence that production secrets are protected.
- Hardware-backed rollback prevention, swap/core-dump exclusion, TPM-backed keys
  and recovery are not implemented. Full disk rollback across restarts is not
  detected. A compromised privileged service/kernel or stolen decrypted memory
  is outside the enforced boundary.
- Managed buffers are erased, but compiler/register copies, raw OS input/IPC
  buffers, explicitly revealed text and rendering/display copies are not all
  guaranteed to be scrubbed. `TextFieldInteractionState::value()` and external
  bindings hand plaintext copies to their caller; sensitive consumers should
  transfer ownership with `take_value()` and erase their own buffers.
- Native startup accepts only the authenticated launching service-manager;
  restarting that manager requires coordinated service restart. Restart begins
  locked and does not silently restore a previous session's authority.

Final regression results for this review: protocol 4, service 14, AppCore 28,
service-manager 22, Keychain UI 5 and ViewKit 142 tests passed (215 total;
one pre-existing ViewKit test ignored). `mmake ui-check` passed. Native release
builds of keychain-service, service-manager and Keychain succeeded using the
existing SDK. The ordinary `mmake keychain-service` dependency path is still
blocked by the pre-existing SDK `sys/wait.h` include_next failure; a successful
direct build is not evidence of OS runtime correctness.
