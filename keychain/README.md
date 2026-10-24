# keychain.service

An encrypted, local, per-OS-user vault. The service owns storage and keys;
AppCore is the application API and Keychain.app is the trusted management UI.
No keychain-specific syscall or kernel policy is added. Three names are declared
in the shared capability catalogue: `keychain.access`, `keychain.manage` and
`keychain.session`.

## Authority

Native requests derive application package, signing-key ID and provenance from
`GetThreadSecurityContext`. A WAIT-only ProcessHandle is opened for the actual
IPC sender and passed to POSIX `process_session_info`; request fields cannot
select the caller UID/PID or Bundle ID. Only the authenticated session controller
may select the active UID through the separate `ActivateSession` operation. Set-ID callers are rejected. Each user's file
and in-memory key is separate. An item's owner is the complete verified
application identity, including signing key and provenance. Grants permit reads,
not mutation or deletion. Replacement signing keys require a new grant.

Access requires `keychain.access`. Management additionally requires
`keychain.manage` and the built-in `org.mochios.keychain` identity. Revealing,
deleting other owners' items, granting/revoking access and changing the password
require the vault password again. `LockAll` requires `keychain.session` and the
built-in service-manager identity, pinned to the exact authenticated launching
manager process. Native startup requires this bootstrap authority. The manager
waits for READY before login and waits for key removal before acknowledging
screen lock/logout. Native vault access starts disabled; only a successful OS
authentication (or the trusted first-boot installer path) activates an OS user.
Locking disables access until another authenticated activation. Session epochs
start from the CSPRNG and advance on lock/activation. Password-authorized
operations carry the epoch captured before queuing UI work, so stale approvals
cannot unlock, reveal, delete, grant/revoke, or rekey a later session. A confirmed dead
vault process already has no live keys; an unconfirmed failure blocks the
acknowledgement. No app-grant can authorize crossing the OS-user boundary.

Native AppCore clients also require `process.inspect` to verify the actual
built-in keychain endpoint before transmitting secrets. This uses the existing
inspection API; replacing it with a narrower delegated service endpoint can be
considered separately.

## Storage and cryptography

- `/var/lib/keychain/<effective-uid>.vault`, directory 0700, files 0600.
- Argon2id v1.3, 64 MiB, three passes, one lane, 32-byte key. A new password must
  have at least 12 Unicode characters. Format version 1 fixes these parameters.
- Random 16-byte salt; XChaCha20-Poly1305 with a fresh random 24-byte nonce on
  every publication. CSPRNG failure aborts the operation, with no fallback.
- A 64-byte authenticated header contains magic, user ID, format version, salt,
  nonce and ciphertext length. Labels, services, accounts, owners, grants and
  secrets are all encrypted. No usable key or password verifier sits beside it.
- At most 256 items, 16 grants/item, 4096 secret bytes/item and 2 MiB per file.
  IPC is bounded to the native 8 KiB capacity. Item pages contain at most two
  worst-case records; application pages contain at most 32 identities. Both
  lists are paginated with revision/count checking. Wire magic is `MKCHN003`;
  clients and service must be rebuilt together. The encrypted file format
  remains version 1 and existing vaults stay readable.
- Explicit secret, derived-key, KDF working-memory and wire buffers are zeroized;
  their Debug representations never contain secret bytes. UI text rendering is
  not a guarantee that every allocator or display-system copy is erased.
- Mutations publish a complete encrypted candidate through a synced private
  temporary file, atomic rename and parent-directory sync. Memory changes only
  after success. Any storage/integrity error drops that user's cached key;
  uncertain post-rename failures require re-unlocking instead of using stale data.
- While unlocked, a SHA-256 fingerprint binds the cached vault to the last
  committed ciphertext. Reauthentication and mutations reject missing/replaced
  storage and drop cached keys instead of using another file's password to
  authorize the cached secrets. This is not rollback protection across restarts.
- A restart always begins locked. Wrong passwords, malformed files and failed
  authentication never reset or overwrite an existing vault. Password changes
  publish a fresh salt/key/nonce while retaining entries and grants.

The first version uses a separate, manually entered vault password. It does not
reuse the OS password hash. Login auto-unlock, OS-password-change integration,
TPM protection, cloud synchronization, recovery keys, account-deletion cleanup,
and hardware-backed rollback prevention are not implemented. Resetting a login
password does not decrypt or reset this vault. Revocation cannot recall secrets
already delivered to an authorized app.

## Linux preview

The same vault/protocol core runs as a Unix-socket daemon. A trusted development
launcher pins allowed executable inodes, package IDs and manager roles. The daemon
checks SO_PEERCRED and `/proc/<pid>/exe`; clients cannot enroll themselves through
request fields. The socket directory is private and peers must have the host
UID. A held file lock prevents concurrent preview daemons writing the same data.
This is a development adapter, not equivalent to native signed-process isolation:
it does not defend against the host user's ptrace, preload or binary modification.

`mmake preview-keychain` starts a daemon and UI, retaining encrypted data under
`out/preview/config/keychain`. `mmake ui` uses a disposable session, including its
vault. Both stop the daemon on exit. Rebuild/restart the preview to enroll a new
executable inode. The native daemon is launched once by the trusted service
manager, owns the root-private storage directory and uses existing POSIX/IPC APIs.

## Validation

Tests exercise encrypted-at-rest content, user/owner/signer boundaries, grant
revocation, unauthorized management, restart locking, wrong passwords, password
changes, ciphertext tampering, cross-user file substitution, failed writes,
CSPRNG failure, storage permissions and preview writer exclusion. A real Unix
socket/SO_PEERCRED test performs AppCore initialize/put/get/lock requests. Native
transport code is type-checked in the host test build; actual OS runtime checks
remain separate from these tests.

## Adversarial review, 2026-10-24

This was an internal review of our implementation, not an independent security
certification. Concrete weaknesses were reproduced and corrected:

| Finding | Exposure / correction | Regression evidence |
| --- | --- | --- |
| Secret encoder reallocation released unwiped old memory | Memory-residency weakness; allocate separately and zeroize the old allocation before release | Allocator inspects the still-live allocation before free/realloc; test failed before the fix |
| Secure input retained editing/rendering copies | ViewKit's secure display alone did not guarantee buffer erasure; protect stored and temporary values, erase superseded editing buffers, move input ownership | Allocator verifies editing, extraction and destruction; accessibility/clipboard masking remains intact |
| A late reveal reappeared after focus loss | Background RPC completion could restore a secret even after blur/refocus; reject the old exposure generation and clear secret inputs on blur | Delayed-channel completion test failed before the fix |
| Storage trusted pathname metadata and insufficient ownership/link checks | Refuse foreign/non-private directories, use NOFOLLOW/NONBLOCK, validate the opened file's owner/type/mode/link count, and validate the preview lock file | Symlink lock and hard-linked vault were accepted before the fix; regression rejects both |
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
