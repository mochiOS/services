# keychain.service

An encrypted, local, per-OS-user vault. The service owns storage and keys;
AppCore is the application API and Keychain.app is the trusted management UI.
No keychain-specific syscall or kernel policy is added. Three names are declared
in the shared capability catalogue: `keychain.access`, `keychain.manage` and
`keychain.session`.

## Authority

Native requests derive application package, signing-key ID and provenance from
`GetThreadSecurityContext`. A WAIT-only ProcessHandle is opened for the actual
IPC sender and passed to POSIX `process_session_info`; no request UID/PID or
Bundle ID can select the caller. Set-ID callers are rejected. Each user's file
and in-memory key is separate. An item's owner is the complete verified
application identity, including signing key and provenance. Grants permit reads,
not mutation or deletion. Replacement signing keys require a new grant.

Access requires `keychain.access`. Management additionally requires
`keychain.manage` and the built-in `org.mochios.keychain` identity. Revealing,
deleting other owners' items, granting/revoking access and changing the password
require the vault password again. `LockAll` requires `keychain.session` and the
built-in service-manager identity. The manager waits for READY before login and
waits for key removal before acknowledging screen lock/logout. A confirmed dead
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
  IPC is bounded to 64 KiB, metadata lists are paginated with revision checking.
- Explicit secret, derived-key, KDF working-memory and wire buffers are zeroized;
  their Debug representations never contain secret bytes. UI text rendering is
  not a guarantee that every allocator or display-system copy is erased.
- Mutations publish a complete encrypted candidate through a synced private
  temporary file, atomic rename and parent-directory sync. Memory changes only
  after success. Any storage/integrity error drops that user's cached key;
  uncertain post-rename failures require re-unlocking instead of using stale data.
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
