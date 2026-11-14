# First-login standard applications

After authenticated desktop startup, service-manager starts the built-in
AppStore as a session-scoped, unprivileged process with
`--install-standard-apps`. It does not open a window. No additional service is
introduced, and installer media never starts this worker. Later logins start a
new worker; the device ledger determines whether any work remains.

The fixed order is Terra, Edit, Calendar, Mail and Calculator. The common
`mochios-package-protocol::provisioning` definition contains their package IDs
and the official publisher's developer ID. Order and publisher are bound into
the ledger checksum; changing the policy requires an explicit migration.

## Authority

Only the measured **built-in** `org.mochios.appstore` image from
`org.mochios.system` can query or claim the queue. The broker observes the
active desktop session and POSIX account itself. Neither UID zero, an argument,
a copied application name, an installed Store replacement nor a declared
`package.install` capability is sufficient.

One worker owns a measured-process/session/account lease. A request can renew
that lease, report bounded progress, release it or attach a prepared package
object for approval. Clients cannot report completion.

For automatic approval the broker requires all of the following:

- A current worker lease and unchanged native process/image, session and account.
- A package in the fixed set whose initial setup is not already satisfied.
- An **Install** plan with no installed base record, never Update or Remove.
- The official publisher identity returned by signature.service during capture.

The existing package transaction path remains responsible for source capture,
signature and manifest verification, catalog ID/version/SHA-256 comparison,
resource bounds, payload validation and activation. The broker registers a
normal single-use grant for the exact native plan. At commit, package.service
consumes it and the broker rechecks policy generation, expiration, process,
account, desktop session and provisioning eligibility. Replacing the MPKG or
replaying another application's transaction cannot reuse the grant.

Ordinary installation, update and removal continue to use administrator consent.
The provisioning endpoint cannot perform arbitrary unattended package changes.

## Persistence and removal

The broker stores progress in `/var/lib/security/standard-applications.db`, with
mode `0600`, through its existing recoverable policy-file replacement mechanism.
All directory ancestors and ledger files are checked for root ownership,
unsafe write permissions and symlinks before privileged recovery or writes.
The ledger is shared by local users. No setup status is uploaded to the Store.
Malformed, truncated or incompatible state fails closed instead of resetting
the queue and reinstalling previously removed applications.

Only activated package records satisfy an entry. A successful download or an
installation RPC alone does not mark it complete. Already installed applications
are skipped, including manually installed copies. A normal, approved removal
of a standard application records its setup as satisfied **before** package
removal. This closes the crash window between successful installation,
progress reconciliation and immediate user removal.

## Retry and UI

Release metadata and package bytes use the existing public Store APIs and
network.service HTTPS transport. Each package uses an exclusive, private
random temporary file, bounded chunks and SHA-256 verification. Only one app
is installed at a time; one unavailable release does not block the others.
Failures retry with delays from 30 seconds up to 30 minutes. Incomplete apps
retry after the next login or reboot; interrupted downloads start again from
the beginning rather than claiming byte-range persistence.

The headless process is independent of the Store window. The Installed library
shows device progress and failure reasons using standard ViewKit settings rows,
with polling outside the UI thread. It remains accessible when the remote
catalog is unavailable. Closing the Store window does not cancel setup.

## Validation

Host tests exercise strict protocol decoding, immutable completion, corruption,
interrupted attempts, exclusive leases, expired or changed identities,
untrusted callers, fixed IDs/publisher, write failures, installed packages and
removal across users. Boot orchestration tests verify that worker failure does
not fail login and that installation media excludes it. Actual signed package
installation and session teardown still require a mochiOS runtime test.
