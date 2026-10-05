# Operating SharkTrust Private CA

Use this reference to configure and maintain the portal host. For browser tasks,
see the [user manual](user-manual.md); for the first start, see the
[README](../README.md#start-the-portal).

## Runtime requirements

Use a Mako executable and matching `mako.zip` with TPM key creation, CSR creation
and [certificate signing with explicit CA/server profiles](https://realtimelogic.com/ba/doc/en/lua/auxlua.html#ba_tpm_createcertificate).
Signed-intermediate import also requires the CA-chain validation form of
[`ba.parsecert`](https://realtimelogic.com/ba/doc/en/lua/auxlua.html#ba_parsecert).
Older runtimes without these APIs cannot perform these operations. Update the
binary and resources together, preserving the original TPM identity.

SharkCA uses ECC keys and certificates. It can validate supported RSA parent
CAs when importing an intermediate, but does not issue RSA device certificates.
OpenSSL is not required on the portal host.

## Portal configuration

Keep `mako.conf` beside the portal's `www/` directory, outside Git and application
ZIPs. It is a Lua file, loaded when Mako starts. Restart Mako after editing it.
The minimal configuration is the `apps` table in the [README](../README.md#start-the-portal).

The optional top-level `sharkca` table configures the **portal**. The separate
[`acme.sharkca` table](https://realtimelogic.com/ba/doc/en/Mako.html#opsharkca)
configures a **device client**; do not add it to this portal configuration.

For example, to issue device certificates lasting six days:

```lua
-- Portal settings. Keep one sharkca table and merge other options into it.
sharkca = {
   ca = {leafLifetime=6*24*60*60} -- Seconds; omitted fields use their defaults.
}
```

| Field | Type and default | Meaning |
| --- | --- | --- |
| `networkMode` | Optional string: `"wan"` or `"local"`; new database default `"wan"`. | Use one zone for local mode. For WAN, use a distinct portal domain per zone, all pointing to the same public VPS; devices are grouped by their observed public address (the Network's WAN address). Browser setup lets you choose the mode. An explicit value must match an existing database's saved mode. |
| `notifications` | Optional boolean; `false`. | Set `true` to email diagnostics. Requires the [`log` table](#optional-email-notifications). Activity is recorded either way. |
| `ca` | Optional table; defaults below. | Certificate policy, shared across the portal's independently keyed CAs. |
| `ca.curve` | Optional string; `"P-256"`. | Also accepts `"P-384"`. Must match existing issuers: changing it prevents them from loading, rather than rotating their keys. |
| `ca.commonName` | Optional string, 1-48 bytes; `"SharkTrust Private CA"`. | Base name for new zone roots; SharkCA adds a zone suffix. Does not rename existing CAs. |
| `ca.rootLifetime` | Optional integer seconds; `315360000` (3650 days). | Validity of newly created or prepared replacement roots. No portal-imposed maximum. |
| `ca.leafLifetime` | Optional integer seconds; `7776000` (90 days), maximum `31536000` (365 days). | Validity of new device certificates and private portal HTTPS certificates, subject to issuer expiry. |

Both lifetimes must be whole seconds and at least `3600`. Only the device
certificate lifetime is capped at `31536000` seconds (365 days). For a 100-year CA,
set `ca.rootLifetime=100*365*24*60*60` in the portal's `sharkca` table.
The runtime and clients must support the resulting expiry date. The root
lifetime must exceed the leaf lifetime by more than 300 seconds.
Changing a value does not
change certificates already issued or force devices to renew immediately.
Clients schedule renewal using the actual issued validity period. Shorter
lifetimes require more frequent successful connections to the portal.

The 365-day maximum is SharkCA policy for private certificates. Browser rules
for publicly trusted certificates are separate; for example,
[Chrome's root policy excludes locally trusted private CAs](https://www.chromium.org/Home/chromium-security/root-ca-policy/).

Configure portal addresses, zones, credentials, IP policy and the portal HTTPS
issuer in the UI. These settings persist in the database and are not read from
`mako.conf`.

### Mako listeners and storage

These optional settings are top-level fields, outside `sharkca`:

| Field | Type and default | Use |
| --- | --- | --- |
| `port`, `sslport` | Integer; `80`, `443`. | HTTP and HTTPS listen ports. `0` disables a listener. Check startup output: Mako may choose alternate ports if defaults are unavailable. |
| `host`, `sslhost` | String; omitted means all interfaces. | Bind HTTP or HTTPS to a specific interface address. |
| `certfile`, `keyfile` | String paths, or matching tables of paths; omitted uses Mako's initial identity. | Supply the bootstrap certificate chain and key before SharkCA installs its managed HTTPS certificates. |
| `homeio` | String path; execution directory. | Mako's writable home. Use an absolute path for a service. |
| `dbdir` | String path; normally the configuration directory. | Parent of the `data/` directory, not the database filename. |

See the [Mako configuration reference](https://realtimelogic.com/ba/doc/en/Mako.html#cfgfile)
for host options. Zone addresses and HTTPS ports do not open listeners or
configure DNS, firewalls or forwarding. Let's Encrypt portal HTTPS requires
external HTTP port 80 to reach Mako for issuance and renewal.

The database is normally `data/sharkca.sqlite.db` next to `mako.conf`.
If the selected location is unavailable, sqlutil tries other locations; see
[database directory selection](https://realtimelogic.com/ba/doc/en/Mako.html#sqlutil).
Let's Encrypt state is stored in `sharkca-https/` under Mako's writable home.
Changing paths does not move existing state. Back up both locations and the
original TPM identity using the [backup procedure](#backup-and-restore-on-the-original-tpm-identity).

## Headless installation

Create `mako.conf` as shown in the README, then run Mako with
`-credentials "username:password"` on the first start. This creates the site
account before administration opens and never overwrites an existing account.
Use a case-sensitive username of 1-64 ASCII letters, digits, underscores,
periods or hyphens, and a password of 12-128 bytes. Only the first colon separates
the username from the password. Quote the argument for your shell.

Open the intended HTTPS address and sign in. The first successful login saves
that administration address; no `origin` setting is needed. The initial
certificate may need explicit browser trust before the managed certificate is
ready. WAN mode is the default. For a local headless installation, add
`sharkca={networkMode="local"}` before the first start, or add that field to your
existing `sharkca` table. Local mode creates a default zone on first login.

Restart normally after setup. Do not retain the credentials argument in service
commands: operating-system tools may expose process arguments to privileged
users. For an existing account, use [password recovery](#recover-a-forgotten-password).

## Administrator access

Use the manual's [account procedures](user-manual.md#manage-your-administrator-account)
for credential changes and zone delegation.

The site administrator can move the administration address to a configured zone address with an installed HTTPS certificate. Verify routing and browser trust at that address first. Confirm the password, then sign in at the new address. Sessions are invalidated. The old address remains accepted only if a zone still uses it. Device enrollment URLs remain unchanged. This operation does not configure DNS, listeners or forwarding.

## Recover a forgotten password

This procedure recovers the site administrator. For a zone administrator, use
**Administrator > Reset or reassign** while signed in as the site administrator.

Recovery requires operating-system access to the portal host, its existing
configuration and its original TPM identity. The old administrator password is
not required. There is no browser or email password-reset flow. Microsoft
sign-in cannot replace the local-password check for sensitive actions.

On a Linux installation using `/opt/SharkCA` and `SharkCA.service`:

```bash
# Stop the service before opening its database from a foreground process.
sudo systemctl stop SharkCA
cd /opt/SharkCA
sudo /usr/local/bin/mako -reset-credentials 'my-admin-user:my-password'
```

Replace the example username and password with the intended credentials.
Wait for **Administration available** in the startup log, then verify that
the replacement credentials let you sign in. Press Ctrl+C to stop the foreground
process before resuming normal service:

```bash
# Resume with the ordinary service command, without the recovery option.
sudo systemctl start SharkCA
sudo systemctl is-active SharkCA
```

On Windows, stop the running Mako instance or service, open CMD in its normal
working directory, and run:

```cmd
rem Use the same executable, configuration and state as the normal installation.
mako -reset-credentials "admin:REPLACE_WITH_A_NEW_PASSWORD"
```

After confirming startup and sign-in, stop that foreground instance and restart
normally without the option. Only the first colon separates the username from
the password; the username/password limits above apply. Shell quoting also
applies to the command. Do not retain the recovery option in startup scripts or
service commands.

Recovery replaces the administrator credentials and clears the linked Microsoft
identity. Link it again from **Administrator** after signing in. The CA, zones,
devices and certificate history are preserved. Restart invalidates browser
sessions. This option requires an existing administrator; `-credentials` is for
first-install provisioning and does not overwrite an account. Never delete the
database for password recovery.

## Microsoft administrator sign-in

Microsoft Entra ID sign-in is optional. It provides another way to authenticate
an existing site or zone administrator; it preserves their assigned role and
does not grant access to everyone in a tenant. The local password remains necessary for
sensitive operations and recovery.

Register an Entra **Web** application redirect URI matching the portal exactly,
including any nondefault port: `https://<portal-address>/ms-sso.lsp`. Add the
following table to the private `mako.conf`, then restart Mako:

```lua
-- Use this portal's exact HTTPS address and the secret Value, not its ID.
openid = {
   tenant="YOUR_TENANT_ID",
   client_id="YOUR_APPLICATION_ID",
   client_secret="YOUR_CLIENT_SECRET_VALUE",
   client_secret_expires="2028-08-01", -- Replace with the actual Entra expiry date.
   redirect_uri="https://ca.example.com/ms-sso.lsp",
   alert_days={1,7,14,30,60} -- Optional reminder thresholds, in days.
}
```

`tenant`, `client_id`, `client_secret` and `redirect_uri` are required strings
when the optional `openid` table is present; there are no default
values. `client_secret_expires` is an optional string with a `YYYY-MM-DD` UTC expiration date;
omit it only when unknown. Without a supplied date, expiry reminders are
disabled. Copy the actual date from Entra rather than the example. Credentials
stay in host configuration, outside the application ZIP and Git.
`alert_days` is an optional table of positive numbers, default `{1,7,14,30,60}`;
email reminders also require notifications and SMTP configuration.

Follow the [account-linking steps](user-manual.md#manage-your-administrator-account).
The login-page button is hidden until an identity has been linked. SharkCA saves
the verified tenant ID and object ID, not an email address, as the authorized
identity in the TPM-encrypted administrator record.

Linking or replacing an identity invalidates existing portal sessions. Linking
requires a one-use password grant valid for two minutes; completing Microsoft
sign-in must take no more than ten minutes. Signing out, restarting the portal,
changing credentials or moving the administration address cancels unfinished
link operations. Linked identity settings survive restart and normal password
changes. **Unlink Microsoft account** requires the local password and revokes
all portal sessions. Command-line credential recovery also clears the link.

The shared SSO module verifies the ID-token signature, issuer, tenant, audience,
nonce and time limits, and uses authorization-code flow with PKCE. The redirect
must match the current browser origin. When moving administration, update the
registered redirect URI and `openid.redirect_uri` as well.

Replace an expired or invalid client secret in `mako.conf`, update its expiration
date and restart the portal. The local-password sign-in continues to work when
Microsoft sign-in is unavailable. The portal does not offer browser-based
client-secret rotation.

## Optional email notifications

Diagnostics appear in **Activity** even when email is disabled. To send diagnostic batches, set optional boolean `sharkca.notifications` to `true` and configure Mako's existing SMTP logging options. The default is `false`; enabling it requires a `log` configuration table.

For example, merge the following settings into the private `mako.conf`. Do not include that file in the application ZIP or source control:

```lua
-- SMTP credentials stay on the portal host. Use your actual mail provider settings.
sharkca = {notifications=true} -- Merge into an existing sharkca table, if present.
log = {
   smtp = {
      server="smtp.example.com", port=587,
      from="sharkca@example.com", to="operator@example.com",
      useauth=true, user="sharkca@example.com",
      password="REPLACE_WITH_SMTP_PASSWORD", consec="starttls"
   }
}
```

`log` and `log.smtp` are tables. Within `smtp`, `server`, `from` and `to` are
required strings, and `port` is a required integer. With boolean `useauth=true`,
`user` and `password` are required strings. Set string `consec="starttls"` for
port 587, or `"tls"` for port 465, as required by your provider. The current Mako
mail module applies these TLS settings when authentication is enabled.

For optional subjects, signatures and logging controls, see
[Mako email configuration](https://realtimelogic.com/ba/doc/en/Mako.html#oplog).
Mako's log-buffer limits do not control SharkCA's diagnostic batches.
As site administrator, use **Activity > Send test email**, confirm your password
and check the inbox. SMTP acceptance alone does not prove delivery.

Each diagnostic contains a stable event code, UTC time, occurrence count, zone ID (or `portal`), device IP and observed WAN/peer IP. Missing addresses are shown as `unknown`. A local portal's observed peer can be a LAN address. Authenticated device/account records supply the local IP when a request omits it. Request proofs, enrollment secrets, passwords, raw request bodies and private keys are excluded.

Repeated events with the same zone, code and addresses are combined within each collection batch. Collection runs every five seconds. Automatic email batches contain up to 50 stored records, at least 60 seconds apart after success; failures are retried after 300 seconds. The explicit test action can trigger an earlier retry. Delivery status is `disabled`, `activity_only`, `pending`, `sent` or `failed`. Pending/failed records survive restart. SMTP work runs separately from database transactions and certificate signing.

Unconfigured portal addresses (`unknown_portal`) and unsolicited SSO rejections
(`sso_request_rejected`) remain in Activity and the server log with status
`activity_only`. They are excluded from automatic and test emails. Failures
tied to an authenticated administrator or a server-held sign-in flow use
`sso_signin_rejected` and remain eligible for email. Provider validation and
credential-expiry alerts also remain eligible.

The diagnostic buffer holds 128 distinct events; storage keeps the latest 1,000
records and the UI shows 200. Sustained failures can overflow this history before
email delivery. Shutdown can lose up to five seconds of buffered events, and a
restart after SMTP acceptance can cause a duplicate email. Treat this as an
operational warning feed. Issuance and administrative audit records are separate.

## Message meanings

| Message | Meaning and action |
| --- | --- |
| `name_unavailable` | The name is already used in this device's network group. Select another name or use the client's increment policy. The same name in a different WAN group is intentional and does not cause this message. |
| `network_conflict` | A WAN transition overlaps saved groups. Issuance/allocation is blocked for affected groups. Operator reconciliation is required; the portal does not silently merge groups or rename devices. |
| `invalid_credentials`, `credential_conflict`, `account_mismatch`, `account_in_use` | Enrollment or account identity does not match the saved association. Check the selected portal, zone credentials and device state. Retrying unchanged configuration does not repair the mismatch. |
| `address_not_allowed`, `invalid_ip_address`, `name_required`, `invalid_name` | The supplied identity violates the zone policy or input format. Correct the client address/name or intended policy. |
| `unknown_portal` | Activity/log only, no email. A request used an unconfigured portal hostname or address and was rejected before device identification. Internet scans or a misconfigured client can cause this; `device IP=unknown` is expected at this stage. No action is needed for isolated requests when devices work normally. For a known failing client, correct its URL or the zone address. Retrying the same incorrect address does not fix it. |
| `zone_portal_mismatch` | The requested address does not belong to the selected zone. Correct the client URL or zone address. |
| `sso_request_rejected` | Activity/log only, no email. An SSO request had no authenticated administrator or matching server-held sign-in flow, or used an unconfigured address. Internet probes, old bookmarks and callbacks after a server restart can cause this. No action is needed for unsolicited requests. If you were signing in, return to the configured portal and start again. |
| `sso_signin_rejected` | A sign-in flow or authenticated administrator request could not complete Microsoft sign-in. An unlinked account, expired transaction, cancellation or invalid identity response can cause this. Start again, using the linked account. Use the local password to link or replace an account. These failures remain eligible for email. |
| `sso_validation_failed` | The SSO provider module reported a discovery or token-validation failure. Discovery retries automatically; retry sign-in after recovery. If persistent, check outbound trusted HTTPS and the Entra configuration. This background diagnostic may have no caller address. |
| `sso_credential_expiring`, `sso_credential_expired`, `sso_credential_invalid` | Replace the Entra client secret and its expiration date in private configuration, then restart. A reminder uses the supplied expiration date; it does not extend the credential. Local-password access remains available. |
| `unsupported_command`, `invalid_account_binding` | The request does not match the SharkCA profile. Check the client's version and SharkCA configuration. |
| `invalid_json`, `body_too_large`, `unsupported_media_type`, `method_not_allowed`, `tls_required` | A malformed or unsupported protocol request was rejected. A single event may be an unrelated probe; persistent events from a known device require client correction. |
| `rate_limited`, `ACME rateLimited` | A request/enrollment limit was reached. Short-term limits clear with their window. A capacity limit requires operator action. |
| `ACME badNonce` | An expired, reused or unknown nonce was rejected. A conforming client obtains a new nonce and retries automatically. Persistent events merit investigation. |
| Other `ACME ...` errors | The suffix is the standard ACME problem type. The client receives the specific problem detail. Invalid CSR, account, signature or identifier requests require correction; transient server errors can be retried. |
| `issuer_initialization_failed`, `issuer_unavailable` | The CA could not be restored or is not ready. Inspect the startup log and original TPM identity. Do not delete state or substitute a new root as a repair. |
| `ca_expiring_N_days` | The active CA has entered a warning window of 365, 180, 90, 30, 7 or 1 days. Prepare and distribute a renewed root before the displayed issuance cutoff. Renewal is not automatic. Only the most urgent applicable window is reported. |
| `ca_issuance_blocked` | The remaining CA lifetime is shorter than the configured device certificate lifetime. New issuance is blocked. Complete root renewal and provisioning; existing certificates are unaffected until their validity/trust expires. |
| `ca_expired` | The CA expiry has been reached. Complete root renewal with the original TPM identity and provision the renewed trust certificate. Access through private portal HTTPS may require operator recovery. |
| `portal_https_issuance_failed`, `portal_https_renewal_failed`, `portal_https_installation_failed` | Portal HTTPS could not be issued, renewed or installed. The existing certificate is retained. Check the zone's HTTPS status, DNS, public port 80 and CA response. Retry is automatic, but configuration faults require correction before expiry. |
| `notification_test` | An administrator requested a delivery test. No device action is needed. |
| `notification_delivery_failed` | Local log: SMTP delivery failed. Pending diagnostics remain eligible for retry. Check SMTP configuration/connectivity; certificate issuance continues independently. |
| `alert_storage_failed` | Local log: a diagnostic batch could not be saved. A bounded in-memory retry is attempted. Check storage availability. |

## CA lifetime settings and persistence

Use the [configuration table](#portal-configuration) for lifetime values and the
[manual's CA procedures](user-manual.md#renew-the-ca-root) to prepare, distribute
and activate replacements. Editing a lifetime does not replace an active CA.

The lifetime monitor runs at startup and hourly. A persisted marker prevents
repeating the same warning window after a restart. Issuance-blocked and expired
warnings take precedence over day-count warnings. Diagnostics use the existing
Activity/SMTP batching; CA-wide warnings have unknown device/WAN addresses.
The manual's **Renew before** date is CA expiry minus leaf lifetime.

Pending renewals, intermediate CSRs and key descriptors are included in the
database backup. Use the UI to manage them, not direct database edits. Displayed
SHA-256 values hash the exact PEM file bytes. In Windows CMD, compare a downloaded
file with `certutil -hashfile SharkCA-prepared-root.cer SHA256`.

## Capacity limits

These current implementation limits are portal-wide and are not `mako.conf`
options:

| Resource | Limit |
| --- | --- |
| Retained orders | 32,768; an unfinished order expires after 900 seconds. |
| ACME nonces | 4,096 outstanding one-use values, valid for 300 seconds. |
| Requests | 300 per minute per observed peer, for each protocol handler. |
| Failed SharkTrust authentications | 10 per minute per observed peer. |

Registered devices and ACME accounts have no fixed count limit. Practical
capacity depends on the host's storage and workload.
Deleting registrations does not clear account, order or certificate history.
If a capacity limit is reached, contact the portal maintainer rather than
deleting database rows. Short-term request limits clear with their time window.

## Backup and restore on the original TPM identity

Keep the original host/TPM identity together with a protected backup of:

- The SQLite database and any SQLite journal/WAL files in its data directory.
- `mako.conf` and the complete writable Mako home, including `sharkca-https/` public ACME state, TPM descriptors and saved listener state.
- The exact portal package, Mako resource package, executable version and launch configuration needed to reproduce the installation.

Private signing keys remain in the TPM. Copying database records and descriptors alone does not transfer a hardware TPM key or reproduce another host's TPM identity. Restore on the original identity; restoring to different machine is not possible.

When rebuilding Mako, preserve the original encryption-key header selection and
other TPM inputs. Building on the same machine is not enough if the build selects
a different embedded key. Keep the original key material private and retain
the build settings with the backup.
Before replacing an executable, check that the candidate reproduces the saved
CA public key on the target host. Stop the upgrade if it reports an identity
mismatch. Do not reset the database or generate another CA to bypass it.

For a stopped-snapshot restore:

1. Stop the portal and verify that no second process uses its database or CA.
2. Copy the complete state to an access-controlled backup location. Preserve configuration paths and file permissions.
3. Restore that stopped snapshot without allowing intervening issuance. Keep the pre-restore state separately until validation succeeds.
4. Start with the original TPM identity. Verify administrator login, exact root fingerprint, registered devices, certificates and the issuer serial counter.
5. Verify a real issuance/renewal, retained device key and trusted TLS connection before normal operation resumes.

**Do not roll back to an older live backup under the same issuer after additional certificates have been issued.** The current serial counter and issued-certificate history must not be rolled back. Recovery after loss of newer state needs reconciliation or a supported issuer transition; do not attempt it by simply restoring the older database. A stopped backup restores only on the original TPM identity. Loss of that identity requires a new CA and redistribution of trust; rotation cannot recover a lost private key.
