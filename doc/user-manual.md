# SharkTrust Private CA user manual

SharkTrust Private CA (SharkCA) issues private certificates for devices through
the Automatic Certificate Management Environment (ACME) protocol. This manual
guides the portal administrator through setup, everyday use and recovery.
See [current limitations](#current-limitations) before deployment.

Start with [sign-in](#open-the-portal-and-sign-in), then
[create a zone](#create-a-zone-and-configure-https) and
[connect devices](#connect-devices-and-distribute-trust).
Use [administrator accounts](#site-and-zone-administrators) to delegate a zone.
For maintenance, see [CA renewal](#renew-the-ca-root),
[password recovery](#recover-a-forgotten-password),
[email](#configure-email-and-interpret-warnings), and
[backups](#backups-and-current-limitations).

This manual covers browser workflows. Start with the [README](../README.md) to
install the portal. The [operations reference](operations.md) covers server
settings, email, Microsoft setup, recovery commands and diagnostic messages.

### Certificate terms

| Term | Meaning in SharkCA |
| --- | --- |
| Certificate authority (CA) | A signing identity that issues certificates. Each zone has its own CA. |
| Root certificate | The public certificate you install to trust a CA. It contains no private key. |
| Intermediate CA | A CA whose certificate was signed by another CA. Clients need a chain leading to a root they trust. |
| Certificate signing request (CSR) | A public request sent to another CA for signing. The private key stays with SharkCA. |
| Elliptic curve cryptography (ECC) | The public-key algorithm used for SharkCA device certificates and CA keys. |
| Trusted Platform Module (TPM) | The BAS key-management interface used for signing. Mako's software TPM is distinct from a hardware TPM chip. |
| PEM | A text file format for certificates and signing requests. |

## Runtime requirement

Use a Mako binary and resource package that meet the
[runtime requirements](operations.md#runtime-requirements). Updates must preserve
the original TPM identity and saved CA records; do not delete device registrations
to upgrade.

## Open the portal and sign in

Open the portal's configured HTTPS address. If you open its HTTP address,
click **Open this page using HTTPS**. A private HTTPS certificate requires
the portal's CA root to be trusted by your browser.

A new installation needs one administrator username and password. For a
headless installation, the server operator provisions them on the first run
using `mako -credentials "username:password"`. This option does not replace an
existing account. Browser setup is available on localhost if no account has
been provisioned. Follow the [local setup walkthrough](local-testing.md) when
testing from a source checkout.

Use the sidebar to open each section. On a narrow screen, use the menu button.
Sections have their own URLs and support bookmarks and browser Back. Sessions
expire after 30 minutes idle or eight hours total; restarting the portal also
signs out browser sessions.

## Site and zone administrators

The first account is the **site administrator**. It can manage every zone and
portal-wide settings, including the portal HTTPS CA, administration address,
SMTP testing and administrator accounts.

To add a zone administrator:

1. Sign in as the site administrator and open **Administrator** in the sidebar.
2. Under **Zone administrators**, choose **Add zone administrator**.
3. Enter a unique username, select the existing zone they will manage, and set
   their password.
4. Enter your own site administrator password and choose **Save administrator**.
   This signs out all browser sessions. The new administrator can now sign in
   with their own username and password at the portal's login page.

Only the site administrator sees these account-management controls. A username
is a case-sensitive string of 1-64 ASCII letters, digits, underscores, periods
or hyphens. A password is a string of 12-128 bytes. Each account belongs to
exactly one zone; a zone can have several administrators.

A **zone administrator** sees only their zone's devices, certificates, CA,
credentials and activity. They can download its C code, edit its certificate
policy, clean inactive devices, delete their zone, and perform its complete CA
lifecycle. Server-side checks also protect API requests and downloads. They
cannot create zones, assign administrators, manage the portal CA or access
portal-wide diagnostics. Shared HTTPS settings that affect another zone or the
administration hostname require a site administrator. A zone administrator must
ask the site administrator to move or delete a zone supplying Let's Encrypt
HTTPS for the administration hostname.

Both roles can change their own credentials and link a Microsoft account when
SSO is configured. Linking retains the account's existing role and zone; it
does not grant tenant-wide access. One Microsoft identity can be linked to only
one administrator. Sensitive actions require that administrator's local password.

The site administrator can reset or reassign a zone account with **Reset or
reassign**, or remove it with **Delete**. Resetting clears its Microsoft link.
Account changes sign out all browser sessions. Deleting a zone also removes its
administrator accounts. For a lost zone password, contact the site administrator;
command-line recovery is for the site account.

## Separate device trust from portal HTTPS trust

Every zone has its own TPM-backed ECC signing key, CA certificate, serial counter,
pending CSR and rotation history. In **Certificate authority**, a site
administrator selects a zone or **Portal HTTPS CA**. Zone administrators see
only their own CA. **Download root PEM** exports the selected trust root.

Install a zone root on computers and applications that connect to that zone's
devices. Install the separate portal root in browsers and device HTTP clients
only when the portal uses private HTTPS. `/acme/root.pem` supplies the public
portal HTTPS root; zone roots are downloaded through authenticated administration.
Let's Encrypt portal HTTPS needs no private portal root. Do not infer trust from
an unauthenticated download; verify and distribute roots through your provisioning
process. Sharing an external parent CA between zone intermediates also shares
that parent's trust boundary, even though the zone keys remain distinct.

Activity records store the zone ID independently of device records, so deleting
devices or zones preserves attribution. The site administrator can view all
activity or filter by zone. Login/SSO configuration, database/startup failures and
requests with no authenticated zone remain portal-wide. Diagnostic emails go to
the configured site SMTP recipient and include the zone ID (or `portal`), device
IP and observed WAN IP.

## Understand zones and network groups

A zone owns an independent CA, enrollment credentials, administrators and device
certificate policy. A network group determines which devices must have different
names, including across zones. These are separate:
devices in different WAN groups may intentionally receive certificates for the
same `.local` name. A zone does not create public DNS records.

Use **one zone for a local installation**. All devices share the same local
network namespace, so additional zones are unnecessary for this setup. Configure
the default zone created during setup with a portal address its devices can reach.
`localhost` works only on the portal computer.

For a **WAN installation**, give every zone a distinct portal domain, for example:

| Zone | Portal domain | DNS destination |
| --- | --- | --- |
| Zone 1 | `zone1.example.com` | Your VPS public IP address |
| Zone 2 | `zone2.example.com` | The same VPS public IP address |

Create these DNS records with your DNS provider, then enter each domain in its
zone's setup wizard. One Mako instance serves all the domains; you do not need a
separate server or port for each zone. These are portal addresses, separate from
the devices' `.local` names. SharkCA does not create the DNS records.

This is the intended deployment layout. The current UI still permits multiple
local zones and shared WAN hostnames; it does not enforce these restrictions.

WAN installations group devices automatically by their observed WAN address,
independently of the zone's portal domain. A device must be factory
reset before moving it to another network. A reset does not delete its old portal
registration or invalidate an issued certificate.

When a registered device reports a changed WAN address, SharkCA updates the
address for its whole group. There is a race: a new device may register at that
address before an existing group member reports the move. SharkCA can initially
accept a name that conflicts with the arriving group. Once the overlap is
detected, both groups are blocked from further allocation and issuance. They
are not automatically merged or renamed. Ask the operator to resolve the
`network_conflict`; see the [diagnostic guide](operations.md#message-meanings).

## Create a zone and configure HTTPS

For local mode, configure the default zone. For WAN mode, open
**Zones > Create zone** and follow the wizard for each zone:

1. Enter a zone name and a reachable portal address: a domain or IPv4 address
   for local mode, or a distinct domain per zone for WAN mode. Enter the address
   without `https://` or a path. The HTTPS port defaults
   to 443; changing this field does not configure Mako's listeners or routing.
2. Choose **SharkCA (self-signed CA)** or **Let's Encrypt** for the
   portal's HTTPS certificate. Let's Encrypt is recommended for a
   public server such as a VPS, but is optional.
3. Review the settings and choose whether device certificates may include an
   IP address. The allowed IPv4 range is pre-filled with `192.168.1.0/24`, which
   covers addresses from `192.168.1.0` through `192.168.1.255`. Change it to the
   device network you want to permit, or enter several ranges separated by
   commas. These are CIDR (Classless Inter-Domain Routing) ranges. At least one
   range is required when **Include device IP in certificates** is selected;
   the field is ignored when that option is cleared.

For Let's Encrypt, provide the requested contact and terms acceptance, configure
public DNS, and make external HTTP port 80 reach Mako for issuance and renewal.
For private HTTPS, provision the Portal HTTPS CA root on both the administrator's PC
and the device HTTP clients. Trust on the PC does not configure a device.

Check the zone's HTTPS status after saving. **Configure HTTPS** lets you switch
certificate issuers later. The existing working certificate remains active
until its replacement is ready. You can change a zone's address only while it has no
registered devices.

**Portal certificate issuer** controls the HTTPS connection to SharkCA. For
example, `https://portal.mycompany.com` can use a Let's Encrypt certificate that
browsers and device HTTP clients already trust. A device such as `device.local`
still receives a certificate from its zone's private CA, whose root must be
installed wherever that device certificate needs to be trusted. Let's Encrypt
does not sign the zone CA or the device certificates.

The HTTPS choice is in the zone wizard because the zone specifies the portal
address used by its devices. If an existing configuration shares a hostname
between zones, a site administrator must confirm HTTPS changes affecting those
zones together. Use distinct domains when creating new WAN zones. The wizard
changes no DNS, listeners or router settings. Let's Encrypt in this
wizard supports public domain names through HTTP validation, not IP addresses
or DNS validation. Requested domains appear in public certificate transparency
logs. For private HTTPS, domains and IPv4 addresses are supported.

After creation, **Zones > Edit policy** changes the zone name, whether IP
certificates are allowed, and the allowed address ranges. Confirm your
administrator password to save. The changed policy applies to subsequent
issuance; existing certificates retain their original contents and validity.

## Connect devices and distribute trust

On the zone card, choose **Credentials** to view the portal address, zone key,
secret and ACME directory. Confirm the administrator password. The display
clears when closed or after one minute.

Choose **Download C code** to generate `tokengen.c` for an embedded enrollment
identity. This also requires the password. Keep both credentials and generated
code private. See [generated C integration](local-testing.md#zone-c-code-download)
and [Mako client testing](local-testing.md#test-mako-as-a-sharkca-client).

For [Mako's client configuration](https://realtimelogic.com/ba/doc/en/Mako.html#opsharkca),
a requested device name requires an executable with
[`ba.createmdns`](https://realtimelogic.com/ba/doc/en/lua/auxlua.html#mdns).
Mako advertises the portal-assigned `.local`
name automatically and closes the responder on shutdown. Do not also start a
responder for that name in your application. IP-only clients do not require
mDNS. Name resolution stays on the local network; restart Mako after an
interface or address change so its responder uses the new network snapshot.

Export the device and portal roots as described under
[device and portal trust](#separate-device-trust-from-portal-https-trust).

### Connect Xedge

In Xedge, open the three-dot menu and choose **TLS Certificate**. Enable
**Use SharkCA**, then use the compiled zone identity or enable **Custom Portal
Credentials** and enter this zone's portal URL, key, and secret. The SharkCA
switch appears only when the BAS host provides `ba.createmdns`.

For a private HTTPS portal, paste its verified Portal HTTPS CA root into
**Portal CA certificate**. Leave that field empty for a portal using Let's
Encrypt or another already trusted issuer. Enter a device label without
`.local`, or leave it blank for an IP-only certificate if the zone permits it.
Choose **Save**. Email and terms acceptance are not used for SharkCA.

Xedge advertises a named registration through mDNS. Install the zone's device CA
root on computers that connect to Xedge. When Xedge runs in Mako, let Xedge own
certificate management; do not also configure Mako's top-level `acme` table.

## Renew the CA root

Select the intended zone or **Portal HTTPS CA**, then open **CA lifetime and
renewal** to see the expiry and
the earlier **Renew before** date. That date allows for the full device
certificate lifetime. With the default 90-day device lifetime, issuance stops
90 days before the CA expires if the root has not been renewed.

The portal checks CA lifetime at startup and hourly. Warnings appear in
**Activity** and use the configured email service. Renewal requires your action;
the portal cannot install a renewed trust certificate on other machines.

1. Make a current backup using the [operator procedure](operations.md#backup-and-restore-on-the-original-tpm-identity).
2. Choose **Prepare root renewal** and confirm the administrator password.
   This creates a new self-signed certificate for the existing TPM key and CA
   name. The currently active root remains unchanged.
3. Choose **Download renewed root**. Verify its certificate-file SHA-256 against
   the displayed value. Distribute the renewed root to every computer, browser,
   application and device trust store that relies on this CA. This includes
   device HTTP clients only when renewing the Portal HTTPS CA. Follow each trust
   store's replacement procedure and test it before activation.
4. Choose **Activate prepared CA**, acknowledge that trust has been provisioned,
   and confirm the password. Check the new expiry and test a device connection
   and certificate renewal.

The saved preparation survives restart. **Discard prepared CA** removes only that
preparation. Activation keeps the existing key, registrations, accounts, issued
certificates and serial sequence. Existing certificates can be verified with the
renewed root because its key and name are unchanged. The previous public root
is retained in the database history. Portal HTTPS certificates continue their
normal renewal; Let's Encrypt certificates are independent of the private CA.

This operation extends validity; it does not rotate the key or recover a
compromised CA. It requires the original TPM identity. If expiry has already
blocked issuance, the same procedure can restore it while administration remains
reachable. Private portal HTTPS may also have expired, so arrange authenticated
operator access and trust distribution first. Never delete CA state as a repair.

## Prepare an externally signed intermediate

Open **Certificate authority > External intermediate CA**, choose **Create
intermediate CSR**, and confirm the password. **Download intermediate CSR**
exports a certificate signing request for a separate TPM-backed ECC key. The
CSR persists across restarts; repeat downloads return the same request. No
private key is exported, and the active CA remains unchanged.

The external signer must agree to issue a CA certificate permitting your private
device names and addresses. Preserve the portal database and original TPM
identity while the request is being signed.

To install the result:

1. Obtain the signed intermediate certificate and any parent intermediates in
   PEM format, ordered from SharkCA toward the root. Obtain the root certificate
   separately and verify its fingerprint with the CA administrator.
2. Choose **Import signed intermediate**. Select the chain and the independently
   verified root file, approve that root as a trust anchor, and confirm your
   administrator password.
3. SharkCA checks the signatures, CA permissions, chain order, validity, and
   exact match to the pending TPM key. A rejected import leaves the active CA
   unchanged. A successful import creates a prepared candidate.
4. Download the prepared trust root and provision it to browsers and device
   clients. Check the displayed certificate-file SHA-256 fingerprints. These
   fingerprints cover the downloaded PEM file, not the decoded DER certificate.
5. Choose **Activate prepared CA** and confirm the trust-provisioning checkbox
   and password. For a zone CA, new device certificates use the intermediate;
   ACME delivers the intermediate chain with the device certificate. For the
   Portal HTTPS CA, the portal sends that chain with its private HTTPS
   certificate. In either case, clients need the independently trusted root.

The supported profile is deliberately limited: X.509 v3 CA certificates,
P-256/P-384 operational keys, supported ECC/RSA parents, and SHA-256/384/512
signatures. Chains may contain at most eight certificates including the root;
each uploaded PEM file is limited to 60 KB. Certificate-signing permission and
path-length limits must allow the chain. Name constraints, extended key usage,
certificate-policy extensions and unsupported critical extensions are rejected.
Ask the external CA for a compatible profile if import is rejected. No private
key is uploaded or exported, and OpenSSL is not required on the portal.

Validity is limited by the earliest expiry in the entire chain. Startup
revalidates an imported chain. An external CA must sign future intermediate
renewals: create another CSR and repeat this process. SharkCA cannot extend a
parent CA's validity itself.

## Rotate the CA key

Choose **Prepare new root key** to generate a separate TPM-backed key and root.
Preparation does not change the active CA. Download and distribute its trust
root before choosing **Activate prepared CA**. The preparation survives restart;
**Discard prepared CA** abandons it without changing the active issuer.

Only the selected CA changes. Activation preserves registrations, ACME accounts,
zones, issued certificates and audit history. A new issuer gets its own serial
sequence; unfinished signing operations under the old issuer are invalidated
and clients can submit a new order. Activation does not force existing devices
to renew immediately. Keep both old and new roots trusted until old certificates
have been replaced or expired. **Previous authorities** lets you download earlier
trust roots. For a compromised key, follow the compromise procedure instead of
retaining trust in that key.

Private portal HTTPS changes only when activating the Portal HTTPS CA. Install the
new trust in the administration browser first or the next request may report a
certificate warning. Let's Encrypt portal certificates remain independent.

## Inspect and maintain the portal

### Find a device on your network

Open **Available Devices** in the left menu. No portal sign-in is required.
Select a device name to open its HTTPS interface in a new tab. Named devices
use `https://name.local/`; IP-only devices use their registered IPv4 address.
The device may still require its own sign-in. Your browser must trust the
device's zone CA, and `.local` links require working mDNS on your network.

The list includes registrations for the portal address you are visiting. On a
cloud installation, it matches your connection's WAN address to the devices'
current network group. VPNs or a different internet connection may therefore
show an empty list. Networks sharing one public address, such as carrier-grade
NAT, cannot be distinguished this way. On a local installation, it shows the
shared local group. Groups with unresolved network conflicts are omitted.
This is a registration list, not an online-status check. It exposes only device
names and local IP addresses, up to 200 entries, without management controls.

### Manage registrations

**Overview** shows issuer readiness and totals. **All devices** shows registered
identities and network information. **Certificates** shows issued certificates.
**Activity** shows audit events and warnings with device and observed WAN IPs.
List views show at most 200 recent records; totals cover all records.

To remove one device, open **All devices**, find its name and IP address, and select
**Delete**. Check the device and WAN addresses in the confirmation, then select
**Delete device**. Site administrators can remove any device; zone
administrators can remove only devices in their own zone. Deletion frees the
name, disables the old device credential and cancels unfinished certificate
requests. It retains issued certificates and activity history. It does not
revoke certificates or block fresh enrollment using the zone credentials.

**Clean inactive devices** previews registrations for removal. Review the list
and acknowledge before confirming. Devices that reconnect after the preview
are preserved. **Delete zone** previews the zone's registrations and requires
confirmation. These actions do not revoke issued certificates; certificate and
audit history remain. Other zones and the CA are retained.

## Manage your administrator account

Use **Administrator** to change the username and password, supplying the
current password. Successful changes sign out every portal session. The
[account rules](#site-and-zone-administrators) apply to both new and changed
credentials.

Microsoft sign-in is optional. After the server operator configures Entra,
sign in with the local password and open **Administrator > Microsoft sign-in**.
Choose **Link Microsoft account**, confirm the password, and complete Microsoft
sign-in. If an account is already linked, the button instead says **Replace
linked account**. **Unlink Microsoft account** removes that association.

After linking, sign out and choose **Sign in with Microsoft** on the login
page. The linked identity receives only that administrator's existing access.
Keep your local password: viewing credentials, downloading C code and other sensitive actions
still require it. See [Microsoft configuration and account linking](operations.md#microsoft-administrator-sign-in).

## Recover a forgotten password

For a zone account, ask the site administrator to use **Administrator > Reset
or reassign**. For the site account, ask the server operator to perform
[command-line recovery](operations.md#recover-a-forgotten-password).
Neither requires the lost password. Both preserve CA and device state and clear
the affected account's Microsoft link, which can be recreated after signing in
with the replacement password.

There is no browser **Forgot password** flow or email reset link. Microsoft
sign-in does not bypass password confirmation for sensitive actions or allow
resetting the local password. Do not delete the database to regain access.

## Configure email and interpret warnings

The server operator can [configure and test email](operations.md#optional-email-notifications).
Zone administrators cannot change or test the site's email configuration.

Consult [message meanings](operations.md#message-meanings) before changing
settings. For example, `unknown_portal` means a request used an unconfigured
address and was rejected before device identification. An isolated external
request needs no action when your devices work normally. A known failing
client needs its portal address checked.

The [message guide](operations.md#message-meanings) distinguishes automatic
retries, faults needing your attention, and events recorded only in Activity.

## Respond to a compromise

SharkCA protects CA keys through the BAS TPM API instead of storing an exported
private key in a file or database. The portal stores public certificates and key
descriptors and requests signing through TPM handles. Copying the portal database
alone therefore does not expose a stored CA private key. This reduces the risk
of key theft compared with keeping an ordinary private-key file on the server.

Mako and Xedge provide a software TPM (softTPM), distinct from a hardware TPM
chip. Protection depends on the host and its TPM configuration. An attacker who
controls the running server may still request unauthorized signatures without
exporting the key, so the recovery procedure below remains necessary.

If the CA or its issued certificates can no longer be trusted:

1. Remove the SharkCA CA certificate from the certificate stores of every
   computer, browser and device that trusts it, including application-specific
   trust stores.
2. Open **Zones**, select **Delete zone** for the affected zone, review the
   registrations and confirm deletion.

Deleting a zone removes its enrollment credentials and registrations and stops
further issuance for that zone. It does not make existing certificates invalid
on computers that still trust the CA. Removing the CA is what withdraws that
trust. With independently rooted zones, removing one zone root does not remove
trust in other zones. If the portal host or its TPM identity is compromised,
assess every key it controls, including the portal HTTPS key.

SharkCA does not provide certificate revocation lists (CRLs) or Online Certificate
Status Protocol (OCSP) services. Trust-store removal is an administrator action;
the portal cannot perform it remotely. Do not reinstall a compromised CA to
restore connectivity.

## Backups and current limitations

Follow the [backup and restore procedure](operations.md#backup-and-restore-on-the-original-tpm-identity).
Preserve the database, configuration and original TPM identity together. Do not
restore an older serial/certificate state after additional issuance under the
same CA.

### Current limitations

The portal has one site administrator and accounts assigned to individual zones.
Sensitive actions require the local password; email verification is not part of
this product scope.
Certificate revocation services are out of scope. Zone deletion and device
cleanup must not be treated as certificate revocation.
