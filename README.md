# SharkTrust Private CA

SharkTrust Private CA (SharkCA) gives devices on private networks HTTPS
certificates for names such as `controller.local`, local IPv4 addresses, or
both. Mako and Xedge clients enroll and renew automatically through the
Automatic Certificate Management Environment (ACME) protocol.

Each enrollment zone has its own certificate authority (CA), credentials and
device policy. A site administrator manages the portal and can delegate zones
to zone administrators. Devices on separate WAN network groups can use the same
`.local` name. SharkCA does not provide DNS services; named devices use
multicast DNS (mDNS) on their local network.

**Private certificates need trust installed on the computers that use them.**
The portal itself can use Let's Encrypt for browser-trusted HTTPS, but device
certificates are always signed by the zone's private CA.

## Start the portal

Use a current [Mako Server](https://makoserver.net/) executable and matching
`mako.zip`, with the TPM certificate-signing APIs described under
[runtime requirements](doc/operations.md#runtime-requirements).

Create a private `mako.conf` in this repository's root directory:

```lua
-- Load the portal at / from the source directory beside this configuration.
apps={{name="",path="www"}}
```

`apps` is Mako's application list. The string `name=""` selects the site root;
the string `path="www"` selects the portal directory. No priority setting is
needed.

Run `mako` from that directory and open [https://localhost/](https://localhost/).
Create the site administrator account and choose local or WAN network grouping.
Use one zone for a local installation; setup creates it automatically. For WAN,
create each zone with a distinct portal domain, such as `zone1.example.com` and
`zone2.example.com`, with all domains pointing to the same VPS. See
[zones and network groups](doc/user-manual.md#understand-zones-and-network-groups).
The initial
HTTPS certificate may cause a browser warning until you configure the portal
address and trust its certificate. Follow the
[HTTPS setup guide](doc/user-manual.md#create-a-zone-and-configure-https).

For a remote installation, create the account on the first run:

```sh
# Replace both values. The password must contain 12-128 bytes.
mako -credentials "my-admin-name:REPLACE_WITH_A_STRONG_PASSWORD"
```

This protects setup before remote visitors can reach it. Sign in at the portal's
HTTPS address, then restart without the credentials argument. See
[headless installation](doc/operations.md#headless-installation) for details.
Do not also pass `-l::www` when `apps` already loads the portal.

## Connect devices

Create a zone in **Zones**, then use **Credentials** or **Download C code** to
configure its devices. Import the zone's root certificate on computers and
applications that will connect to those devices.

Mako devices use the
[`acme.sharkca` client settings](https://realtimelogic.com/ba/doc/en/Mako.html#opsharkca).
These belong in the **device's** `mako.conf`. The portal's optional `sharkca`
table instead controls CA policy and notifications. See
[portal configuration](doc/operations.md#portal-configuration) for those settings.
The Xedge UI exposes **Use SharkCA** when its BAS host provides mDNS support; see
[Connect Xedge](doc/user-manual.md#connect-xedge).

## Administration and maintenance

Use **Certificate authority** to renew a root, rotate its key, or import an
externally signed intermediate. Signing uses the Barracuda App Server (BAS)
Trusted Platform Module (TPM) interface; Mako's software TPM is not a hardware
TPM chip. However, backups must be restored on the same hardware.

Device certificates default to 90 days. You can choose a shorter lifetime in
`mako.conf`, such as six days. Short lifetimes limit how long an issued
certificate remains valid; they do not revoke it. If a CA is compromised,
[remove its trust and delete the affected zone](doc/user-manual.md#respond-to-a-compromise).

| Guide | Use it for |
| --- | --- |
| [User manual](doc/user-manual.md) | Zones, administrator accounts, device setup and CA maintenance. |
| [Operations reference](doc/operations.md) | Configuration, email, Microsoft sign-in, password recovery and backups. |
| [Installation checks](doc/local-testing.md) | Verify browser trust, device enrollment and restart behavior. |
