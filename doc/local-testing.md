# Check your SharkCA installation

Use these checks after configuring the portal. The [user manual](user-manual.md)
describes first-time setup, administrator accounts and normal operation.

## Start and open the portal

Follow the [README setup](../README.md#start-the-portal), then open the configured
HTTPS address. Check the startup log for **SharkCA: Administration available**
and, after setup, **SharkCA: Ready (TPM issuer)**. Do not start a second process
against the same database.

## Browser walkthrough

1. Sign in and check **Overview** for issuer readiness.
2. Open **Zones** and check the address, certificate policy and HTTPS status.
   Use one zone locally. For WAN, verify that every zone has its own portal
   domain and that all those domains resolve to the same VPS. Open each domain
   and check that it serves the expected HTTPS certificate.
3. Open **Certificate authority**, select the intended zone and download its
   trust root. Provision it on clients that will connect to the devices.
4. Connect a device and check **All devices**, **Certificates** and **Activity**.
5. Sign out and open **Available Devices** from the device's network. Select
   its HTTPS link and check that its interface opens with the expected trust.
6. Restart Mako and check that the administrator, zones, registrations and CA
   fingerprint remain unchanged. Browser sessions require a new sign-in.

## Choose portal HTTPS

Follow the [HTTPS wizard](user-manual.md#create-a-zone-and-configure-https), then
refresh **Zones** and check that the certificate is installed. Open the exact
configured address and inspect its certificate in the browser. Verify the name,
issuer and expiry. For private HTTPS, provision the Portal HTTPS CA root in both
the browser and the device HTTP client's trust store. For Let's Encrypt, also
confirm that public HTTP port 80 remains reachable for renewals.

## Windows browser trust

1. Open **Certificate authority**, select **Portal HTTPS CA**, then **Download root PEM** to trust the private web interface. Select a zone instead to trust that zone's devices. These are separate public certificates.
2. Open that file and choose **Install Certificate**. For trust limited to your Windows account, choose **Current User**.
3. Choose **Place all certificates in the following store**, then select **Trusted Root Certification Authorities** and complete the wizard.
4. Close/reopen the browser if necessary and visit the exact configured domain or IP. A browser using a separate certificate store needs the CA imported there instead.

You can also import through `certmgr.msc` under **Trusted Root Certification Authorities > Certificates > All Tasks > Import**. The CA private key is never exported. You make this trust-store change explicitly. Installing this root makes certificates issued by this private CA trusted for your account; downloading it alone does not.

SharkCA manages certificates for the current administrator and zone addresses.
Hostnames using Let's Encrypt receive their public certificates through TLS
Server Name Indication (SNI); the private certificate is the fallback for other
configured addresses and IP access. An IP address must appear in the certificate
as an IP Subject Alternative Name (SAN). Inspect the certificate at the address
you will actually use, rather than assuming every address gets the same one.

After changing a CA, provision its new root through the
[CA lifecycle procedure](user-manual.md#renew-the-ca-root).

## Test Mako as a SharkCA client

Run the client from its own directory and configuration. If the portal and
client share a computer, assign different HTTP and HTTPS listener ports to
avoid a port conflict. Configure the client's `acme.sharkca` settings using
the portal address and zone credentials shown under **Zones > Credentials**.
An embedded identity may supply the zone key and proof instead of explicit
credentials. Follow the
[Mako client configuration reference](https://realtimelogic.com/ba/doc/en/Mako.html#opsharkca).

For a private portal HTTPS certificate, supply its verified CA root through
the optional string `acme.sharkca.caFile` setting, a PEM file path relative to
Mako's home directory. By default it is omitted, using Mako's bundled trust.
Omit this setting when the portal uses a
publicly trusted issuer such as Let's Encrypt. This is separate from trusting
the zone CA that signs device certificates. Supplying the file replaces the
shared ACME client's default roots; it does not merge them. Provision the root
through a trusted path, not an unverified automatic download.

A named device requires a Mako executable with `ba.createmdns` support. Mako
advertises its assigned `.local` name automatically. After enrollment, check
the name and IP under **All devices**, then open the device using HTTPS.
Restart the client and confirm that its existing registration and certificate
are reused. Do not delete its persistent ACME state as a routine check.

## Zone C-code download

Select **Zones > Download C code** and confirm your administrator password.
The generated `tokengen.c` includes build instructions, the selected zone's
enrollment identity and its portal address. It supports an embedded `etokengen`
module or a Mako `tokengen` shared library. Its secret is obfuscated, not
encrypted. Keep the file and its compiled module private.
Regenerate it after changing the portal address or enrollment credentials.
It does not replace the client's HTTPS trust configuration.

## CA import and key rotation

Follow the [CA lifecycle procedures](user-manual.md#renew-the-ca-root).
Prepare and review a replacement before activation, distribute the required
trust, and check a device connection afterwards. Keep the previous root only
as long as it is needed to trust certificates that are still in use.
