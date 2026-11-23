# orbis-webauthn

Scaffold for enrollment and request authorization using WebAuthn credentials.

This library serves both [passkey-sign](../../../bin/example-integrations/passkey-sign/README.md)
and [yubikey-sign](../../../bin/example-integrations/yubikey-sign/README.md). The YubiKey example
uses FIDO2/WebAuthn, not PIV, OpenPGP, or OTP.

Enrollment, credential persistence, challenge lifecycle, and node verification
will be developed with the first reference app. Browser calls remain in the
example frontend; Rust handles the application and node integration.
