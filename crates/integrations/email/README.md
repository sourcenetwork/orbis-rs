# orbis-email

Scaffold for request-bound email challenges, signed-reply evidence, and DKIM
verification for [email-decrypt](../../../bin/example-integrations/email-decrypt/README.md).

Mail delivery, reply capture, and trusted-key lookup will be supplied through
adapters. Request binding, domain-key lifecycle, and mapping the authenticated
identity into an ACP-supported principal remain design work.

The proof must identify the exact recipient key and requested operation.
The email integration must preserve Orbis's separate reader-key proof of
possession and fresh recipient-key requirement.
