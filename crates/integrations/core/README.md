# orbis-integration-core

Scaffold for the operation description, portable authentication evidence, and
local verification result shared by the flow integrations.

No public types or verification functions exist yet. Keep this crate small and
independent of HTTP frameworks, databases, mail delivery, and node startup.

A verified actor returned inside one process is not proof for another process.
Participating nodes must independently verify the original evidence.
