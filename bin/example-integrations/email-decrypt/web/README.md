# Browser code

Plain HTML/JS (`index.html`/`app.js`), no framework — served directly by
`src/main.rs` via `include_str!`, no build step.

Unlike `passkey-sign`'s browser code, there's no in-browser ceremony here:
the browser's whole job is collecting a few inputs and showing results. The
actual send/receive loop runs entirely in `src/main.rs`:

- **Send challenge** (`POST /api/{sign,pre}/challenge`): the backend builds
  an exact, single-use challenge (`PendingSign`/`PendingPre::email_challenge_text`
  — the same `canonical_display()` rendering the node will independently
  recompute), emails it to the address you typed in (SMTP, via `lettre`),
  and returns both a `request_token` and the challenge text itself — shown
  on the page so you know exactly what you're about to approve before you
  reply.
- **Reply, from your own mail client** — not this page. Keep the shown text
  exactly as-is in your reply; your mail client fills in `In-Reply-To`
  automatically when you hit "Reply," which is how the backend finds your
  response later.
- **Check for reply** (`POST /api/{sign,pre}/check-reply`): a one-shot IMAP
  lookup (not a background poll) for a message whose `In-Reply-To` names the
  original challenge email. A miss just means "not yet" — click again after
  you've actually replied.
