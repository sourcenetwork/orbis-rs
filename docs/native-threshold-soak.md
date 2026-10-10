# Native threshold soak

The opt-in `soak` scope keeps one four-validator Vera deployment and one
three-member Orbis ring alive for a fifteen-minute measured interval. Both BLS
and Jubjub run against the same immutable normal runtime image revisions used
by focused lifecycle qualification. The driver rejects production source changes
against those images and clears test KDF overrides. It does not build a diagnostic
runtime or change the production refresh interval.

The focused driver selects Orbis runtime `67ed409901ed694ac9855ef5217e2b57ee75be40`
and Vera `c8a718743b19e6e8b9320baa5643380ada2a6932`. It pulls the pinned
Linux amd64 images by digest and checks their source, backend and curve labels.
The fault scope additionally requires the diagnostic image's unsafe-testing
label; that image is not used by the soak. A newer fixture can reuse these images
only when its changes belong to the driver's explicit fixture allowlist.

Each cycle rotates its entry point among the three Orbis members. It revokes and
regrants one of four certified relationships: the stored document, the inline
document, the signing derivation or the PET audit target. Denials must have the
exact authorization status. After regrant, two concurrent PRE calls must recover
the original plaintexts and a threshold signature over a new cycle message must
verify against the independently derived key and fail against the bare ring key.
The certified ring record must remain unchanged. At least twenty cycles must
complete; failed operations are not retried.

All Orbis members are killed and restarted near one-third and two-thirds of the
interval, using their existing containers and encrypted stores. The harness
checks member identities and both public polynomials and refreshes endpoints.
After the interval it revokes the documents and signing derivation, restarts all
members again and checks denial through every entry point while the audit grant
remains active. Regrant must restore verified signing and decryption at every
member. The stored document must remain identical and the inline document must
remain absent from the bulletin.

```sh
gh workflow run rust.yml --ref "$ORBIS_BRANCH" -f scope=soak -f restart_curve=both
```

The Rust test is ignored in ordinary CI and selected exactly once by the focused
driver with the `native-soak` nextest profile and zero retries. Its thirty-minute
outer deadline includes provisioning, the fifteen-minute interval and the final
restart checks. The separate profile leaves existing lifecycle deadlines unchanged.
The measured interval includes restart downtime; it is not fifteen minutes of
uninterrupted successful requests.

Only the selected test status/duration and bounded numeric cycle, elapsed-time
and restart counts are uploaded. Raw RPC responses, stores, keys and logs stay
private on the ephemeral runner. A missing, malformed or incomplete completion
record fails qualification even if JUnit reports success.

This fixture covers a bounded single-host workload with fixed membership. It
does not establish capacity, a memory plateau, WAN behavior or prolonged refresh
and membership churn. Scheduled refresh and member replacement have separate
lifecycle cases. The soak requires a successful hosted run on each curve before
its behavior can be described as qualified.
