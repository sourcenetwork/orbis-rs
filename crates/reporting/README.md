# orbis-reporting

Canonical report envelopes, fault evidence, and statement encodings shared by
Orbis and Vera. The crate provides deterministic encodings and digests for
reports and protocol evidence, including DKG, signing, proxy re-encryption,
and private equality tests.

Add it to a Rust project with:

```toml
[dependencies]
orbis-reporting = "0.0.2"
```

`ReportEnvelope::canonical_bytes` produces the representation used for signing.
`ReportEnvelope::validate_shape` checks the envelope's fields and validity
window. Shape validation does not authenticate a report or verify its evidence;
consumers must perform the appropriate signature, membership, and evidence
checks for their protocol.

The crate defines the shared data formats. It does not run an Orbis node,
manage keys, or submit reports. See the [API documentation](https://docs.rs/orbis-reporting)
and the [Orbis repository](https://github.com/sourcenetwork/orbis-rs) for details.

## License

Business Source License 1.1. The licensed work changes to Apache License 2.0
on March 13, 2030. See the included `Bsl.txt` and `LICENSE-APACHE` for the full
terms and the managed-service restriction.
