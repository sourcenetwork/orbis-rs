#!/usr/bin/env bash
set -euo pipefail

curve="${1:?expected bls12-381 or jubjub}"
case "$curve" in
  bls12-381|jubjub) ;;
  *) echo 'expected bls12-381 or jubjub' >&2; exit 2 ;;
esac

native_graph="$(mktemp)"
trap 'rm -f -- "$native_graph"' EXIT
cargo tree --locked --color never -p orbis-node --no-default-features \
  --features "native,redb,iroh,$curve" --target x86_64-unknown-linux-gnu \
  --edges normal,build --prefix none > "$native_graph"

if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v|^(reqwest v0\.11\.|h2 v0\.3\.|rustls v0\.21\.|rustls-webpki v0\.101\.)' "$native_graph"; then
  echo 'Native node includes legacy transport dependencies' >&2
  exit 1
fi
