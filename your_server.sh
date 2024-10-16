#!/bin/sh

exec cargo run \
    --quiet \
    --release \
    --target-dir=/tmp/codecrafters-dns-target \
    --manifest-path $(dirname $0)/Cargo.toml -- "$@"
