#!/bin/sh

set -ex

CRATES="bitcoin hashes internals fuzz"
DEPS="recent minimal"
MSRV="1\.48\.0"

# Test pinned versions.
if cargo --version | grep ${MSRV}; then
    cargo update -p serde_json --precise 1.0.99
    cargo update -p serde --precise 1.0.156
    cargo update -p quote --precise 1.0.30
    cargo update -p proc-macro2 --precise 1.0.63
    cargo update -p serde_test --precise 1.0.175

    cargo update -p bitcoin:0.30.1 --precise 0.30.0

    # Build MSRV with pinned versions.
    cargo check --all-features --all-targets
fi

for crate in ${CRATES}
do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

exit 0
