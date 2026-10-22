#!/bin/bash
#
# Entrypoint of hopf's quic-interop-runner endpoint image.

set -e

/setup.sh

echo "hopf interop endpoint: ROLE=$ROLE TESTCASE=$TESTCASE"
/hopf/quic-interop --version 2>/dev/null || true

export INTEROP_PREFERRED_IPV4="${INTEROP_PREFERRED_IPV4:-$(hostname -I | cut -f1 -d" ")}"
export INTEROP_PREFERRED_IPV6="${INTEROP_PREFERRED_IPV6:-$(hostname -I | cut -f2 -d" ")}"

if [ "$ROLE" = "client" ]; then
    export INTEROP_WAIT_FOR=sim:57832
    echo "REQUESTS=$REQUESTS"
    exec /hopf/quic-interop
else
    exec /hopf/quic-interop
fi
