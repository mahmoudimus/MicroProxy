#!/usr/bin/env bash
set -euo pipefail

# Unsupported cases must be reported before network setup, file access or binding.
case "${ROLE:-}" in client|server) ;; *) exit 127 ;; esac
case "${TESTCASE:-}" in
  handshake|transfer|retry|chacha20|keyupdate|multiconnect|resumption|zerortt|http3|rebind-port|rebind-addr) ;;
  *) exit 127 ;;
esac
if [[ $ROLE == server && $TESTCASE == keyupdate ]]; then exit 127; fi

# Only direct container smoke tests bypass the simulator's routing contract.
if [[ ${MICROPROXY_INTEROP_SKIP_SETUP:-0} != 1 ]]; then
  /setup.sh
  if [[ $ROLE == client ]]; then
    /wait-for-it.sh sim:57832 -s -t 30
  fi
fi
echo "MicroProxy QUIC interop revision ${MICROPROXY_SOURCE_REVISION:-working-tree}"
exec java -Xms16m -Xmx512m -jar /opt/microproxy/quic-interop.jar
