# GDB script: Demonstrate OOB vector read in ValueDeserializer::ReadSharedObject
#
# WHAT THIS SHOWS:
#  1. ReadSharedObject() is reached via the Wasm shared-struct postMessage path
#  2. The only bounds check in V8 source (src/handles/shared-object-conveyor-handles.h)
#     is a DCHECK — stripped in Release builds:
#       Tagged<HeapObject> GetPersisted(uint32_t object_id) const {
#         DCHECK(HasPersisted(object_id));   // ← DEBUG only
#         return *shared_objects_[object_id]; // ← Release: no check → OOB
#       }
#  3. This d8 binary uses libc++ HARDENED MODE, which inlines a bounds check
#     into std::vector::operator[] at ReadSharedObject+206:
#       cmp [rcx+0x10], rax   ; size/end vs id
#       jbe __libcpp_verbose_abort (+563)  ; SIGABRT if OOB (hardened only)
#  4. Injecting id=0xFFFF triggers the hardening assertion → SIGABRT.
#     In a non-hardened Release build (production Chrome), +206 is ABSENT;
#     the access at +220 fires blindly → SIGSEGV / silent corruption.
#
# HOW TO RUN:
#  gdb -batch -x value_serializer_oob.gdb /tmp/d8_build_mca/d8
#
# EXPECTED OUTPUT (hardened libc++ build):
#  vector.h:419: libc++ Hardening assertion __n < size() failed
#  Thread N "WorkerThread" received signal SIGABRT
#
# EXPECTED OUTPUT (non-hardened Release build):
#  Thread N received signal SIGSEGV at ReadSharedObject+220

set pagination off
set confirm off
set print address on

# Source the Python injection script (handles dynamic address resolution).
# This avoids "function+offset" breakpoint syntax which requires DWO debug info.
source value_serializer_oob_inject.py

run --wasm-shared --allow-natives-syntax value_serializer_oob.js
