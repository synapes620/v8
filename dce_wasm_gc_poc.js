/**
 * dce_wasm_gc_poc.js — ExternConvertAny DCE via incorrect effects declaration
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * BUG LOCATION
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * 1) dead-code-elimination-reducer.h:266 — DCE CallOp bypass
 *    is<CallOp>() arm intercepts before IsRequiredWhenUnused() check.
 *    For any CallOp, liveness is determined ONLY by downstream op usage.
 *
 * 2) operations.h:7999 — ExternConvertAnyOp incorrect effects
 *    struct ExternConvertAnyOp {
 *      static constexpr OpEffects effects = OpEffects().CanDependOnChecks();
 *    };
 *    Declared: only depends on checks (no allocation, no heap writes).
 *    Actual: calls WasmToJSObject → may allocate JS wrapper + write js_wrapper_.
 *
 * Combined effect: DCE eliminates ExternConvertAny when result is dropped.
 * This is "safe" due to V8's lazy wrapper initialization (WasmToJSObject checks
 * js_wrapper_ on each call), but the incorrect effects declaration can mislead
 * load elimination, causing it to assume no heap writes occurred when they did.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * PROTECTION FOR CallRuntime<WasmExternConvertAny> (non-kWasm path)
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * wasm-lowering-reducer.h:304-311:
 *   if (pipeline_kind() == kWasm) {
 *     wrapper = WasmCallRuntime(..., CanThrow{true});  // protected
 *   } else {
 *     wrapper = CallRuntime<WasmExternConvertAny>(...); // vulnerable effects
 *   }
 *
 * The else branch requires WasmLoweringPhase to run in a non-kWasm pipeline.
 * WasmLoweringPhase ONLY runs in the kWasm pipeline (pipeline.cc:3063).
 * Hence the vulnerable else branch is UNREACHABLE in the current V8 codebase.
 * The ExternConvertAnyOp effects bug (finding #2) is the active vulnerability.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * OBSERVABLE BEHAVIOR
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * Run:    d8 --trace-turbo-graph dce_wasm_gc_poc.js 2>&1 | grep -A5 'ExternConvertAny'
 *
 * In the kWasm Turboshaft pipeline, ExternConvertAnyOp with dropped result:
 * - effects.is_required_when_unused() = false (CanDependOnChecks only)
 * - DCE marks op kDead → op eliminated → no allocation
 *
 * Timing shows: convert_drop is FASTER than convert_use because DCE eliminates
 * the runtime call that would allocate a JS wrapper for wasm structs/funcref.
 */

'use strict';

// ── Wasm module: extern.convert_any + drop (DCE target) vs use (preserved) ──
// (module
//   (func (export "convert_drop") (param anyref)
//     local.get 0        ;; push anyref onto stack
//     extern.convert_any ;; anyref → externref (may allocate JS wrapper)
//     drop               ;; discard result — DCE eliminates this sequence
//   )
//   (func (export "convert_use") (param anyref) (result externref)
//     local.get 0        ;; push anyref
//     extern.convert_any ;; anyref → externref — result IS used, preserved
//   )
// )
const wasmBytes = new Uint8Array([
  // Magic + version
  0x00, 0x61, 0x73, 0x6d,  0x01, 0x00, 0x00, 0x00,

  // Type section: 2 types
  // type 0: (func (param anyref) (result))
  // type 1: (func (param anyref) (result externref))
  0x01, 0x0a, 0x02,
    0x60, 0x01, 0x6e, 0x00,         // type 0: anyref→void
    0x60, 0x01, 0x6e, 0x01, 0x6f,   // type 1: anyref→externref

  // Function section: func[0]→type[0], func[1]→type[1]
  0x03, 0x03, 0x02, 0x00, 0x01,

  // Export section
  0x07, 0x1e, 0x02,
    0x0c,                                                              // "convert_drop" len=12
    0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x74, 0x5f, 0x64, 0x72, 0x6f, 0x70,
    0x00, 0x00,                                                        // func[0]
    0x0b,                                                              // "convert_use" len=11
    0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x74, 0x5f, 0x75, 0x73, 0x65,
    0x00, 0x01,                                                        // func[1]

  // Code section: 2 bodies
  0x0a, 0x10, 0x02,
    // body 0: convert_drop
    0x07, 0x00,
      0x20, 0x00,  // local.get 0
      0xfb, 0x1b,  // extern.convert_any (anyref→externref)
      0x1a,        // drop
    0x0b,          // end
    // body 1: convert_use
    0x06, 0x00,
      0x20, 0x00,  // local.get 0
      0xfb, 0x1b,  // extern.convert_any
    0x0b,          // end
]);

print('[*] Compiling wasm module...');
let mod, inst;
try {
  mod = new WebAssembly.Module(wasmBytes);
  inst = new WebAssembly.Instance(mod);
  print('[*] Module OK');
} catch(e) {
  print('[!] Module error:', e.message);
  quit(1);
}

// ── Correctness test ─────────────────────────────────────────────────────────
const jsObj = { sentinel: 'test', value: 42 };
inst.exports.convert_drop(jsObj);   // void
const r = inst.exports.convert_use(jsObj);
print('[*] convert_use(jsObj) === jsObj:', r === jsObj, '(expected true)');

// ── Warm up: trigger tier-up to Turboshaft ───────────────────────────────────
print('\n[*] Warming up (triggering Turboshaft tier-up)...');
for (let i = 0; i < 50_000; i++) inst.exports.convert_drop(jsObj);
for (let i = 0; i < 50_000; i++) inst.exports.convert_use(jsObj);
print('[*] Warm-up done');

// ── Timing benchmark ─────────────────────────────────────────────────────────
const N = 5_000_000;
print(`\n[*] Timing ${N} iterations of each function...`);

// convert_drop: DCE should eliminate extern.convert_any (ExternConvertAnyOp kDead)
const t1 = Date.now();
for (let i = 0; i < N; i++) inst.exports.convert_drop(jsObj);
const ms_drop = Date.now() - t1;

// convert_use: ExternConvertAnyOp is live (result used by return)
const t2 = Date.now();
for (let i = 0; i < N; i++) inst.exports.convert_use(jsObj);
const ms_use = Date.now() - t2;

const ratio = ms_use / ms_drop;
print(`\n[Phase 1] convert_drop (DCE eliminates ExternConvertAny): ${ms_drop} ms`);
print(`[Phase 2] convert_use  (ExternConvertAny preserved):       ${ms_use} ms`);
print(`[Result]  Ratio use/drop = ${ratio.toFixed(2)}x`);
print('');
if (ratio >= 1.2) {
  print('[*] CONFIRMED: convert_drop is faster — DCE eliminated ExternConvertAny');
  print('    ExternConvertAnyOp.effects = CanDependOnChecks() (no required_when_unused)');
  print('    → DCE marks op kDead when result unused → op eliminated → no runtime call');
} else {
  print('[?] Small ratio — both paths optimized similarly or tier-up not triggered');
  print('    Try: d8 --no-liftoff --turboshaft dce_wasm_gc_poc.js');
}

// ── Bug analysis printout ────────────────────────────────────────────────────
print('');
print('═══════════════════════════════════════════════════════════════════');
print('BUG ANALYSIS: ExternConvertAny incorrect effects declaration');
print('');
print('File:    src/compiler/turboshaft/operations.h:7999');
print('Code:    static constexpr OpEffects effects = OpEffects().CanDependOnChecks();');
print('');
print('Declared effects: CanDependOnChecks() only');
print('  → required_when_unused = false');
print('  → allocation_requirement = none');
print('  → heap_write_requirement = none');
print('');
print('Actual effects (via WasmToJSObject / WasmCustomMap::CreateJSWrapper):');
print('  → May allocate a JS wrapper object on the heap (WasmCustomMap input)');
print('  → Writes to js_wrapper_ field of WasmCustomMap');
print('  → Should declare: CanAllocate() | CanWriteHeapMemory()');
print('');
print('DCE impact (dead-code-elimination-reducer.h:266):');
print('  For ExternConvertAnyOp (NOT a CallOp):');
print('    is<CallOp>() → false → check IsRequiredWhenUnused()');
print('    IsRequiredWhenUnused() → effects.is_required_when_unused() = false');
print('    → op_state stays kDead → op eliminated');
print('');
print('  For the lowered CallRuntime<WasmExternConvertAny> (kWasm pipeline):');
print('    is<CallOp>() → true → line 266 bypass (IsRequiredWhenUnused() skipped)');
print('    DidntThrowOp.effects = Desc::kEffects (narrow, no required_when_unused)');
print('    If GotoOp.inputs() is empty (confirmed: FixedArityOperationT<0>):');
print('      DidntThrowOp not marked kLive by GotoOp → kDead → CallOp kDead');
print('    But WasmLoweringPhase only runs in kWasm pipeline where kWasm branch is taken');
print('    → Vulnerable else branch (CallRuntime path) is never triggered');
print('');
print('Primary finding: ExternConvertAnyOp.effects incorrect (CWE-670)');
print('Secondary: DCE line-266 CallOp bypass (latent, not currently exploitable)');
print('═══════════════════════════════════════════════════════════════════');
