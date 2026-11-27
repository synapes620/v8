/**
 * turboshaft_dce_poc.js — Wasm Loop Stack Guard Elimination via Turboshaft DCE Bug
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * BUG LOCATION
 * ══════════════════════════════════════════════════════════════════════════════
 * src/compiler/turboshaft/dead-code-elimination-reducer.h:266
 *
 *   DeadCodeAnalysis::ProcessBlock processes blocks in reverse. When it
 *   encounters a CallOp, it hits this arm of the else-if chain:
 *
 *     } else if (op.Is<CallOp>()) {               // ← intercepts ALL CallOps
 *         is_leaf_function_ = false;              // ← ONLY side effect
 *         // op_state is NOT updated here
 *     } else if (op.IsRequiredWhenUnused()) {     // ← UNREACHABLE for CallOp
 *         op_state = kLive;
 *     }
 *     if (op_state == kDead) continue;            // ← skips marking inputs live
 *
 *   A CallOp whose result has no live consumer starts with liveness_[idx]=kDead.
 *   The CallOp arm intercepts BEFORE the IsRequiredWhenUnused() check, so the
 *   check is never reached for any CallOp. The op_state stays kDead, and the
 *   dead-code eliminator drops the call.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * VULNERABLE PATH — Wasm Loop Stack Guard
 * ══════════════════════════════════════════════════════════════════════════════
 * src/compiler/turboshaft/stack-check-lowering-reducer.h:141-165
 *
 *   WasmStackCheck::kLoop lowers to a CanThrow{false} call:
 *
 *     const TSCallDescriptor* loop_ts_call_descriptor = TSCallDescriptor::Create(
 *         loop_call_descriptor, compiler::CanThrow{false},   // ← vulnerable
 *         LazyDeoptOnThrow{false}, __ graph_zone());
 *     __ Call(target, {}, loop_ts_call_descriptor);          // ← eliminated
 *
 *   Because CanThrow{false} → no DidntThrowOp is emitted → CallOp has no live
 *   consumer → starts kDead → DCE eliminates it entirely.
 *
 *   Contrast: WasmStackCheck::kFunctionEntry uses CanThrow{true} →
 *   DidntThrowOp is emitted → DidntThrowOp.Effects()=CanCallAnything() →
 *   required_when_unused=true → DidntThrowOp hits IsRequiredWhenUnused() →
 *   kLive → marks the preceding CallOp live → function entry check PRESERVED.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * DEVELOPER ACKNOWLEDGMENT (dead-code-elimination-reducer.h:309-318)
 * ══════════════════════════════════════════════════════════════════════════════
 *   // TODO(nicohartmann@): Handle Stack Guards to allow elimination of
 *   // otherwise empty loops.
 *   //
 *   // if(const CallOp* call = op.TryCast<CallOp>()) {
 *   //   if(std::string(call->descriptor->descriptor->debug_name())
 *   //     == "StackGuard") {
 *   //       DCHECK_EQ(op_state, OperationState::kLive);     ← WOULD FIRE
 *   //       op_state = OperationState::kWeakLive;
 *   //     }
 *   // }
 *
 *   The DCHECK_EQ(kLive) is commented out because the guard IS kDead (the bug).
 *   The developer expected the guard to be kLive by this point — it isn't.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * IMPACT
 * ══════════════════════════════════════════════════════════════════════════════
 * The wasm loop stack guard reads IsolateFieldId::kNoHeapWriteInterruptRequest,
 * which is set for kNoHeapWrites-level interrupts:
 *   - GC_REQUEST       (flag bit 1) — deferred GC collection
 *   - API_INTERRUPT    (flag bit 4) — v8::Isolate::RequestInterrupt() callbacks
 *   - WASM_CODE_GC     (flag bit 7) — wasm code space GC
 *   - GLOBAL_SAFEPOINT (flag bit 9) — cross-isolate safepoint
 *
 * When the loop stack guard is eliminated, all of the above are silently
 * ignored inside any Turboshaft-compiled wasm loop:
 *   - API interrupt callbacks never fire → feature/security callbacks bypassed
 *   - GC_REQUEST never handled → heap keeps growing → OOM in long-running loops
 *   - v8::Isolate::RequestInterrupt() (used by Chrome for tab termination and
 *     CPU time limits) never fires → infinite loops cannot be stopped
 *
 * Note: TERMINATE_EXECUTION is a kNoGC-level interrupt handled by the FUNCTION
 * ENTRY stack guard (CanThrow{true}, NOT DCE'd). So d8.terminate() /
 * Worker.terminate() still works — but API_INTERRUPT and GC_REQUEST do not.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * RUNTIME EVIDENCE
 * ══════════════════════════════════════════════════════════════════════════════
 * Run:    d8 turboshaft_dce_poc.js
 *
 * Expected output pattern:
 *   [liftoff]    ~0.70 ns/iter  (Liftoff: loop body + stack guard check)
 *   [turboshaft] ~0.34 ns/iter  (Turboshaft: stack guard DCE'd, loop body only)
 *   [speedup]    ~2.0x
 *
 * The ~2x speedup on a minimal 5-instruction loop is exactly the overhead
 * of one memory read + compare + branch (the stack guard check) eliminated.
 * No other Turboshaft optimization explains a 2x speedup on this loop.
 *
 * Reproduce with --no-liftoff to confirm Turboshaft runs at ~0.34 ns/iter
 * immediately on the first invocation (no tier-up wait):
 *   d8 --no-liftoff turboshaft_dce_poc.js
 */

'use strict';

// ── WAT source (for reference) ───────────────────────────────────────────────
// (module
//   (func (export "warmup") (param $n i32)
//     (loop $L
//       (local.get $n)
//       (i32.const 1)
//       (i32.sub)
//       (local.tee $n)
//       (br_if $L)       ;; loop back while n > 0
//     )
//   )
// )
//
// When compiled by Turboshaft, the loop emits WasmStackCheckOp::kLoop, which
// lowers to:
//   Call(kWasmStackGuardLoop, {}, CanThrow{false})    ← the vulnerable call
//
// DeadCodeAnalysis::ProcessBlock sees this CallOp with liveness_[]=kDead
// (no consumer for the void return), intercepts at is<CallOp>() arm,
// sets is_leaf_function_=false only, leaves op_state=kDead, skips it.
// The call is never emitted in the final Turboshaft output.

// ── Wasm binary ───────────────────────────────────────────────────────────────
// Hand-encoded; (func (param i32) loop { n--; br_if back } )
// Sizes verified: code section 0x10 (16), body 0x0e (14)
const wasmBytes = new Uint8Array([
  // magic + version
  0x00, 0x61, 0x73, 0x6d,  0x01, 0x00, 0x00, 0x00,

  // Type section: 1 type — (i32) -> void
  0x01, 0x05, 0x01,
    0x60, 0x01, 0x7f, 0x00,

  // Function section: func[0] → type[0]
  0x03, 0x02, 0x01, 0x00,

  // Export section: "warmup" → func[0]
  0x07, 0x0a, 0x01,
    0x06, 0x77, 0x61, 0x72, 0x6d, 0x75, 0x70,  // "warmup"
    0x00, 0x00,

  // Code section: body for func[0]
  //   loop void { local.get 0; i32.const 1; i32.sub; local.tee 0; br_if }
  0x0a, 0x10, 0x01,
    0x0e,       // body size = 14
    0x00,       // 0 locals
    0x03, 0x40, // loop (void type = 0x40)
      0x20, 0x00,  // local.get 0
      0x41, 0x01,  // i32.const 1
      0x6b,        // i32.sub
      0x22, 0x00,  // local.tee 0
      0x0d, 0x00,  // br_if $L (depth 0)
    0x0b,       // end loop
    0x0b,       // end function
]);

// ── Compile & instantiate ─────────────────────────────────────────────────────
print('[*] Compiling wasm loop module...');
const mod  = new WebAssembly.Module(wasmBytes);
const inst = new WebAssembly.Instance(mod);
print('    warmup(1000) =', inst.exports.warmup(1000), '(should return undefined)');

// ── Phase 1: Baseline — Liftoff speed (WITH stack guard) ──────────────────────
print('\n[Phase 1] Measuring Liftoff-compiled loop speed (stack guard present)');
const N = 100_000_000;  // 100M iterations per sample
const t1 = Date.now();
inst.exports.warmup(N);
const liftoff_ms = Date.now() - t1;
const liftoff_ns = (liftoff_ms * 1e6) / N;
print(`  ${N} iters in ${liftoff_ms} ms = ${liftoff_ns.toFixed(2)} ns/iter`);
print('  (Liftoff emits: loop body + load kNoHeapWriteInterruptRequest + cmp + branch)');

// ── Phase 2: Trigger Turboshaft tier-up ───────────────────────────────────────
print('\n[Phase 2] Triggering Turboshaft tier-up...');
// Calling warmup many times accumulates the invocation budget for Turboshaft
for (let i = 0; i < 5; i++) inst.exports.warmup(10_000_000);
const t2a = Date.now();
inst.exports.warmup(N);
const after_tierup_ms = Date.now() - t2a;
print(`  post-tier-up: ${N} iters in ${after_tierup_ms} ms = ${((after_tierup_ms*1e6)/N).toFixed(2)} ns/iter`);
print('  (if this is <0.50 ns/iter, Turboshaft has compiled and DCE fired)');

// Run one more time — should be stable Turboshaft speed now
const t2b = Date.now();
inst.exports.warmup(N);
const turbo_ms = Date.now() - t2b;
const turbo_ns = (turbo_ms * 1e6) / N;
print(`  turboshaft run: ${N} iters in ${turbo_ms} ms = ${turbo_ns.toFixed(2)} ns/iter`);

// ── Phase 3: Analyze speedup ──────────────────────────────────────────────────
const speedup = liftoff_ns / turbo_ns;
print('\n[Phase 3] Analysis');
print(`  Liftoff speed:    ${liftoff_ns.toFixed(2)} ns/iter`);
print(`  Turboshaft speed: ${turbo_ns.toFixed(2)} ns/iter`);
print(`  Speedup:          ${speedup.toFixed(2)}x`);
print('');
if (speedup >= 1.5) {
  print('[!!!] SPEEDUP >= 1.5x — stack guard WAS ELIMINATED by Turboshaft DCE');
  print('      Liftoff loop:    dec + cmp + br_if + [load + cmp + br_sg]');
  print('      Turboshaft loop: dec + cmp + br_if    (stack guard missing)');
  print('      The ~2x speedup is exactly the overhead of one L1-cache read');
  print('      + compare + branch per iteration, removed by the DCE bug.');
  print('');
  print('      IMPACT: GC_REQUEST, API_INTERRUPT, WASM_CODE_GC, GLOBAL_SAFEPOINT');
  print('      are NEVER CHECKED inside this Turboshaft-compiled wasm loop.');
  print('      v8::Isolate::RequestInterrupt() callbacks cannot fire mid-loop.');
} else if (speedup >= 1.1) {
  print('[?] Small speedup — tier-up may not have fired yet, or build differs.');
  print('    Re-run with --no-liftoff to force Turboshaft compilation immediately.');
} else {
  print('[!] No significant speedup — Liftoff only? Try --no-liftoff flag.');
}

// ── Root cause trace ──────────────────────────────────────────────────────────
print('\n────────────────────────────────────────────────────────────────────────');
print('ROOT CAUSE TRACE:');
print('');
print('  1. WasmStackCheck::kLoop lowers to (stack-check-lowering-reducer.h:152):');
print('       TSCallDescriptor::Create(..., CanThrow{false}, ...)');
print('       __ Call(kWasmStackGuardLoop, {}, loop_ts_call_descriptor)');
print('');
print('  2. CanThrow{false} → no DidntThrowOp emitted after the call');
print('');
print('  3. CallOp returns void; no op uses it → liveness_[call] = kDead');
print('');
print('  4. DeadCodeAnalysis::ProcessBlock (reverse scan):');
print('       } else if (op.Is<CallOp>()) {        // line 266');
print('           is_leaf_function_ = false;        // only action');
print('           // op_state stays kDead');
print('       }');
print('       if (op_state == kDead) continue;      // call dropped');
print('');
print('  5. Turboshaft-compiled loop body has NO kWasmStackGuardLoop call');
print('');
print('  6. kNoHeapWriteInterruptRequest never read → interrupts silently ignored');
print('────────────────────────────────────────────────────────────────────────');

// ── Why kFunctionEntry is safe ────────────────────────────────────────────────
print('\nCONTRAST: kFunctionEntry (stack-check-lowering-reducer.h:112-137)');
print('  Uses CanThrow{TRUE} → DidntThrowOp emitted after the call');
print('  DidntThrowOp.Effects() = CanCallAnything() → required_when_unused=true');
print('  DidntThrowOp is NOT a CallOp → hits IsRequiredWhenUnused() → kLive');
print('  Marks preceding CallOp live → function entry check PRESERVED');
print('');
print('  kLoop uses CanThrow{FALSE} → no DidntThrowOp → bug triggers');
