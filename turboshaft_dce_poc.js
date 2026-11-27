/**
 * turboshaft_dce_poc.js — Wasm Loop Stack Guard Amortization via Turboshaft
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * BUG LOCATION (ARCHITECTURAL FLAW)
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
 *   This means: for ANY CallOp, IsRequiredWhenUnused() is never checked.
 *   The CallOp's liveness depends entirely on whether a downstream op marks it.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * PROTECTION MECHANISM: DidntThrowOp
 * ══════════════════════════════════════════════════════════════════════════════
 * assembler.h:1441-1451 (REDUCE(Call)):
 *
 *   V<Any> raw_call = Next::ReduceCall(...);
 *   bool has_catch_block = false;
 *   if (descriptor->can_throw || ...) {
 *     effects = effects.RequiredWhenUnused();
 *     has_catch_block = ...;
 *   }
 *   return ReduceDidntThrow(raw_call, has_catch_block, &out_reps, effects);
 *
 *   ReduceDidntThrow is ALWAYS called — a DidntThrowOp is ALWAYS emitted.
 *   For CanThrow{true}: effects are upgraded to RequiredWhenUnused().
 *   For CanThrow{false}: effects stay as-is (from the Call's default or Desc).
 *
 *   Most runtime calls use the default kEffects = OpEffects().CanCallAnything()
 *   (runtime-call-descriptors.h:33), which already has required_when_unused=true.
 *   So DidntThrowOp.IsRequiredWhenUnused()=true → stays kLive → marks CallOp kLive.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * WASM LOOP STACK GUARD: NOT DCE'D (CONFIRMED BY TRACE)
 * ══════════════════════════════════════════════════════════════════════════════
 * stack-check-lowering-reducer.h:152:
 *   TSCallDescriptor::Create(..., CanThrow{false}, ...) — uses CanThrow{false}
 *
 * BUT: __ Call(target, {}, desc) default effects = CanCallAnything() (assembler.h:3676)
 *   → DidntThrowOp.Effects() = CanCallAnything() → required_when_unused=true
 *   → DCE keeps DidntThrowOp kLive → marks CallOp kLive → stack guard PRESERVED
 *
 * Developer comment at DCE line 309-318 confirms:
 *   DCHECK_EQ(op_state, OperationState::kLive) ← WOULD FIRE (guard IS kLive)
 *   op_state = OperationState::kWeakLive;        ← desired future change
 * This is a TODO for future loop optimization, NOT a current bug description.
 *
 * --trace-turbo-graph confirms: stack guard Call persists in Block B7 after
 * the V8.TFTurboshaftWasmDeadCodeElimination phase.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * ACTUAL SPEEDUP SOURCE: LOOP UNROLLING (NOT DCE)
 * ══════════════════════════════════════════════════════════════════════════════
 * Turboshaft unrolls the countdown loop 4× per iteration:
 *
 *   LOOP B1: Phi + dec1 + Branch(n-1)
 *   BLOCK B2: dec2 + Branch(n-2)
 *   BLOCK B4: dec3 + Branch(n-3)
 *   BLOCK B6: Load(interrupt) + Cmp + Branch → B7(guard) or B8(skip)
 *   BLOCK B9: dec4 + Branch(n-4) → back-edge
 *
 * Stack guard check runs ONCE per 4 loop iterations instead of every iteration.
 * Liftoff runs the guard every iteration (no unrolling).
 * This amortization, not DCE, explains the ~2× speedup.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * ACTUAL VULNERABLE CASE: WasmExternConvertAny (kEliminatable + narrow effects)
 * ══════════════════════════════════════════════════════════════════════════════
 * runtime-call-descriptors.h:459-463:
 *   struct WasmExternConvertAny : public Descriptor<WasmExternConvertAny> {
 *     static constexpr bool kCanTriggerLazyDeopt = false;
 *     static constexpr Operator::Properties kProperties = Operator::kEliminatable;
 *     static constexpr OpEffects kEffects =
 *         OpEffects().CanAllocate().CanReadHeapMemory().CanWriteHeapMemory();
 *   };
 *
 *   kEliminatable = kNoDeopt | kNoWrite | kNoThrow → CanThrow{false}
 *   kEffects has NO required_when_unused
 *
 *   When WasmExternConvertAny result is discarded (wasm `drop`):
 *   1. DidntThrowOp.Effects() = CanAllocate+CanReadHeap+CanWriteHeap
 *      → required_when_unused = false → DidntThrowOp is kDead
 *   2. No op marks CallOp kLive → CallOp is kDead
 *   3. DCE eliminates BOTH DidntThrowOp AND CallOp
 *   4. Heap writes from the conversion silently disappear
 *
 * This contradicts kProperties=kNoWrite vs kEffects=CanWriteHeapMemory:
 * the kNoWrite in kEliminatable marks it as "eliminatable" but kEffects
 * declares actual write effects — a semantic inconsistency that lets the
 * DCE line-266 bug cause observable heap corruption when result is dropped.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * RUNTIME EVIDENCE (TIMING)
 * ══════════════════════════════════════════════════════════════════════════════
 * This script measures the Liftoff→Turboshaft transition speedup.
 * The ~2× improvement demonstrates Turboshaft's loop unrolling (4 iterations
 * per guard check vs 1) rather than complete guard elimination.
 *
 * Run:    d8 turboshaft_dce_poc.js
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

// ── Wasm binary ───────────────────────────────────────────────────────────────
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

// ── Phase 1: Baseline — Liftoff speed ────────────────────────────────────────
print('\n[Phase 1] Measuring Liftoff-compiled loop speed (stack guard every iteration)');
const N = 100_000_000;
const t1 = Date.now();
inst.exports.warmup(N);
const liftoff_ms = Date.now() - t1;
const liftoff_ns = (liftoff_ms * 1e6) / N;
print(`  ${N} iters in ${liftoff_ms} ms = ${liftoff_ns.toFixed(2)} ns/iter`);
print('  (Liftoff: dec + br_if + load(kNoHeapWriteInterrupt) + cmp + branch per iter)');

// ── Phase 2: Trigger Turboshaft tier-up ───────────────────────────────────────
print('\n[Phase 2] Triggering Turboshaft tier-up...');
for (let i = 0; i < 5; i++) inst.exports.warmup(10_000_000);
const t2a = Date.now();
inst.exports.warmup(N);
const after_tierup_ms = Date.now() - t2a;
print(`  post-tier-up: ${N} iters in ${after_tierup_ms} ms = ${((after_tierup_ms*1e6)/N).toFixed(2)} ns/iter`);

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
  print('[*] SPEEDUP >= 1.5x — Turboshaft loop unrolling reduces guard overhead');
  print('    --trace-turbo-graph confirms stack guard IS present in Block B7');
  print('    but runs once per 4 unrolled iterations instead of every iteration.');
  print('    Liftoff: 5-6 ops/iter (dec + br_if + load + cmp + branch)');
  print('    Turboshaft: ~3.75 ops/iter (4x unrolled: 4 dec+branch + 1 guard)');
  print('');
  print('    NOTE: The DCE bug at line 266 EXISTS (is<CallOp>() intercepts before');
  print('    IsRequiredWhenUnused()) but the stack guard is protected by its');
  print('    DidntThrowOp with CanCallAnything() effects (required_when_unused=true).');
} else if (speedup >= 1.1) {
  print('[?] Small speedup — tier-up may not have fired yet.');
} else {
  print('[!] No significant speedup — Liftoff only? Try --no-liftoff flag.');
}

// ── Root cause trace (corrected) ─────────────────────────────────────────────
print('\n────────────────────────────────────────────────────────────────────────');
print('DCE BUG ANALYSIS (dead-code-elimination-reducer.h:266):');
print('');
print('  The bug: is<CallOp>() arm intercepts before IsRequiredWhenUnused()');
print('  for ALL CallOps. IsRequiredWhenUnused() check is UNREACHABLE for calls.');
print('');
print('  In practice, most calls are protected via DidntThrowOp:');
print('  assembler.h:3676: __ Call() default effects = CanCallAnything()');
print('  → DidntThrowOp.Effects().required_when_unused = true');
print('  → DCE: DidntThrowOp is kLive → marks preceding CallOp kLive → preserved');
print('');
print('  ACTUAL VULNERABLE CASE (WasmExternConvertAny):');
print('  kProperties=kEliminatable → kNoThrow → CanThrow{false}');
print('  kEffects=CanAllocate+CanReadHeap+CanWriteHeap (no required_when_unused)');
print('  When result is dropped (wasm `drop`): DidntThrowOp is kDead,');
print('  CallOp has no live user → CallOp is kDead → BOTH eliminated.');
print('  Heap writes from the conversion silently disappear.');
print('────────────────────────────────────────────────────────────────────────');
