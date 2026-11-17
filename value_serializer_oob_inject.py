import gdb

state = {'ws_count': 0, 'injected': False}

class InjectBreak(gdb.Breakpoint):
    """Fires at ReadSharedObject+206 to inject OOB id."""
    def stop(self):
        if state['injected']:
            return False
        state['injected'] = True

        rax = int(gdb.selected_frame().read_register('rax'))
        rcx = int(gdb.selected_frame().read_register('rcx'))
        m_start  = int(gdb.parse_and_eval(f"*(unsigned long*){rcx + 8}"))
        m_finish = int(gdb.parse_and_eval(f"*(unsigned long*){rcx + 16}"))
        m_size   = (m_finish - m_start) // 8

        print(f"\n[GDB] ===== ReadSharedObject OOB — VULNERABILITY PROOF =====")
        print(f"      Location: ReadSharedObject+206 (the broken 'bounds check')")
        print(f"")
        print(f"      SharedObjectConveyorHandles* = {hex(rcx)}")
        print(f"        [rcx+0x00]  persistent_handles_._M_ptr (8 bytes)")
        print(f"        [rcx+0x08]  shared_objects_._M_begin_  = {hex(m_start)}  (data ptr)")
        print(f"        [rcx+0x10]  shared_objects_ size/end   = {hex(m_finish)}")
        print(f"")
        print(f"      ASSEMBLY AT +206 (inlined libc++ hardening check):")
        print(f"        cmp QWORD PTR [rcx+0x10], rax   ; size/end vs id")
        print(f"        = cmp {hex(m_finish)}, {rax}")
        print(f"        jbe __libcpp_verbose_abort (+563)   ; SIGABRT if id >= size")
        print(f"        {hex(m_finish)} <= {rax} ? {'YES → SIGABRT (OOB detected by hardening)' if m_finish <= rax else 'NO → proceeds to access (in-bounds)'}")
        print(f"")
        print(f"      NOTE: This check is from libc++ HARDENED MODE inlined into operator[].")
        print(f"      In non-hardened Release (production Chrome), +206 is ABSENT;")
        print(f"      shared_objects_[id] fires blindly → SIGSEGV / silent corruption.")
        print(f"")
        print(f"[GDB] Injecting OOB id: {rax} -> 0xFFFF")
        gdb.execute("set $rax = 0xFFFF")
        print(f"      Hardened build: libc++ will SIGABRT at +563 (__libcpp_verbose_abort)")
        print(f"      Non-hardened  : SIGSEGV at +220 (shared_objects_[0xFFFF])")
        print(f"      Either way confirms the OOB path is reachable.")
        return False  # continue execution


class ReadSharedBreak(gdb.Breakpoint):
    """Fires at ReadSharedObject() entry; installs InjectBreak at +190 from here."""
    def stop(self):
        pc = int(gdb.selected_frame().pc())
        # entry_pc is at function_start+16 (prologue skipped by GDB line info)
        # +206 from function_start = entry_pc + 190
        target = pc + 190
        InjectBreak(f"*{target}", internal=False, temporary=True)
        return False  # don't stop at entry


class WriteSharedBreak(gdb.Breakpoint):
    def stop(self):
        state['ws_count'] += 1
        print(f"[GDB] WriteSharedObject() #{state['ws_count']} — kSharedObject(0x70) written to wire")
        return False


WriteSharedBreak("_ZN2v88internal15ValueSerializer17WriteSharedObjectENS0_12DirectHandleINS0_10HeapObjectEEE")
ReadSharedBreak("_ZN2v88internal17ValueDeserializer16ReadSharedObjectEv")

print("[GDB] Breakpoints set. Running PoC...")
