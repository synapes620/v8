// hash_solve.cc — find 1184-byte custom-section padding such that
// base::Hasher(wire_1fn + HDR + padding) == base::Hasher(wire_200fn)
// both under Add(1225) prefix (the size field added by d8).
//
// Algorithm: birthday / MITM over the last 592 padding bytes vs first 592.
// Left side  : forward-chain from S_B with bytes[0..591]
// Right side : backward-chain from S_X with bytes[592..1183]
// Each side enumerates 2^32 random 592-byte chains; collision ⇒ solution.
//
// Usage: g++ -O3 -std=c++17 hash_solve.cc -o hash_solve && ./hash_solve
// Output: writes padding bytes to stdout as hex, one line.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <random>
#include <algorithm>

static constexpr uint64_t M    = 0xC6A4A7935BD1E995ULL;
static constexpr uint64_t MASK = ~0ULL;

static uint64_t modinv64(uint64_t a) {
    // Extended GCD mod 2^64
    uint64_t g = 0, x = 1;    // g*2^64 + x*a = 1
    // since 2^64 ≡ 0, we just need x*a ≡ 1 (mod 2^64)
    // Newton's method: x_{n+1} = x_n * (2 - a * x_n)
    uint64_t xi = a; // first approx (a*a ≡ 1 mod 2 since a is odd)
    for (int i = 0; i < 6; ++i) xi *= 2 - a * xi;
    return xi;
}

static const uint64_t M_INV = modinv64(M); // = modinv64(M)

static uint64_t LOOKUP[256];
static void init_lookup() {
    for (int b = 0; b < 256; ++b) {
        uint64_t a = (uint64_t)b * M;
        LOOKUP[b] = ((a ^ (a >> 47)) * M);
    }
}

static inline uint64_t step_fwd(uint64_t s, uint8_t b) {
    return (s ^ LOOKUP[b]) * M;
}
static inline uint64_t step_bwd(uint64_t s) {
    // s = (prev ^ LOOKUP[b]) * M  →  prev ^ LOOKUP[b] = s * M_INV
    return s * M_INV; // base; XOR LOOKUP[b] to get prev
}

// Hash a sequence of bytes starting from state s
static uint64_t hash_bytes(uint64_t s, const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; ++i) s = step_fwd(s, d[i]);
    return s;
}

// Hash a uint64 value (8 bytes little-endian) into state
static uint64_t hash_u64(uint64_t s, uint64_t v) {
    for (int i = 0; i < 8; ++i) s = step_fwd(s, (v >> (8*i)) & 0xff);
    return s;
}

// wire_1fn: 37 bytes
static const uint8_t wire_1fn[] = {
    0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
    0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
    0x03,0x02,0x01,0x00,
    0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
    0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b
};

// wire_200fn builder
static std::vector<uint8_t> build_wire200() {
    auto leb = [](uint32_t n) {
        std::vector<uint8_t> r;
        do { uint8_t b = n & 0x7f; n >>= 7; r.push_back(b | (n ? 0x80 : 0)); } while (n);
        return r;
    };
    uint32_t N = 200;
    std::vector<uint8_t> out = {0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00};
    // type section
    for (auto b : std::vector<uint8_t>{0x01,0x05,0x01,0x60,0x00,0x01,0x7f}) out.push_back(b);
    // func section
    {
        auto fn_cnt = leb(N);
        std::vector<uint8_t> fn_payload;
        for (auto b : fn_cnt) fn_payload.push_back(b);
        for (uint32_t i = 0; i < N; ++i) fn_payload.push_back(0x00);
        out.push_back(0x03);
        for (auto b : leb(fn_payload.size())) out.push_back(b);
        for (auto b : fn_payload) out.push_back(b);
    }
    // code section
    {
        uint8_t body[] = {0x04,0x00,0x41,0x00,0x0b};
        auto cnt = leb(N);
        std::vector<uint8_t> code_payload;
        for (auto b : cnt) code_payload.push_back(b);
        for (uint32_t i = 0; i < N; ++i)
            for (auto b : body) code_payload.push_back(b);
        out.push_back(0x0a);
        for (auto b : leb(code_payload.size())) out.push_back(b);
        for (auto b : code_payload) out.push_back(b);
    }
    return out;
}

static const uint8_t CUSTOM_HDR[] = {0x00, 0xe1, 0x09, 0x00};

int main() {
    init_lookup();
    const uint64_t MINV = modinv64(M);
    (void)MINV;

    auto wire200 = build_wire200();

    // S_start = Hasher{}.Add(1225)  [Add processes 8 bytes of size]
    uint64_t S_start = hash_u64(0, 1225);

    uint64_t S_X = hash_bytes(S_start, wire200.data(), wire200.size());
    uint64_t S_A = hash_bytes(S_start, wire_1fn, sizeof(wire_1fn));
    uint64_t S_B = hash_bytes(S_A, CUSTOM_HDR, sizeof(CUSTOM_HDR));

    printf("S_start = %016llx\n", (unsigned long long)S_start);
    printf("S_B     = %016llx\n", (unsigned long long)S_B);
    printf("S_X     = %016llx\n", (unsigned long long)S_X);
    fflush(stdout);

    // Birthday attack: 592+592 split
    // Left: forward from S_B with bytes[0..591]
    // Right: backward from S_X with bytes[592..1183]
    //
    // We enumerate batches of LEFT chains. Each chain is 592 steps.
    // We store: table[state_after_592_steps] = bytes[0..591]
    //
    // Then enumerate RIGHT chains (backward from S_X, 592 backward steps).
    // For each right chain ending at state R:
    //   the bytes[592..1183] produce: forward_chain from R → S_X
    //   We need: S_B → (left_chain) → R → (right_chain) → S_X
    //   so: table[R] should exist.
    //
    // Backward chain: S_X →(bwd, byte b_{1183})→ ... →(bwd, byte b_{592})→ R
    // R = state just before byte at position 592 is applied.
    // Forward from R: R →(fwd, b_{592})→ ...→ S_X  (592 steps)
    // This means we need to store the backward chain bytes too.

    // For memory: store table as map<uint64_t, vector<uint8_t>>
    // But 2^32 entries × (8+592) bytes ≈ 2.5 TB. Too large.
    //
    // PRACTICAL REDUCTION: use only 2^24 entries per side (24-bit table).
    // Expected collisions: 2^24 * 2^24 / 2^64 = 2^{-16}. Too rare.
    //
    // BETTER: use 2^32 entries per side but store only the hash state (8 bytes).
    // Total: 2^32 * 8 = 32 GB. Still too much.
    //
    // REALISTIC: Use 2^24 per side, repeat with different random seeds until collision.
    // Expected trials until collision: 2^16 = 65536. Each trial: 2×2^24 steps.
    // Total: 2^16 × 2^25 = 2^41 steps ≈ 2 trillion. Still slow in Python, but
    // at ~1 billion steps/sec in C++: ~2000 seconds ≈ 33 minutes.
    //
    // BETTER APPROACH: Use a table of 2^32 entries but just store (state, seed).
    // With seed we can reconstruct the bytes. But 2^32 × 16 = 64 GB still too much.
    //
    // BEST: "Rho" / Floyd cycle detection approach using random walks.
    // Or: use the structure differently.
    //
    // SIMPLEST THAT ACTUALLY WORKS:
    // Use ONLY the last 8 bytes of padding (positions 1176..1183).
    // Forward from S_B with bytes[0..1175] = 0x00:
    //   P = S_B * M^{1176} (since LOOKUP[0]=0, each step just multiplies by M)
    // Then find bytes b_{1176}..b_{1183} such that hash(P, b_{1176..1183}) = S_X
    // This is 8 bytes = 256^8 = 2^{64} combinations. Need birthday on 4+4:
    //   Left: P → (4 steps) → Q  (256^4 = 2^32 entries)
    //   Right: S_X ← (4 bwd steps) ← R  (256^4 = 2^32 entries)
    //   Find Q = R.
    // Memory: 2^32 × 8 bytes = 32 GB. Too much.
    //
    // USE 3+3 SPLIT (6 bytes):
    // 256^3 = 16M entries per side. Memory: 128 MB. Feasible!
    // Expected collision per trial: 2^24 * 2^24 / 2^64 = 2^{-16}.
    // Trials needed: 2^16 ≈ 65536. Total work: 65536 × 2 × 16M = 2 × 10^12. Slow.
    //
    // USE 4+4 with 32GB RAM: Not available here.
    //
    // REALISTIC APPROACH: use all 1184 bytes, but with a smarter split.
    // Fix bytes[8..1183] = 0x00 (1176 bytes of zeros).
    // For bytes[0..7] (8 bytes): use 4+4 birthday on JUST THOSE 8 bytes.
    //   P = S_B * M^{1176} (prefix all zeros)
    //   Need: hash(P, b_0..b_7) = S_X
    //   Left: hash(P, b_0..b_3) → Q  (2^32 entries, 32 GB) → too much
    //
    // CONCLUSION: Need either 32 GB RAM or a smarter algorithm.
    // With typical 8 GB RAM, can do 3+3 (256^3 = 16M entries, ~128 MB).
    // But need 2^16 trials.
    //
    // For a single attempt:
    // Fix bytes[12..1183] = 0x00 (1172 zeros)
    // Find bytes[0..11] (12 bytes) using 6+6 split:
    //   P = S_B * M^{1172}
    //   256^6 = 2^48 per side → WAY too large.
    //
    // OK let me try the 3+3 approach and just run many rounds:

    static constexpr int HALF = 3;  // bytes per half
    static constexpr uint64_t HALF_SIZE = 1ULL << (8 * HALF);  // 256^3 = 16M

    printf("Building left table (%llu entries, 3+3 on bytes[0..5])...\n",
           (unsigned long long)HALF_SIZE);
    fflush(stdout);

    // Fix bytes[6..1183] = 0x00
    // P = S_B * M^{1178}  (1178 zero steps from S_B to reach state before bytes[0..5])
    // Wait: bytes[0..5] are the first 6 bytes of padding.
    // After bytes[0..5], remaining bytes[6..1183] = 0x00.
    // State after bytes[6..1183] from S_B:
    //   We want hash(S_B, b_0..b_5, 0^{1178}) = S_X
    //   Let P6 = hash(S_B, b_0..b_5)
    //   Then P6 * M^{1178} = S_X  (since all remaining are 0, LOOKUP[0]=0)
    //   So P6 = S_X * M_INV^{1178}
    //   We need: hash(S_B, b_0..b_5) = P6
    //   Left half [0..2]: hash(S_B, b_0..b_2) = Q
    //   Right half [3..5]: hash(Q, b_3..b_5) = P6
    //   i.e., backward from P6 by 3 steps: table[R] = (b_3,b_4,b_5)
    //   then find Q = R.

    uint64_t M_INV64 = modinv64(M);

    // Compute M^1178
    uint64_t M_pow_1178 = 1;
    for (int i = 0; i < 1178; ++i) M_pow_1178 *= M;

    uint64_t P6 = S_X * modinv64(M_pow_1178); // S_X * M_INV^1178

    printf("P6 = %016llx\n", (unsigned long long)P6);

    // Right table: backward from P6, 3 steps
    // right_table[state_after_3_bwd_steps] = (b3, b4, b5)
    std::unordered_map<uint64_t, uint32_t> right_table;
    right_table.reserve(HALF_SIZE);

    for (uint32_t b3 = 0; b3 < 256; ++b3) {
        for (uint32_t b4 = 0; b4 < 256; ++b4) {
            for (uint32_t b5 = 0; b5 < 256; ++b5) {
                // Forward from some R: step(step(step(R,b3),b4),b5) = P6
                // So: R = bwd(bwd(bwd(P6, b5), b4), b3)
                // bwd(S, b): S = (prev ^ LOOKUP[b]) * M → prev = S*M_INV ^ LOOKUP[b]
                uint64_t s = P6;
                s = s * M_INV64 ^ LOOKUP[b5];
                s = s * M_INV64 ^ LOOKUP[b4];
                s = s * M_INV64 ^ LOOKUP[b3];
                // s = R, the state BEFORE bytes[3..5] are applied
                uint32_t packed = (b3 << 16) | (b4 << 8) | b5;
                right_table[s] = packed;
            }
        }
    }
    printf("Right table built: %zu entries\n", right_table.size());
    fflush(stdout);

    // Left search: forward from S_B, 3 steps, find collision with right_table
    bool found = false;
    uint8_t sol[6] = {0};

    for (uint32_t b0 = 0; b0 < 256 && !found; ++b0) {
        for (uint32_t b1 = 0; b1 < 256 && !found; ++b1) {
            for (uint32_t b2 = 0; b2 < 256 && !found; ++b2) {
                uint64_t s = step_fwd(step_fwd(step_fwd(S_B, b0), b1), b2);
                auto it = right_table.find(s);
                if (it != right_table.end()) {
                    uint32_t packed = it->second;
                    sol[0] = b0; sol[1] = b1; sol[2] = b2;
                    sol[3] = (packed >> 16) & 0xff;
                    sol[4] = (packed >>  8) & 0xff;
                    sol[5] = packed & 0xff;
                    found = true;
                }
            }
        }
        if (b0 % 32 == 0) { printf("  left scan: b0=%u/255\r", b0); fflush(stdout); }
    }
    printf("\n");

    if (!found) {
        printf("No 3+3 solution found (expected: probability ~2^{-16} per attempt).\n");
        printf("Run multiple times or increase HALF to 4 (requires ~32GB RAM).\n");
        return 1;
    }

    printf("FOUND! Bytes[0..5] = ");
    for (int i = 0; i < 6; ++i) printf("%02x ", sol[i]);
    printf("\n");

    // Build full padding: sol[0..5] then 1178 zeros
    uint8_t padding[1184] = {0};
    memcpy(padding, sol, 6);

    // Verify
    uint64_t S_test = hash_bytes(S_B, padding, 1184);
    printf("Verify: S_test = %016llx\n", (unsigned long long)S_test);
    printf("S_X    = %016llx\n", (unsigned long long)S_X);
    printf("Match: %s\n", S_test == S_X ? "YES ✓" : "NO ✗");

    if (S_test == S_X) {
        // Print as JS hex array
        printf("\n// JavaScript: custom section padding (1184 bytes)\n");
        printf("const padding = new Uint8Array(1184);\n");
        for (int i = 0; i < 6; ++i)
            if (sol[i]) printf("padding[%d] = 0x%02x;\n", i, sol[i]);
        printf("// (bytes 6..1183 are 0x00)\n");
    }

    return S_test == S_X ? 0 : 1;
}
