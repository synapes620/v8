// Birthday attack: find 8-byte prefix so hash(S_B, b[0..7], 0*1176) = S_X
// Build: g++ -O3 -std=c++17 hash_solve_fast.cc -o hash_solve_fast
// Runtime: 10-20 min, Memory: 6 GB (falls back to 1.5 GB if unavailable)
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <chrono>

static constexpr uint64_t M = 0xC6A4A7935BD1E995ULL;

static uint64_t modinv64(uint64_t a) {
    uint64_t x = a;
    for (int i = 0; i < 6; ++i) x *= 2 - a * x;
    return x;
}
static const uint64_t M_INV = modinv64(M);
static uint64_t LOOKUP[256];

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

static const uint8_t WIRE_1FN[] = {
    0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
    0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
    0x03,0x02,0x01,0x00,
    0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
    0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b
};
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

// Open-addressed hash table using UINT64_MAX as "empty" sentinel.
// Prob of sentinel collision: 2^-64 per entry — negligible.
struct HTable {
    uint64_t *states = nullptr;
    uint32_t *keys   = nullptr;
    uint32_t cap = 0, mask = 0;

    bool alloc(uint32_t capacity) {
        cap = capacity; mask = cap - 1;
        states = (uint64_t*)malloc((size_t)cap * 8);
        keys   = (uint32_t*)malloc((size_t)cap * 4);
        return states && keys;
    }
    void clear() { memset(states, 0xff, (size_t)cap * 8); }
    void insert(uint64_t s, uint32_t k) {
        // skip sentinel value (2^-64 chance; we just lose one entry)
        if (s == ~0ULL) return;
        uint32_t slot = (uint32_t)(s >> 33) & mask;
        while (states[slot] != ~0ULL) {
            if (states[slot] == s) return; // duplicate state: keep first
            slot = (slot + 1) & mask;
        }
        states[slot] = s; keys[slot] = k;
    }
    uint32_t lookup(uint64_t s) const {
        if (s == ~0ULL) return ~0u;
        uint32_t slot = (uint32_t)(s >> 33) & mask;
        while (states[slot] != ~0ULL) {
            if (states[slot] == s) return keys[slot];
            slot = (slot + 1) & mask;
        }
        return ~0u;
    }
    void free_mem() { ::free(states); ::free(keys); states = nullptr; keys = nullptr; }
};

int main() {
    init_lookup();
    auto wire200 = build_wire200();

    uint64_t S_start = hash_u64(0, 1225);
    uint64_t S_X     = hash_bytes(S_start, wire200.data(), wire200.size());
    uint64_t S_A     = hash_bytes(S_start, WIRE_1FN, sizeof(WIRE_1FN));
    uint64_t S_B     = hash_bytes(S_A, CUSTOM_HDR, sizeof(CUSTOM_HDR));

    // We want: hash(S_B, b[0..7], 0^1176) = S_X
    // ↔ hash(S_B, b[0..7]) = S_X * M_INV^1176  (since 1176 zero steps each mult by M_INV)
    uint64_t target_8 = S_X;
    for (int i = 0; i < 1176; ++i) target_8 *= M_INV;

    printf("S_B      = %016llx\n", (unsigned long long)S_B);
    printf("S_X      = %016llx\n", (unsigned long long)S_X);
    printf("target_8 = %016llx\n", (unsigned long long)target_8);
    printf("wire200 size = %zu\n", wire200.size());

    // Birthday attack: 4+4 split
    // Left : Q = fwd^4(S_B, b0..b3) → stored in table
    // Right: R = bwd^4(target_8, b7..b4) → looked up in table
    // If Q == R: fwd^4(Q, b4..b7) = target_8 (verified below)
    //
    // Size: N_INSERT entries in N_TABLE = 2*N_INSERT slots (50% load)
    // Prob collision per trial: (N_INSERT)^2 / 2^64
    // For N_INSERT=2^28: prob=2^-8, need ~256 trials, ~20 min total
    // For N_INSERT=2^26: prob=2^-12, need ~4096 trials, ~55 min total

    HTable ht;
    uint32_t N_INSERT, N_TABLE;
    N_INSERT = 1u<<28; N_TABLE = 1u<<29;  // try 6 GB first
    if (!ht.alloc(N_TABLE)) {
        printf("6 GB alloc failed, falling back to 1.5 GB\n");
        N_INSERT = 1u<<26; N_TABLE = 1u<<27;
        if (!ht.alloc(N_TABLE)) { printf("alloc failed\n"); return 1; }
    }
    printf("Table: %u slots (%.1f GB), %u inserts/trial\n",
           N_TABLE, (double)N_TABLE*12.0/1e9, N_INSERT);
    printf("Expected trials: ~%.0f\n",
           (double)(1LLu<<32) * (1LLu<<32) / (double)N_INSERT / (double)N_INSERT);
    fflush(stdout);

    // LCG: enumerate 4-byte values in pseudo-random order (full period)
    static constexpr uint32_t A = 1664525u, C = 1013904223u;

    auto t0 = std::chrono::steady_clock::now();
    bool found = false;
    uint32_t found_lk = 0, found_rk = 0;

    for (uint32_t trial = 0; trial < 65536 && !found; ++trial) {
        // Build LEFT table
        ht.clear();
        uint32_t lk = trial * 2654435761u;
        for (uint32_t i = 0; i < N_INSERT; ++i) {
            lk = lk * A + C;
            uint8_t b0=lk>>24, b1=(lk>>16)&0xff, b2=(lk>>8)&0xff, b3=lk&0xff;
            uint64_t Q = fwd(fwd(fwd(fwd(S_B, b0), b1), b2), b3);
            ht.insert(Q, lk);
        }

        // Check RIGHT side
        uint32_t rk = trial * 2654435761u ^ 0xDEADBEEFu;
        for (uint32_t i = 0; i < N_INSERT && !found; ++i) {
            rk = rk * A + C;
            uint8_t b4=rk>>24, b5=(rk>>16)&0xff, b6=(rk>>8)&0xff, b7=rk&0xff;
            uint64_t R = bwd(bwd(bwd(bwd(target_8, b7), b6), b5), b4);
            uint32_t hit = ht.lookup(R);
            if (hit != ~0u) { found_lk = hit; found_rk = rk; found = true; }
        }

        if ((trial & 15) == 0) {
            auto t1 = std::chrono::steady_clock::now();
            printf("  trial %u, %.1f s\r", trial,
                   std::chrono::duration<double>(t1-t0).count());
            fflush(stdout);
        }
    }

    ht.free_mem();
    if (!found) { printf("\nNo solution in 65536 trials.\n"); return 1; }

    auto t1 = std::chrono::steady_clock::now();
    printf("\nFound in %.1f s!\n", std::chrono::duration<double>(t1-t0).count());

    uint8_t b[8];
    b[0]=found_lk>>24; b[1]=(found_lk>>16)&0xff;
    b[2]=(found_lk>>8)&0xff; b[3]=found_lk&0xff;
    b[4]=found_rk>>24; b[5]=(found_rk>>16)&0xff;
    b[6]=(found_rk>>8)&0xff; b[7]=found_rk&0xff;

    // Verify 8-step hash
    uint64_t check = S_B;
    for (int i = 0; i < 8; ++i) check = fwd(check, b[i]);
    printf("b[0..7]=%02x %02x %02x %02x %02x %02x %02x %02x\n",
           b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
    printf("hash8=%016llx target=%016llx %s\n",
           (unsigned long long)check, (unsigned long long)target_8,
           check==target_8?"OK":"MISMATCH!");
    if (check != target_8) return 1;

    // Verify full 1184-byte padding (b[0..7] then 1176 zeros)
    uint64_t S_test = check;
    for (int i = 8; i < 1184; ++i) S_test = fwd(S_test, 0);
    printf("full=%016llx S_X=%016llx %s\n",
           (unsigned long long)S_test, (unsigned long long)S_X,
           S_test==S_X?"OK":"MISMATCH!");
    if (S_test != S_X) return 1;

    printf("\n=== SOLUTION ===\n");
    printf("const pad = new Uint8Array(1184);\n");
    for (int i = 0; i < 8; ++i)
        if (b[i]) printf("pad[%d] = 0x%02x;\n", i, b[i]);
    printf("// (pad[8..1183] remain 0x00)\n");
    return 0;
}
