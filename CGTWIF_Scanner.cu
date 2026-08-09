/* ============================================================================
 *  CGTWIF_Scanner  --  GPU engine #1  (delta-table odometer)
 * ----------------------------------------------------------------------------
 *  Recovers any number of missing Base58 characters in a Bitcoin WIF key.
 *  Unknown slots may sit anywhere in the string (contiguous or scattered).
 *
 *  Numeric model
 *  -------------
 *  A WIF string is a base-58 positional number:
 *
 *        N = SUM  digit(i) * 58^(L-1-i)
 *
 *  Every unknown slot h contributes an independent term  d_h * 58^(L-1-p_h),
 *  so the host can pre-bake, for each slot and each of the 58 digits, the
 *  exact 320-bit delta.  The kernel therefore never multiplies - the inner
 *  loop is one 5-limb PTX add-with-carry chain.
 *
 *  Filter chain (instruction count per candidate is what sets the key rate)
 *  ----------------------------------------------------------------------
 *      gate A  1 compare   the 38-byte payload sits right-aligned in a
 *                          40-byte window, so window[0..1] must be zero and
 *                          window[2] must be 0x80  ->  (v[4]>>40) == 0x80
 *      gate B  1 compare   compression flag payload[33] == 0x01
 *      gate C  sha256d     survives at 2^-32
 *
 *  Gates A+B kill ~all candidates for a couple of ALU ops, so the expensive
 *  double-SHA only runs on a vanishing fraction of the keyspace.
 *
 *  Output
 *  ------
 *      found.txt         every checksum-valid WIF discovered
 *      wifaddfound.txt   WIF + both addresses + hex privkey when a generated
 *                        address is present in btc.txt
 *
 *  Build: build.bat in this folder
 * ==========================================================================*/

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <random>

#include "cryptographytube/lib/Int.h"
#include "cryptographytube/lib/SECP256k1.h"
#include "cryptographytube/lib/util.h"

#define B58AL      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#define CGT_SLOTS  25      /* unknown-slot ceiling in sequential mode        */
#define RND_MAX    35      /* unknown-slot ceiling in random-sampling mode   */
#define CGT_TPB    256     /* threads per block                              */
#define CGT_LANE   8192    /* candidates walked per thread per launch        */
#define CGT_LANE_R 2       /* random-mode 58x58 tiles per thread per launch  */
#define CGT_SINK   4096    /* device hit-buffer capacity                     */

/* --- 5 x uint64 little-endian limb order: limb 0 = least significant ------
 * The 40-byte big-endian window maps as
 *      window[32..39] -> limb 0      window[0..7] -> limb 4
 * which is what lets the payload gates collapse into single compares.
 * ------------------------------------------------------------------------*/
__constant__ uint64_t k_anchor[5];                  /* fixed part of the key */
__constant__ int      k_slots;
__constant__ uint64_t k_wtR[RND_MAX][5];            /* weight 58^(L-1-pos) per slot */

/* ---------------------- 5-limb add, PTX carry chain --------------------- */
__device__ __forceinline__ void cgt_add(uint64_t* a, const uint64_t* b) {
    asm volatile (
        "add.cc.u64  %0, %0, %5;\n\t"
        "addc.cc.u64 %1, %1, %6;\n\t"
        "addc.cc.u64 %2, %2, %7;\n\t"
        "addc.cc.u64 %3, %3, %8;\n\t"
        "addc.u64    %4, %4, %9;"
        : "+l"(a[0]), "+l"(a[1]), "+l"(a[2]), "+l"(a[3]), "+l"(a[4])
        : "l"(b[0]), "l"(b[1]), "l"(b[2]), "l"(b[3]), "l"(b[4])
    );
}

/* ---------------------- 5-limb subtract, borrow chain ------------------- */
__device__ __forceinline__ void cgt_sub(uint64_t* a, const uint64_t* b) {
    asm volatile (
        "sub.cc.u64  %0, %0, %5;\n\t"
        "subc.cc.u64 %1, %1, %6;\n\t"
        "subc.cc.u64 %2, %2, %7;\n\t"
        "subc.cc.u64 %3, %3, %8;\n\t"
        "subc.u64    %4, %4, %9;"
        : "+l"(a[0]), "+l"(a[1]), "+l"(a[2]), "+l"(a[3]), "+l"(a[4])
        : "l"(b[0]), "l"(b[1]), "l"(b[2]), "l"(b[3]), "l"(b[4])
    );
}

/* ============================ SHA-256 (device) ============================
 * Single-block compressor kept as a rolling 16-register window so the whole
 * schedule lives in registers on every arch from Turing to Blackwell.
 * ========================================================================*/
__constant__ uint32_t k_rc[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__device__ __forceinline__ uint32_t rr(uint32_t x, uint32_t n) {
    uint32_t d;
    asm("shf.r.clamp.b32 %0, %1, %2, %3;" : "=r"(d) : "r"(x), "r"(x), "r"(n));
    return d;
}

/* Only h[0] of the second hash is ever needed (the 4 checksum bytes), so the
 * caller can stop after the first output word - but we return all eight from
 * pass one because pass two consumes them. */
__device__ void cgt_sha(const uint32_t in[16], uint32_t out[8]) {
    uint32_t w[16];
#pragma unroll
    for (int i = 0; i < 16; i++) w[i] = in[i];

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

#pragma unroll
    for (int r = 0; r < 64; r++) {
        uint32_t wv;
        if (r < 16) {
            wv = w[r];
        } else {
            uint32_t x = w[(r + 1) & 15], y = w[(r + 14) & 15];
            wv = w[r & 15] += (rr(x, 7) ^ rr(x, 18) ^ (x >> 3))
                            + w[(r + 9) & 15]
                            + (rr(y, 17) ^ rr(y, 19) ^ (y >> 10));
        }
        uint32_t t1 = h + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25))
                        + (g ^ (e & (f ^ g))) + k_rc[r] + wv;
        uint32_t t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22))
                        + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    out[0] = a + 0x6a09e667; out[1] = b + 0xbb67ae85;
    out[2] = c + 0x3c6ef372; out[3] = d + 0xa54ff53a;
    out[4] = e + 0x510e527f; out[5] = f + 0x9b05688c;
    out[6] = g + 0x1f83d9ab; out[7] = h + 0x5be0cd19;
}

/* --------------------------------------------------------------------------
 * Checksum test.  PAY is a template parameter so the word packing and the
 * message length fold into immediates at compile time.
 *   PAY == 38 : payload occupies window[2..39], body = window[2..35]
 *   PAY == 37 : payload occupies window[3..39], body = window[3..35]
 * ------------------------------------------------------------------------*/
template <int PAY>
__device__ __forceinline__ bool cgt_checksum(const uint64_t* v) {
    uint32_t m[16], h1[8], h2[8];

    if (PAY == 38) {
        m[0] = (uint32_t)(v[4] >> 16);
        m[1] = (uint32_t)((v[4] & 0xffffULL) << 16 | v[3] >> 48);
        m[2] = (uint32_t)((v[3] & 0xffffffffffffULL) >> 16);
        m[3] = (uint32_t)((v[3] & 0xffffULL) << 16 | v[2] >> 48);
        m[4] = (uint32_t)((v[2] & 0xffffffffffffULL) >> 16);
        m[5] = (uint32_t)((v[2] & 0xffffULL) << 16 | v[1] >> 48);
        m[6] = (uint32_t)((v[1] & 0xffffffffffffULL) >> 16);
        m[7] = (uint32_t)((v[1] & 0xffffULL) << 16 | v[0] >> 48);
        m[8] = ((uint32_t)((v[0] & 0xffffffffffffULL) >> 16) & 0xffff0000u) | 0x8000u;
        m[15] = 0x110;                       /* 34 bytes */
    } else {
        m[0] = (uint32_t)(v[4] >> 8);
        m[1] = (uint32_t)((v[4] & 0xffULL) << 24 | v[3] >> 40);
        m[2] = (uint32_t)((v[3] & 0xffffffffffULL) >> 8);
        m[3] = (uint32_t)((v[3] & 0xffULL) << 24 | v[2] >> 40);
        m[4] = (uint32_t)((v[2] & 0xffffffffffULL) >> 8);
        m[5] = (uint32_t)((v[2] & 0xffULL) << 24 | v[1] >> 40);
        m[6] = (uint32_t)((v[1] & 0xffffffffffULL) >> 8);
        m[7] = (uint32_t)((v[1] & 0xffULL) << 24 | v[0] >> 40);
        m[8] = ((uint32_t)((v[0] & 0xffffffffffULL) >> 8) & 0xff000000u) | 0x800000u;
        m[15] = 0x108;                       /* 33 bytes */
    }
#pragma unroll
    for (int i = 9; i < 15; i++) m[i] = 0;

    cgt_sha(m, h1);

#pragma unroll
    for (int i = 0; i < 8; i++) m[i] = h1[i];
    m[8] = 0x80000000u;
#pragma unroll
    for (int i = 9; i < 15; i++) m[i] = 0;
    m[15] = 0x100;                           /* 32 bytes */
    cgt_sha(m, h2);

    /* stored checksum = window[36..39] = low 32 bits of limb 0 */
    return (uint32_t)v[0] == h2[0];
}

/* ---- the two cheap gates, folded to single compares -------------------- */
template <int PAY>
__device__ __forceinline__ bool cgt_gate(const uint64_t* v) {
    if (PAY == 38) {
        /* window[0]=window[1]=0 and window[2]=0x80 */
        if ((v[4] >> 40) != 0x80ULL) return false;
        /* payload[33] -> window[35] -> byte 4 from the end of limb 0 */
        return ((v[0] >> 32) & 0xFFULL) == 0x01ULL;
    } else {
        /* window[0..2]=0 and window[3]=0x80 */
        return (v[4] >> 32) == 0x80ULL;
    }
}

/* 5-limb  r = b * m   (m in 0..57) : forward decl, defined below */
__device__ __forceinline__ void cgt_scale(uint64_t* r, const uint64_t* b, uint32_t m);

/* ============================== main kernel ==============================
 * Each thread owns CGT_LANE consecutive candidate indices.  It materialises
 * the first one by summing per-slot deltas, then walks forward with a pure
 * add odometer: the fast slot steps by one digit; only on a 58-wrap does the
 * thread rebuild from the anchor.
 * ========================================================================*/
template <int PAY>
__global__ void cgt_scan(uint64_t origin, uint64_t limit,
                         uint32_t* __restrict__ sink,
                         uint32_t* __restrict__ sinkCount)
{
    uint64_t tile = origin + ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x);
    const int slots = k_slots;
    const uint32_t nB = (slots >= 2) ? 58u : 1u;
    uint64_t head = tile * (uint64_t)(nB * 58u);
    if (head >= limit) return;

    const int sA = slots - 1;                 /* fastest  digit -> inner    */
    const int sB = slots >= 2 ? slots - 2 : 0;/* 2nd fast digit -> outer    */

    /* --- seed the tile: one scale per coarse slot.  Setup runs once per 3364
     * candidates, so the multiply is free (and needs no delta table). --- */
    uint64_t v[5];
    v[0] = k_anchor[0]; v[1] = k_anchor[1]; v[2] = k_anchor[2];
    v[3] = k_anchor[3]; v[4] = k_anchor[4];
    {
        uint64_t q = tile;
        for (int i = sB - 1; i >= 0; i--) {
            uint32_t d = (uint32_t)(q % 58); q /= 58;
            if (d) { uint64_t t[5]; cgt_scale(t, k_wtR[i], d); cgt_add(v, t); }
        }
    }

    /* --- warp-uniform stride vectors: no table traffic in the hot loop --- */
    uint64_t stepA[5], stepB[5];
    stepA[0]=k_wtR[sA][0]; stepA[1]=k_wtR[sA][1]; stepA[2]=k_wtR[sA][2];
    stepA[3]=k_wtR[sA][3]; stepA[4]=k_wtR[sA][4];
    stepB[0]=k_wtR[sB][0]; stepB[1]=k_wtR[sB][1]; stepB[2]=k_wtR[sB][2];
    stepB[3]=k_wtR[sB][3]; stepB[4]=k_wtR[sB][4];

    const uint64_t rem = limit - head;
    const bool whole = (rem >= (uint64_t)nB * 58u);

    /* The tail tile is the only one that can run past `limit`, so the bounds
     * test is hoisted out of the hot path entirely: every full tile runs a
     * branch-free 58-step accumulation. */
    for (uint32_t dB = 0; dB < nB; dB++) {
        uint64_t row[5];
        row[0]=v[0]; row[1]=v[1]; row[2]=v[2]; row[3]=v[3]; row[4]=v[4];

        if (whole) {
#pragma unroll 4
            for (uint32_t dA = 0; dA < 58u; dA++) {
                if (cgt_gate<PAY>(row) && cgt_checksum<PAY>(row)) {
                    uint32_t at = atomicAdd(sinkCount, 1u);
                    if (at < CGT_SINK) {
                        uint64_t id = head + (uint64_t)dB * 58u + dA;
                        sink[at * 2 + 0] = (uint32_t)id;
                        sink[at * 2 + 1] = (uint32_t)(id >> 32);
                    }
                }
                cgt_add(row, stepA);
            }
        } else {
            for (uint32_t dA = 0; dA < 58u; dA++) {
                uint64_t ofs = (uint64_t)dB * 58u + dA;
                if (ofs >= rem) return;
                if (cgt_gate<PAY>(row) && cgt_checksum<PAY>(row)) {
                    uint32_t at = atomicAdd(sinkCount, 1u);
                    if (at < CGT_SINK) {
                        uint64_t id = head + ofs;
                        sink[at * 2 + 0] = (uint32_t)id;
                        sink[at * 2 + 1] = (uint32_t)(id >> 32);
                    }
                }
                cgt_add(row, stepA);
            }
        }
        cgt_add(v, stepB);
    }
}

/* ===================== random-sampling mode (engine #1) =================
 * Bypasses the 58^slots < 2^64 ceiling: coarse slots are filled with
 * splitmix64-random digits (deterministic in gid/lane/slot so a survivor
 * can be regenerated host-side), while the two fastest slots keep the exact
 * 58x58 pure-add odometer of cgt_scan - so throughput stays at engine-#1
 * speed no matter how many characters are missing (1..RND_MAX).
 * ======================================================================*/
__host__ __device__ __forceinline__ uint64_t cgt_mix(uint64_t z) {
    z += 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
__host__ __device__ __forceinline__ uint32_t cgt_rdigit(uint64_t seed, uint64_t gid,
                                                        uint32_t lane, int slot) {
    uint64_t k = cgt_mix(seed ^ cgt_mix(gid * (uint64_t)CGT_LANE_R + lane));
    return (uint32_t)(cgt_mix(k + (uint64_t)slot * 0x9e3779b97f4a7c15ULL) % 58ULL);
}
/* 5-limb  r = b * m   (m in 0..57) : widening multiply + PTX carry ripple */
__device__ __forceinline__ void cgt_scale(uint64_t* r, const uint64_t* b, uint32_t m) {
    uint64_t mm = m, hi;
    r[0] = b[0] * mm;              hi = __umul64hi(b[0], mm);
    uint64_t p1 = b[1] * mm,       h1 = __umul64hi(b[1], mm);
    uint64_t p2 = b[2] * mm,       h2 = __umul64hi(b[2], mm);
    uint64_t p3 = b[3] * mm,       h3 = __umul64hi(b[3], mm);
    uint64_t p4 = b[4] * mm;
    asm volatile("add.cc.u64 %0,%4,%8; addc.cc.u64 %1,%5,%9;"
                 "addc.cc.u64 %2,%6,%10; addc.u64 %3,%7,%11;"
        : "=l"(r[1]),"=l"(r[2]),"=l"(r[3]),"=l"(r[4])
        : "l"(p1),"l"(p2),"l"(p3),"l"(p4),
          "l"(hi),"l"(h1),"l"(h2),"l"(h3));
}

template <int PAY>
__global__ void cgt_rand(uint64_t seed, uint32_t* __restrict__ sink,
                         uint32_t* __restrict__ sinkCount)
{
    uint64_t gid  = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t warp = gid >> 5;              /* warp-coherent coarse digits    */
    uint32_t lin  = (uint32_t)(gid & 31);  /* lane inside the warp: 0..31    */
    const int slots = k_slots;
    const int sA = slots - 1;
    const int sB = slots >= 2 ? slots - 2 : 0;
    const uint32_t nB = (slots >= 2) ? 58u : 1u;
    const int loC = sB - 1;                 /* lowest-weight coarse slot      */

    uint64_t stepA[5], stepB[5];
    stepA[0]=k_wtR[sA][0]; stepA[1]=k_wtR[sA][1]; stepA[2]=k_wtR[sA][2];
    stepA[3]=k_wtR[sA][3]; stepA[4]=k_wtR[sA][4];
    stepB[0]=k_wtR[sB][0]; stepB[1]=k_wtR[sB][1]; stepB[2]=k_wtR[sB][2];
    stepB[3]=k_wtR[sB][3]; stepB[4]=k_wtR[sB][4];

    for (uint32_t lane = 0; lane < CGT_LANE_R; lane++) {
        uint64_t v[5];
        v[0]=k_anchor[0]; v[1]=k_anchor[1]; v[2]=k_anchor[2];
        v[3]=k_anchor[3]; v[4]=k_anchor[4];
        /* Coarse digits are keyed on the WARP id, not the thread id, so all
         * 32 lanes of a warp see the same version/flag byte the gate checks.
         * That keeps the cheap-reject / SHA decision warp-uniform - no lane
         * stalls a full warp on a lone SHA (the "poisoned warp" that dropped
         * front/tail masks to <6 Gkey/s).  The lowest-weight coarse slot is
         * nudged by the in-warp lane (0..31) so the 32 threads still walk 32
         * distinct candidate blocks - that slot is far below the version and
         * flag bytes, so gate coherence is preserved. */
        for (int i = 0; i < sB; i++) {
            uint32_t d = cgt_rdigit(seed, warp, lane, i);
            if (i == loC) { d += lin; if (d >= 58u) d -= 58u; }
            if (d) { uint64_t t[5]; cgt_scale(t, k_wtR[i], d); cgt_add(v, t); }
        }
        for (uint32_t dB = 0; dB < nB; dB++) {
            uint64_t row[5];
            row[0]=v[0]; row[1]=v[1]; row[2]=v[2]; row[3]=v[3]; row[4]=v[4];
#pragma unroll 4
            for (uint32_t dA = 0; dA < 58u; dA++) {
                if (cgt_gate<PAY>(row) && cgt_checksum<PAY>(row)) {
                    uint32_t at = atomicAdd(sinkCount, 1u);
                    if (at < CGT_SINK) {
                        sink[at * 4 + 0] = (uint32_t)gid;
                        sink[at * 4 + 1] = (uint32_t)(gid >> 32);
                        sink[at * 4 + 2] = lane;
                        sink[at * 4 + 3] = dB * 58u + dA;
                    }
                }
                cgt_add(row, stepA);
            }
            cgt_add(v, stepB);
        }
    }
}

/* ============================== host side ============================== */
static int b58val(char c) {
    const char* p = strchr(B58AL, c);
    return p ? (int)(p - B58AL) : -1;
}
static bool isHole(char c) {
    /* X and x are valid Base58 chars (they occur in real WIF prefixes),
       so only non-Base58 markers are treated as unknown slots */
    return c == '?' || c == '*' || c == '.';
}

/* Int -> 5 little-endian uint64 limbs of the 40-byte big-endian window */
static void intToLimbs(Int& v, uint64_t out[5]) {
    for (int l = 0; l < 5; l++) {
        uint64_t w = 0;
        for (int b = 0; b < 8; b++) w |= (uint64_t)v.GetByte(l * 8 + b) << (b * 8);
        out[l] = w;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("\n  ============================================================\n");
        printf("      CGTWIF_Scanner   -   GPU engine #1  (delta odometer)\n");
        printf("      cryptographytube      |      Author: Sisujhon\n");
        printf("  ============================================================\n\n");
        printf("  Usage:\n    CGTWIF_Scanner <mask> [-d dev] [-btc btc.txt]\n");
        printf("                   [-out found.txt] [-hit wifaddfound.txt] [-q] [-r]\n");
        printf("                   [-start <tail>] [-end <tail>]\n\n");
        printf("  mask : WIF string, unknown chars written as  ? * .\n");
        printf("  e.g. : KwDiBf89QgGbjEhKnhXJ?H7LrciVrZ?3qYjgd9M7?FU73sVHnoWn\n");
        printf("  -q   : quiet, do not print every checksum-valid key\n");
        printf("  -r   : random sampling (for keyspace > 2^64)\n");
        printf("  -start/-end : Base58 chars filling the unknowns, one per hole.\n");
        printf("                Scans that inclusive range: sequential if count\n");
        printf("                < 2^64, or add -r to random-sample a wide range.\n\n");
        return 1;
    }

    std::string mask;
    int dev = 0;
    bool quiet = false, randMode = false;
    std::string btcFile = "btc.txt", outFile = "found.txt", hitFile = "wifaddfound.txt";
    std::string startTail, endTail;                 /* -start / -end range    */

    /* mask may be given positionally (first arg) or via -mask; -f is an
       alias for -btc so keyhunt-style command lines also work.            */
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-d")    && i + 1 < argc) dev     = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-mask") && i + 1 < argc) mask    = argv[++i];
        else if ((!strcmp(argv[i], "-btc") ||
                  !strcmp(argv[i], "-f"))  && i + 1 < argc) btcFile = argv[++i];
        else if (!strcmp(argv[i], "-out") && i + 1 < argc) outFile = argv[++i];
        else if (!strcmp(argv[i], "-hit") && i + 1 < argc) hitFile = argv[++i];
        else if (!strcmp(argv[i], "-start") && i + 1 < argc) startTail = argv[++i];
        else if (!strcmp(argv[i], "-end")   && i + 1 < argc) endTail   = argv[++i];
        else if (!strcmp(argv[i], "-q")) quiet = true;
        else if (!strcmp(argv[i], "-r")) randMode = true;
        else if (argv[i][0] != '-' && mask.empty()) mask = argv[i];
    }

    int len = (int)mask.length();
    if (len != 51 && len != 52) {
        printf("  ERROR: WIF length must be 51 (uncompressed) or 52 (compressed), got %d\n", len);
        return 1;
    }
    bool comp = (len == 52);
    int payload = comp ? 38 : 37;

    /* ---- holes, anchor, per-slot deltas -------------------------------- */
    std::vector<int> holes;
    std::vector<Int> pw(len);
    pw[0].SetInt32(1);
    for (int i = 1; i < len; i++) { pw[i].Set(&pw[i - 1]); pw[i].Mult((uint64_t)58); }

    Int anchor; anchor.SetInt32(0);
    for (int i = 0; i < len; i++) {
        char c = mask[i];
        if (isHole(c)) { holes.push_back(i); continue; }
        int dv = b58val(c);
        if (dv < 0) { printf("  ERROR: '%c' at position %d is not Base58\n", c, i + 1); return 1; }
        Int term; term.Set(&pw[len - 1 - i]); term.Mult((uint64_t)dv);
        anchor.Add(&term);
    }
    int slots = (int)holes.size();
    int slotCap = randMode ? RND_MAX : CGT_SLOTS;
    if (slots < 1 || slots > slotCap) {
        printf("  ERROR: need 1..%d unknowns, mask has %d%s\n", slotCap, slots,
               (!randMode && slots > CGT_SLOTS) ? "   (use -r for more)" : "");
        return 1;
    }

    /* ---- optional -start/-end tail range ------------------------------- *
     * start/end are the actual Base58 characters that fill the unknown
     * slots (one char per hole, in order).  We scan every combination from
     * start to end inclusive.  The slice may be < 2^64 even when 58^slots is
     * astronomically large, so a range lets a 25-char tail be scanned in
     * bounded exhaustive chunks.  Correct for a contiguous run of holes. */
    bool rangeMode = !startTail.empty() || !endTail.empty();

    /* -r with NO -start/-end  =>  sweep the WHOLE keyspace and EXIT --------- *
     * Plain -r used to sample at random forever. When the unknowns form one
     * contiguous block we synthesise the full tail range "1..1" .. "z..z" so
     * -r walks all 58^slots combinations exactly once (no repeat / skip / miss)
     * and auto-exits, exactly like an explicit range. Non-contiguous unknowns
     * can't be window-tiled, so they keep using the unbounded random sampler. */
    bool autoFull = false;
    if (randMode && !rangeMode) {
        bool contiguous = true;
        for (int i = 1; i < slots; i++) if (holes[i] != holes[i-1] + 1) { contiguous = false; break; }
        if (contiguous) {
            startTail.assign(slots, B58AL[0]);        /* all '1' = digit 0  */
            endTail.assign(slots, B58AL[57]);         /* all 'z' = digit 57 */
            rangeMode = true;
            autoFull  = true;
        }
    }
    std::vector<uint32_t> startDig(slots, 0);       /* start digit per slot  */
    uint64_t total = 0;
    bool totalKnown = true;
    Int  rgStart, rgCount, rgScale;                 /* random-range base, count, id->key scale */
    bool rangeRand = false;                         /* -r together with -start/-end */

    if (rangeMode) {
        if (startTail.empty() || endTail.empty()) {
            printf("  ERROR: give both -start and -end\n"); return 1; }
        if ((int)startTail.size() != slots || (int)endTail.size() != slots) {
            printf("  ERROR: -start/-end must be %d chars (one per unknown), got %d/%d\n",
                   slots, (int)startTail.size(), (int)endTail.size()); return 1; }
        for (int i = 1; i < slots; i++) if (holes[i] != holes[i-1] + 1) {
            printf("  ERROR: -start/-end needs the unknowns to be one contiguous block\n");
            return 1; }

        Int startId, endId;                          /* base-58 value of tail */
        startId.SetInt32(0); endId.SetInt32(0);
        Int startContrib; startContrib.SetInt32(0);  /* value folded into key */
        for (int j = 0; j < slots; j++) {
            int sv = b58val(startTail[j]), ev = b58val(endTail[j]);
            if (sv < 0) { printf("  ERROR: -start char '%c' not Base58\n", startTail[j]); return 1; }
            if (ev < 0) { printf("  ERROR: -end char '%c' not Base58\n", endTail[j]); return 1; }
            startDig[j] = (uint32_t)sv;
            Int ws; ws.Set(&pw[slots - 1 - j]); ws.Mult((uint64_t)sv); startId.Add(&ws);
            Int we; we.Set(&pw[slots - 1 - j]); we.Mult((uint64_t)ev); endId.Add(&we);
            Int wc; wc.Set(&pw[len - 1 - holes[j]]); wc.Mult((uint64_t)sv); startContrib.Add(&wc);
        }
        if (startId.IsGreater(&endId)) {
            printf("  ERROR: -start value is greater than -end\n"); return 1; }

        if (randMode) {
            /* random sampling INSIDE the range: no 2^64 cap. Each launch folds
             * a fresh random base into the key, so the count may be huge. The
             * id->key scale is the weight of the lowest hole (holes are the
             * contiguous tail), so contrib(base) = base * rgScale. */
            rangeRand = true;
            rgStart.Set(&startId);
            rgCount.Set(&endId); rgCount.Sub(&startId); rgCount.AddOne();
            rgScale.Set(&pw[len - 1 - holes[slots - 1]]);
            totalKnown = false;                       /* count may exceed 2^64 */
            total = 0;                                /* not used in this mode */
        } else {
            Int diff; diff.Set(&endId); diff.Sub(&startId);   /* count = diff + 1 */
            bool wide = false;
            for (int l = 1; l < 5; l++) if (diff.bits64[l]) wide = true;
            if (wide || diff.bits64[0] == (uint64_t)-1) {
                printf("  ERROR: range is wider than 2^64 - narrow -start/-end, or add -r\n");
                return 1; }
            total = diff.bits64[0] + 1ULL;
            anchor.Add(&startContrib);                /* scan starts at start  */
        }
    } else {
        total = 1;
        for (int i = 0; i < slots; i++) {
            if (total > (uint64_t)-1 / 58) {
                if (!randMode) { printf("  ERROR: keyspace overflows 64-bit (use -r or -start/-end)\n"); return 1; }
                totalKnown = false; break;
            }
            total *= 58;
        }
    }

    cudaDeviceProp prop;
    if (cudaSetDevice(dev) != cudaSuccess || cudaGetDeviceProperties(&prop, dev) != cudaSuccess) {
        printf("  ERROR: cannot open CUDA device %d\n", dev); return 1;
    }

    printf("\n  ============================================================\n");
    printf("      CGTWIF_Scanner   -   GPU engine #1  (delta odometer)\n");
    printf("      cryptographytube      |      Author: Sisujhon\n");
    printf("  ============================================================\n");
    printf("  GPU        : %s  (sm_%d%d, %d SMs)\n", prop.name, prop.major, prop.minor,
           prop.multiProcessorCount);
    printf("  Mask       : %s\n", mask.c_str());
    printf("  Mode       : %s (%d-byte payload)\n", comp ? "COMPRESSED" : "UNCOMPRESSED", payload);
    printf("  Sampling   : %s\n", autoFull ? "RANDOM (full keyspace, every combo once, exits)"
                                            : (rangeRand ? "RANDOM (-start..-end range, every combo once, exits)"
                                            : (randMode ? "RANDOM (unbounded keyspace)"
                                            : (rangeMode ? "SEQUENTIAL (-start..-end range)"
                                                         : "SEQUENTIAL (full sweep)"))));
    printf("  Unknowns   : %d  @ ", slots);
    for (int i = 0; i < slots; i++) printf("%d%s", holes[i] + 1, i + 1 < slots ? "," : "");
    if (rangeMode) printf("\n  Range      : %s .. %s%s", startTail.c_str(), endTail.c_str(),
                          autoFull ? "   (full keyspace)" : "");
    if (rangeRand)      printf("\n  Keyspace   : %s  (random order, full cover, exits at end)\n", rgCount.GetBase10().c_str());
    else if (totalKnown) printf("\n  Keyspace   : %llu\n", (unsigned long long)total);
    else                 printf("\n  Keyspace   : ~58^%d  (> 2^64, random sampling)\n", slots);
    printf("  found.txt  : %s\n", outFile.c_str());
    printf("  hits       : %s   (btc list: %s)\n", hitFile.c_str(), btcFile.c_str());
    printf("  ------------------------------------------------------------\n\n");

    /* ---- upload constants --------------------------------------------- */
    uint64_t hAnchor[5];
    intToLimbs(anchor, hAnchor);
    cudaMemcpyToSymbol(k_anchor, hAnchor, sizeof(hAnchor));

    /* per-slot weight 58^(len-1-pos), all slots - used by both modes */
    static uint64_t hWtR[RND_MAX][5];
    memset(hWtR, 0, sizeof(hWtR));
    for (int s = 0; s < slots; s++)
        intToLimbs(pw[len - 1 - holes[s]], hWtR[s]);
    cudaMemcpyToSymbol(k_wtR, hWtR, sizeof(hWtR));

    cudaMemcpyToSymbol(k_slots, &slots, sizeof(int));

    uint32_t *dSink = NULL, *dCount = NULL;
    cudaMalloc(&dSink, CGT_SINK * 4 * sizeof(uint32_t));
    cudaMalloc(&dCount, sizeof(uint32_t));

    /* ---- btc.txt ------------------------------------------------------ */
    std::set<std::string> btcSet;
    if (FILE* bf = fopen(btcFile.c_str(), "r")) {
        char line[512];
        while (fgets(line, sizeof(line), bf)) {
            std::string a(line);
            while (!a.empty() && (a.back()=='\n'||a.back()=='\r'||a.back()==' '||a.back()=='\t'))
                a.pop_back();
            if (!a.empty()) btcSet.insert(a);
        }
        fclose(bf);
        printf("  Loaded %llu addresses from %s\n\n",
               (unsigned long long)btcSet.size(), btcFile.c_str());
    } else {
        printf("  NOTE: %s not found - checksum hits still go to %s\n\n",
               btcFile.c_str(), outFile.c_str());
    }

    Secp256K1 secp; secp.Init();

    /* ---- random-sampling launch loop (unbounded keyspace) ------------- */
    if (randMode && !rangeRand) {
        const int sA = slots - 1;
        const int sB = slots >= 2 ? slots - 2 : 0;
        const uint32_t nB = (slots >= 2) ? 58u : 1u;
        const uint64_t threads = (uint64_t)prop.multiProcessorCount * CGT_TPB * 256;
        const int blocks = (int)((threads + CGT_TPB - 1) / CGT_TPB);
        const double perLaunch = (double)threads * CGT_LANE_R * nB * 58.0;

        std::mt19937_64 rng(0xC0FFEEULL ^ (uint64_t)time(NULL));
        auto t0 = std::chrono::steady_clock::now();
        double sampled = 0, valid = 0, matched = 0, lastPrint = 0;

        while (true) {
            uint64_t seed = rng();
            cudaMemset(dCount, 0, sizeof(uint32_t));
            if (comp) cgt_rand<38><<<blocks, CGT_TPB>>>(seed, dSink, dCount);
            else      cgt_rand<37><<<blocks, CGT_TPB>>>(seed, dSink, dCount);

            cudaError_t err = cudaDeviceSynchronize();
            if (err != cudaSuccess) {
                printf("\n  CUDA error: %s\n", cudaGetErrorString(err)); break;
            }
            uint32_t hc = 0;
            cudaMemcpy(&hc, dCount, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            if (hc) {
                uint32_t keep = hc > CGT_SINK ? CGT_SINK : hc;
                std::vector<uint32_t> raw(keep * 4);
                cudaMemcpy(raw.data(), dSink, keep * 4 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
                for (uint32_t i = 0; i < keep; i++) {
                    uint64_t gid = ((uint64_t)raw[i*4+1] << 32) | raw[i*4+0];
                    uint32_t lane = raw[i*4+2], comb = raw[i*4+3];
                    uint32_t dB = comb / 58u, dA = comb % 58u;

                    std::string wif = mask;
                    uint64_t warp = gid >> 5;
                    uint32_t lin  = (uint32_t)(gid & 31);
                    int loC = sB - 1;                 /* lowest coarse slot */
                    for (int s = 0; s < sB; s++) {
                        uint32_t d = cgt_rdigit(seed, warp, lane, s);
                        if (s == loC) { d += lin; if (d >= 58u) d -= 58u; }
                        wif[holes[s]] = B58AL[d];
                    }
                    if (slots >= 2) wif[holes[sB]] = B58AL[dB];
                    wif[holes[sA]] = B58AL[dA];

                    unsigned char bin[64]; size_t bl = payload;
                    if (!b58decode(bin, &bl, wif.c_str(), wif.size())) continue;
                    if ((int)bl != payload) continue;
                    char hex[80]; tohex_dst((char*)(bin + 1), 32, hex);

                    valid++;
                    if (FILE* f = fopen(outFile.c_str(), "a")) { fprintf(f, "%s\n", wif.c_str()); fclose(f); }

                    Int pk; pk.SetBase16(hex);
                    Point pub = secp.ComputePublicKey(&pk);
                    unsigned char hC[20], hU[20];
                    secp.GetHash160(P2PKH, true,  pub, hC);
                    secp.GetHash160(P2PKH, false, pub, hU);
                    char aC[64], aU[64];
                    addressToBase58((char*)hC, aC, false);
                    addressToBase58((char*)hU, aU, false);
                    bool hit = btcSet.count(aC) || btcSet.count(aU);
                    if (!quiet || hit)
                        printf("\n  [VALID] %s\n    comp   %s\n    uncomp %s\n    hex    %s\n",
                               wif.c_str(), aC, aU, hex);
                    if (hit) {
                        matched++;
                        const char* which = btcSet.count(aC) ? aC : aU;
                        if (FILE* f = fopen(hitFile.c_str(), "a")) {
                            fprintf(f, "WIF         : %s\n", wif.c_str());
                            fprintf(f, "PRIVKEY_HEX : %s\n", hex);
                            fprintf(f, "ADDR_COMP   : %s\n", aC);
                            fprintf(f, "ADDR_UNCOMP : %s\n", aU);
                            fprintf(f, "MATCHED     : %s\n\n", which);
                            fclose(f);
                        }
                        printf("  *** BTC MATCH %s  ->  %s ***\n", which, hitFile.c_str());
                    }
                }
            }
            sampled += perLaunch;
            double sec = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - t0).count();
            if (sec - lastPrint > 0.4) {
                lastPrint = sec;
                double rate = sec > 0 ? sampled / sec : 0;
                printf("\r  [%7.1fs] sampled %.3e   %8.2f Gkey/s   valid %.0f  match %.0f     ",
                       sec, sampled, rate / 1e9, valid, matched);
                fflush(stdout);
            }
        }
        cudaFree(dSink); cudaFree(dCount);
        return 0;
    }

    /* ---- RANDOM-ORDER full-cover launch loop (-r) ----------------------
     * The range [start,end] - or the whole 58^slots keyspace when no -start/
     * -end was given - can be far wider than 2^64.  We split it into W disjoint
     * windows of `window` combinations each, then visit those windows in a
     * pseudo-RANDOM order that still touches every one EXACTLY once - no repeat,
     * no skip, no miss - and exit the instant the range is covered.  The random
     * order is a full-period LCG  x <- (A*x + C) mod 2^b  over the window index
     * (b = smallest power-of-two exponent with 2^b >= W); by the Hull-Dobell
     * theorem A == 1 (mod 4) and C odd give period EXACTLY 2^b, so it walks all
     * indices in [0,2^b) once.  Indices >= W are skipped (cycle-walk).  A
     * survivor's tail is base + id, rendered straight to Base58. */
    if (rangeRand) {
        const uint64_t tileSpan       = (slots >= 2) ? 58ull * 58ull : 58ull;
        const uint64_t tilesPerLaunch = (uint64_t)prop.multiProcessorCount * CGT_TPB * 256;
        const uint64_t window = tilesPerLaunch * tileSpan;
        const int blocks = (int)((tilesPerLaunch + CGT_TPB - 1) / CGT_TPB);

        Int winI; winI.SetInt32(0); winI.bits64[0] = window;
        const double totalD = rgCount.ToDouble();

        /* number of windows  W = ceil(rgCount / window) */
        Int Wcount; Wcount.Set(&rgCount); Wcount.Add(window - 1ull);
        { Int divW; divW.Set(&winI); Wcount.Div(&divW, NULL); }

        /* b = smallest exponent with 2^b >= W  (LCG modulus M = 2^b) */
        int b = 0; { Int M; M.SetInt32(1); while (M.IsLower(&Wcount)) { M.ShiftL(1); b++; } }

        /* v <- v mod 2^bits  (keep only the low `bits` bits) */
        auto maskLow = [](Int& v, int bits) {
            for (int limb = 0; limb < NB64BLOCK; limb++) {
                int lo = limb * 64;
                if (bits >= lo + 64) continue;
                else if (bits <= lo) v.bits64[limb] = 0;
                else v.bits64[limb] &= ((1ull << (bits - lo)) - 1ull);
            }
        };

        std::mt19937_64 rng(0xC0FFEEull ^ (uint64_t)time(NULL));
        Int A; A.SetInt32(0); A.bits64[0] = 6364136223846793005ull;   /* A == 1 (mod 4) */
        Int C; C.SetInt32(0); C.bits64[0] = (rng() | 1ull); maskLow(C, b);  /* C odd    */
        Int x; x.SetInt32(0); x.bits64[0] = rng();          maskLow(x, b);  /* start    */

        auto t0 = std::chrono::steady_clock::now();
        double lastPrint = 0;
        uint64_t valid = 0, matched = 0;

        Int covered; covered.SetInt32(0);         /* combinations covered so far */
        while (covered.IsLower(&rgCount)) {
            Int off; off.Set(&x); off.Mult(window);       /* window offset = x * window   */
            x.Mult(&A); x.Add(&C); maskLow(x, b);         /* advance LCG to next index    */
            if (!off.IsLower(&rgCount)) continue;         /* index >= W: skip (cycle-walk) */

            /* thisWin = min(window, rgCount - off): clamp the tail window so we
             * never scan a key past `end`, and never come up short. */
            Int remaining; remaining.Set(&rgCount); remaining.Sub(&off);
            uint64_t thisWin = remaining.IsGreater(&winI) ? window : remaining.bits64[0];

            Int base; base.Set(&rgStart); base.Add(&off);    /* base = start + offset */

            Int aL; aL.Set(&anchor);                  /* fold this launch's base */
            Int contrib; contrib.Set(&base); contrib.Mult(&rgScale); aL.Add(&contrib);
            uint64_t hA[5]; intToLimbs(aL, hA);
            cudaMemcpyToSymbol(k_anchor, hA, sizeof(hA));

            cudaMemset(dCount, 0, sizeof(uint32_t));
            if (comp) cgt_scan<38><<<blocks, CGT_TPB>>>(0, thisWin, dSink, dCount);
            else      cgt_scan<37><<<blocks, CGT_TPB>>>(0, thisWin, dSink, dCount);

            cudaError_t err = cudaDeviceSynchronize();
            if (err != cudaSuccess) {
                printf("\n  CUDA error: %s\n", cudaGetErrorString(err)); break;
            }
            uint32_t hc = 0;
            cudaMemcpy(&hc, dCount, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            if (hc) {
                uint32_t keep = hc > CGT_SINK ? CGT_SINK : hc;
                std::vector<uint32_t> raw(keep * 2);
                cudaMemcpy(raw.data(), dSink, keep * 2 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
                for (uint32_t i = 0; i < keep; i++) {
                    uint64_t id = ((uint64_t)raw[i*2+1] << 32) | raw[i*2];

                    Int hv; hv.Set(&base); hv.Add(id);       /* tail value = base+id */
                    std::string bs = hv.GetBaseN(58, (char*)B58AL);
                    std::string wif = mask;
                    int pad = slots - (int)bs.size();
                    for (int s = 0; s < slots; s++)
                        wif[holes[s]] = (s < pad) ? B58AL[0] : bs[s - pad];

                    unsigned char bin[64]; size_t bl = payload;
                    if (!b58decode(bin, &bl, wif.c_str(), wif.size())) continue;
                    if ((int)bl != payload) continue;
                    char hex[80]; tohex_dst((char*)(bin + 1), 32, hex);

                    valid++;
                    if (FILE* f = fopen(outFile.c_str(), "a")) { fprintf(f, "%s\n", wif.c_str()); fclose(f); }

                    Int pk; pk.SetBase16(hex);
                    Point pub = secp.ComputePublicKey(&pk);
                    unsigned char hC[20], hU[20];
                    secp.GetHash160(P2PKH, true,  pub, hC);
                    secp.GetHash160(P2PKH, false, pub, hU);
                    char aC[64], aU[64];
                    addressToBase58((char*)hC, aC, false);
                    addressToBase58((char*)hU, aU, false);
                    bool hit = btcSet.count(aC) || btcSet.count(aU);
                    if (!quiet || hit)
                        printf("\n  [VALID] %s\n    comp   %s\n    uncomp %s\n    hex    %s\n",
                               wif.c_str(), aC, aU, hex);
                    if (hit) {
                        matched++;
                        const char* which = btcSet.count(aC) ? aC : aU;
                        if (FILE* f = fopen(hitFile.c_str(), "a")) {
                            fprintf(f, "WIF         : %s\n", wif.c_str());
                            fprintf(f, "PRIVKEY_HEX : %s\n", hex);
                            fprintf(f, "ADDR_COMP   : %s\n", aC);
                            fprintf(f, "ADDR_UNCOMP : %s\n", aU);
                            fprintf(f, "MATCHED     : %s\n\n", which);
                            fclose(f);
                        }
                        printf("  *** BTC MATCH %s  ->  %s ***\n", which, hitFile.c_str());
                    }
                }
            }
            covered.Add(thisWin);                     /* count this window as done */
            double sec = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - t0).count();
            bool finished = !covered.IsLower(&rgCount);
            if (sec - lastPrint > 0.4 || finished) {
                lastPrint = sec;
                double coveredD = covered.ToDouble();
                double rate = sec > 0 ? coveredD / sec : 0;
                double pct = totalD > 0 ? 100.0 * coveredD / totalD : 100.0;
                printf("\r  [%7.1fs] %6.2f%%  covered %.3e / %.3e  %8.2f Gkey/s   valid %llu  match %llu     ",
                       sec, pct, coveredD, totalD, rate / 1e9,
                       (unsigned long long)valid, (unsigned long long)matched);
                fflush(stdout);
            }
        }

        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        printf("\n\n  Range complete: all %s combinations scanned (random order) in %.2fs   avg %.2f Gkey/s   valid %llu   btc-match %llu\n\n",
               rgCount.GetBase10().c_str(), sec,
               sec > 0 ? rgCount.ToDouble() / sec / 1e9 : 0,
               (unsigned long long)valid, (unsigned long long)matched);
        cudaFree(dSink); cudaFree(dCount);
        return 0;
    }

    /* ---- launch loop -------------------------------------------------- */
    /* one thread per 58x58 tile (or per 58 when there is a single unknown) */
    const uint64_t tileSpan = (slots >= 2) ? 58ull * 58ull : 58ull;
    const uint64_t tileTotal = (total + tileSpan - 1) / tileSpan;
    const uint64_t tilesPerLaunch = (uint64_t)prop.multiProcessorCount * CGT_TPB * 256;

    auto t0 = std::chrono::steady_clock::now();
    uint64_t done = 0, valid = 0, matched = 0;
    double lastPrint = 0;

    for (uint64_t tb = 0; tb < tileTotal; tb += tilesPerLaunch) {
        uint64_t tN = (tb + tilesPerLaunch > tileTotal) ? (tileTotal - tb) : tilesPerLaunch;
        uint64_t chunk = tN * tileSpan;
        if (done + chunk > total) chunk = total - done;
        int blocks = (int)((tN + CGT_TPB - 1) / CGT_TPB);

        cudaMemset(dCount, 0, sizeof(uint32_t));
        if (comp) cgt_scan<38><<<blocks, CGT_TPB>>>(tb, total, dSink, dCount);
        else      cgt_scan<37><<<blocks, CGT_TPB>>>(tb, total, dSink, dCount);

        cudaError_t err = cudaDeviceSynchronize();
        if (err != cudaSuccess) {
            printf("\n  CUDA error: %s\n", cudaGetErrorString(err));
            break;
        }

        uint32_t hc = 0;
        cudaMemcpy(&hc, dCount, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        if (hc) {
            uint32_t keep = hc > CGT_SINK ? CGT_SINK : hc;
            std::vector<uint32_t> raw(keep * 2);
            cudaMemcpy(raw.data(), dSink, keep * 2 * sizeof(uint32_t), cudaMemcpyDeviceToHost);

            for (uint32_t i = 0; i < keep; i++) {
                uint64_t id = ((uint64_t)raw[i*2+1] << 32) | raw[i*2];

                std::string wif = mask;
                uint64_t q = id; uint32_t carry = 0;
                for (int s = slots - 1; s >= 0; s--) {
                    uint32_t add = (uint32_t)(q % 58); q /= 58;
                    uint32_t d = startDig[s] + add + carry;
                    carry = d / 58; d %= 58;
                    wif[holes[s]] = B58AL[d];
                }

                /* b58tobin right-aligns its output inside the buffer it is
                 * told the size of, so we must pass exactly `payload` (not the
                 * 64-byte capacity) - otherwise the 38-byte value lands at
                 * bin[26..63] and bin+1 reads zeros + the 0x80 version byte. */
                unsigned char bin[64]; size_t bl = payload;
                if (!b58decode(bin, &bl, wif.c_str(), wif.size())) continue;
                if ((int)bl != payload) continue;

                char hex[80];
                tohex_dst((char*)(bin + 1), 32, hex);

                valid++;
                if (FILE* f = fopen(outFile.c_str(), "a")) {
                    fprintf(f, "%s\n", wif.c_str()); fclose(f);
                }

                /* WIF -> 64-hex -> both addresses -> btc.txt */
                Int pk; pk.SetBase16(hex);
                Point pub = secp.ComputePublicKey(&pk);
                unsigned char hC[20], hU[20];
                secp.GetHash160(P2PKH, true,  pub, hC);
                secp.GetHash160(P2PKH, false, pub, hU);
                char aC[64], aU[64];
                addressToBase58((char*)hC, aC, false);
                addressToBase58((char*)hU, aU, false);

                bool hit = btcSet.count(aC) || btcSet.count(aU);

                if (!quiet || hit) {
                    printf("\n  [VALID] %s\n    comp   %s\n    uncomp %s\n    hex    %s\n",
                           wif.c_str(), aC, aU, hex);
                }
                if (hit) {
                    matched++;
                    const char* which = btcSet.count(aC) ? aC : aU;
                    if (FILE* f = fopen(hitFile.c_str(), "a")) {
                        fprintf(f, "WIF         : %s\n", wif.c_str());
                        fprintf(f, "PRIVKEY_HEX : %s\n", hex);
                        fprintf(f, "ADDR_COMP   : %s\n", aC);
                        fprintf(f, "ADDR_UNCOMP : %s\n", aU);
                        fprintf(f, "MATCHED     : %s\n\n", which);
                        fclose(f);
                    }
                    printf("  *** BTC MATCH %s  ->  %s ***\n", which, hitFile.c_str());
                }
            }
        }

        done += chunk;
        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        if (sec - lastPrint > 0.4 || done >= total) {
            lastPrint = sec;
            double rate = sec > 0 ? done / sec : 0;
            printf("\r  [%7.1fs] %6.2f%%  %8.2f Gkey/s   valid %llu  match %llu     ",
                   sec, 100.0 * done / total, rate / 1e9,
                   (unsigned long long)valid, (unsigned long long)matched);
            fflush(stdout);
        }
    }

    double sec = std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - t0).count();
    printf("\n\n  Done in %.2fs   scanned %llu   avg %.2f Gkey/s   valid %llu   btc-match %llu\n\n",
           sec, (unsigned long long)done, sec > 0 ? done / sec / 1e9 : 0,
           (unsigned long long)valid, (unsigned long long)matched);

    cudaFree(dSink);
    cudaFree(dCount);
    return 0;
}
