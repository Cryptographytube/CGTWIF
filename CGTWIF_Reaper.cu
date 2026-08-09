/* ============================================================================
 *  CGTWIF_Reaper  --  GPU engine #2  (Horner walker, no delta tables)
 * ----------------------------------------------------------------------------
 *  Same job as engine #1, opposite trade-off.
 *
 *  Engine #1 pre-bakes 12 x 58 x 320-bit deltas into constant memory and the
 *  kernel only ever adds.  That eats 34 KB of __constant__ and forces every
 *  lane to re-read the table on each odometer wrap.
 *
 *  Engine #2 keeps just ONE 320-bit weight per unknown slot and reconstructs
 *  each candidate with a Horner-style shift-and-multiply directly in
 *  registers.  Constant footprint drops to ~500 bytes so it lives in the
 *  broadcast cache, and there is no table traffic at all.  On top of that:
 *
 *    * work is handed out as a 2-D grid: blockIdx.y selects the coarse digit
 *      combination, blockIdx.x/threadIdx.x sweep the two fastest slots, so
 *      no thread ever divides by 58 in the hot path
 *    * the double-SHA is short-circuited - pass two stops as soon as the
 *      first output word is known, since only 4 checksum bytes matter
 *    * hits are gathered with __ballot_sync + a single warp-leader atomic
 *      instead of one atomic per lane
 *
 *  Output
 *  ------
 *      found.txt         every checksum-valid WIF
 *      wifaddfound.txt   WIF + hex privkey + both addresses on a btc.txt hit
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

#define ALPHA   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#define RP_MAX  35          /* unknown slots supported (random mode)         */
#define RP_LANE 256         /* random candidates walked per thread per launch*/
#define RP_WARP 32
#define RP_TPB  128         /* 4 warps                                       */
#define RP_BAG  4096        /* device hit capacity                           */

/* 320-bit value as 5 x uint64, limb 0 least significant.
 * Byte view: a 40-byte big-endian window, limb4 = window[0..7]. */
__constant__ uint64_t c_fixed[5];        /* contribution of the known chars  */
__constant__ uint64_t c_wt[RP_MAX][5];   /* 58^(L-1-pos) for each hole       */
__constant__ int      c_nholes;
__constant__ int      c_sweepA;          /* index of fastest hole            */
__constant__ int      c_sweepB;          /* index of 2nd fastest hole        */

/* ------------------------- 320-bit primitives --------------------------- */
__device__ __forceinline__ void rp_zero(uint64_t* r) {
    r[0] = r[1] = r[2] = r[3] = r[4] = 0;
}
__device__ __forceinline__ void rp_copy(uint64_t* r, const uint64_t* a) {
    r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3]; r[4]=a[4];
}
__device__ __forceinline__ void rp_acc(uint64_t* r, const uint64_t* a) {
    asm volatile("add.cc.u64 %0,%0,%5; addc.cc.u64 %1,%1,%6;"
                 "addc.cc.u64 %2,%2,%7; addc.cc.u64 %3,%3,%8; addc.u64 %4,%4,%9;"
        : "+l"(r[0]),"+l"(r[1]),"+l"(r[2]),"+l"(r[3]),"+l"(r[4])
        : "l"(a[0]),"l"(a[1]),"l"(a[2]),"l"(a[3]),"l"(a[4]));
}

/* r = a * m  where m < 58 : 5 widening multiplies plus a carry ripple */
__device__ __forceinline__ void rp_scale(uint64_t* r, const uint64_t* a, uint32_t m) {
    uint64_t mm = m, hi;
    r[0] = a[0] * mm;              hi = __umul64hi(a[0], mm);
    uint64_t p1 = a[1] * mm,       h1 = __umul64hi(a[1], mm);
    uint64_t p2 = a[2] * mm,       h2 = __umul64hi(a[2], mm);
    uint64_t p3 = a[3] * mm,       h3 = __umul64hi(a[3], mm);
    uint64_t p4 = a[4] * mm;
    asm volatile("add.cc.u64 %0,%4,%8; addc.cc.u64 %1,%5,%9;"
                 "addc.cc.u64 %2,%6,%10; addc.u64 %3,%7,%11;"
        : "=l"(r[1]),"=l"(r[2]),"=l"(r[3]),"=l"(r[4])
        : "l"(p1),"l"(p2),"l"(p3),"l"(p4),
          "l"(hi),"l"(h1),"l"(h2),"l"(h3));
}

/* ========================= SHA-256, reaper flavour ======================
 * Written as an explicit two-stage pipeline with the message schedule kept
 * in a rolling window.  Stage two is truncated: after round 63 only the 'a'
 * lane is folded, because the caller compares a single word.
 * ======================================================================*/
__device__ __constant__ uint32_t c_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BSIG0(x)  (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x)  (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x)  (ROTR(x, 7) ^ ROTR(x,18) ^ ((x) >>  3))
#define SSIG1(x)  (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

/* full 8-word digest */
__device__ void rp_sha_full(const uint32_t* msg, uint32_t* dig) {
    uint32_t w[16];
#pragma unroll
    for (int i = 0; i < 16; i++) w[i] = msg[i];

    uint32_t s0 = 0x6a09e667, s1 = 0xbb67ae85, s2 = 0x3c6ef372, s3 = 0xa54ff53a;
    uint32_t s4 = 0x510e527f, s5 = 0x9b05688c, s6 = 0x1f83d9ab, s7 = 0x5be0cd19;
    uint32_t a=s0,b=s1,c=s2,d=s3,e=s4,f=s5,g=s6,h=s7;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) wi = w[i];
        else {
            wi = w[i & 15] = w[i & 15] + SSIG0(w[(i+1) & 15])
                           + w[(i+9) & 15] + SSIG1(w[(i+14) & 15]);
        }
        uint32_t T1 = h + BSIG1(e) + (g ^ (e & (f ^ g))) + c_k[i] + wi;
        uint32_t T2 = BSIG0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    dig[0]=s0+a; dig[1]=s1+b; dig[2]=s2+c; dig[3]=s3+d;
    dig[4]=s4+e; dig[5]=s5+f; dig[6]=s6+g; dig[7]=s7+h;
}

/* second pass, first output word only */
__device__ __forceinline__ uint32_t rp_sha_head(const uint32_t* dig) {
    uint32_t w[16];
#pragma unroll
    for (int i = 0; i < 8; i++) w[i] = dig[i];
    w[8] = 0x80000000u;
#pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 0x100;

    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a;
    uint32_t e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) wi = w[i];
        else {
            wi = w[i & 15] = w[i & 15] + SSIG0(w[(i+1) & 15])
                           + w[(i+9) & 15] + SSIG1(w[(i+14) & 15]);
        }
        uint32_t T1 = h + BSIG1(e) + (g ^ (e & (f ^ g))) + c_k[i] + wi;
        uint32_t T2 = BSIG0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    return 0x6a09e667u + a;
}

/* --------------------------------------------------------------------------
 * Envelope gate + checksum.  PLEN folds to an immediate.
 *   PLEN 38 -> payload window[2..39], hashed body window[2..35]
 *   PLEN 37 -> payload window[3..39], hashed body window[3..35]
 * ------------------------------------------------------------------------*/
template <int PLEN>
__device__ __forceinline__ bool rp_envelope(const uint64_t* v) {
    if (PLEN == 38)
        return (v[4] >> 40) == 0x80ULL && ((v[0] >> 32) & 0xFFULL) == 0x01ULL;
    else
        return (v[4] >> 32) == 0x80ULL;
}

template <int PLEN>
__device__ bool rp_reap(const uint64_t* v) {
    if (!rp_envelope<PLEN>(v)) return false;

    uint32_t m[16];
    if (PLEN == 38) {
        m[0] = (uint32_t)(v[4] >> 16);
        m[1] = (uint32_t)((v[4] << 16) | (v[3] >> 48));
        m[2] = (uint32_t)(v[3] >> 16);
        m[3] = (uint32_t)((v[3] << 16) | (v[2] >> 48));
        m[4] = (uint32_t)(v[2] >> 16);
        m[5] = (uint32_t)((v[2] << 16) | (v[1] >> 48));
        m[6] = (uint32_t)(v[1] >> 16);
        m[7] = (uint32_t)((v[1] << 16) | (v[0] >> 48));
        m[8] = ((uint32_t)(v[0] >> 16) & 0xffff0000u) | 0x8000u;
        m[15] = 34 * 8;
    } else {
        m[0] = (uint32_t)(v[4] >> 8);
        m[1] = (uint32_t)((v[4] << 24) | (v[3] >> 40));
        m[2] = (uint32_t)(v[3] >> 8);
        m[3] = (uint32_t)((v[3] << 24) | (v[2] >> 40));
        m[4] = (uint32_t)(v[2] >> 8);
        m[5] = (uint32_t)((v[2] << 24) | (v[1] >> 40));
        m[6] = (uint32_t)(v[1] >> 8);
        m[7] = (uint32_t)((v[1] << 24) | (v[0] >> 40));
        m[8] = ((uint32_t)(v[0] >> 8) & 0xff000000u) | 0x800000u;
        m[15] = 33 * 8;
    }
#pragma unroll
    for (int i = 9; i < 15; i++) m[i] = 0;

    uint32_t dig[8];
    rp_sha_full(m, dig);
    return (uint32_t)v[0] == rp_sha_head(dig);
}

/* ============================== reaper kernel ============================
 * Grid:  x -> fastest slot batches,  y -> coarse combination index
 * Each thread reconstructs its candidate from scratch with rp_scale/rp_acc,
 * then sweeps the fastest slot by repeated weight accumulation.
 * ======================================================================*/
template <int PLEN>
__global__ void rp_kernel(uint64_t coarseBase, uint64_t coarseEnd,
                          uint32_t* __restrict__ bag,
                          uint32_t* __restrict__ bagN)
{
    uint64_t coarse = coarseBase + (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (coarse >= coarseEnd) return;

    const int nh = c_nholes;
    const int sA = c_sweepA;

    /* one modulo pass, amortised over the whole 58-digit sweep below */
    uint64_t v[5], t[5];
    rp_copy(v, c_fixed);
    uint64_t q = coarse;
    for (int i = nh - 1; i >= 0; i--) {
        if (i == sA) continue;
        uint32_t d = (uint32_t)(q % 58); q /= 58;
        if (d) { rp_scale(t, c_wt[i], d); rp_acc(v, t); }
    }

    uint64_t step[5];
    rp_copy(step, c_wt[sA]);

    /* sweep the fastest slot with pure accumulation - no multiply, no modulo.
     * Survivors are a 2^-32 event, so a plain per-lane atomic is cheaper than
     * paying a warp ballot on every single candidate. */
#pragma unroll 4
    for (uint32_t d = 0; d < 58; d++) {
        if (rp_reap<PLEN>(v)) {
            uint32_t at = atomicAdd(bagN, 1u);
            if (at < RP_BAG) {
                bag[at * 3 + 0] = (uint32_t)coarse;
                bag[at * 3 + 1] = (uint32_t)(coarse >> 32);
                bag[at * 3 + 2] = d;
            }
        }
        rp_acc(v, step);
    }
}

/* ======================= random-mode digit RNG =========================
 * splitmix64: identical on device and host so a survivor's (gid, lane) pair
 * fully regenerates its digits host-side - the bag only stores the coordinate,
 * never the 35 digits themselves.  This is the odometer-free path that lifts
 * the 64-bit keyspace ceiling: nothing counts 58^slots, threads just sample.
 * ======================================================================*/
__host__ __device__ __forceinline__ uint64_t rp_mix(uint64_t z) {
    z += 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
/* digit for slot i of the candidate identified by (seed, gid, lane) */
__host__ __device__ __forceinline__ uint32_t rp_digit(uint64_t seed, uint64_t gid,
                                                      uint32_t lane, int slot) {
    uint64_t k = rp_mix(seed ^ rp_mix(gid * (uint64_t)RP_LANE + lane));
    return (uint32_t)(rp_mix(k + (uint64_t)slot * 0x9e3779b97f4a7c15ULL) % 58ULL);
}

/* ============================ random kernel =============================
 * Each thread draws RP_LANE independent candidates, builds each from scratch
 * with rp_scale/rp_acc, and checksum-tests it.  No sequential index anywhere,
 * so slots may be 1..35 without any 58^slots overflow.
 * ======================================================================*/
template <int PLEN>
__global__ void rp_rand_kernel(uint64_t seed, uint32_t* __restrict__ bag,
                               uint32_t* __restrict__ bagN) {
    uint64_t gid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    const int nh = c_nholes;
    const int sA = c_sweepA;               /* fastest slot -> the swept one */

    uint64_t step[5];
    rp_copy(step, c_wt[sA]);

    for (uint32_t lane = 0; lane < RP_LANE; lane++) {
        /* base value = fixed part + every NON-swept slot at a random digit.
         * The swept slot starts at digit 0 and is walked by pure addition,
         * so one 320-bit reconstruction is amortised over 58 checksum tests
         * - the same trick that gives sequential mode its throughput. */
        uint64_t v[5], t[5];
        rp_copy(v, c_fixed);
        for (int i = 0; i < nh; i++) {
            if (i == sA) continue;
            uint32_t d = rp_digit(seed, gid, lane, i);
            if (d) { rp_scale(t, c_wt[i], d); rp_acc(v, t); }
        }
#pragma unroll 4
        for (uint32_t d = 0; d < 58; d++) {
            if (rp_reap<PLEN>(v)) {
                uint32_t at = atomicAdd(bagN, 1u);
                if (at < RP_BAG) {
                    bag[at * 4 + 0] = (uint32_t)gid;
                    bag[at * 4 + 1] = (uint32_t)(gid >> 32);
                    bag[at * 4 + 2] = lane;
                    bag[at * 4 + 3] = d;      /* swept-slot digit */
                }
            }
            rp_acc(v, step);
        }
    }
}

/* ================================ host ================================== */
static int alphaIdx(char c) {
    const char* p = strchr(ALPHA, c);
    return p ? (int)(p - ALPHA) : -1;
}
static bool isGap(char c) {
    return c=='X' || c=='x' || c=='?' || c=='*' || c=='.';
}
static void toLimbs(Int& v, uint64_t out[5]) {
    for (int l = 0; l < 5; l++) {
        uint64_t w = 0;
        for (int b = 0; b < 8; b++) w |= (uint64_t)v.GetByte(l * 8 + b) << (b * 8);
        out[l] = w;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("\n  CGTWIF_Reaper  -  GPU engine #2 (Horner walker)\n\n");
        printf("  Usage:\n    CGTWIF_Reaper <mask> [-d dev] [-btc btc.txt]\n");
        printf("                  [-out found.txt] [-hit wifaddfound.txt] [-q]\n\n");
        printf("  mask : 51/52 char WIF, unknowns as  X ? * .\n");
        printf("  e.g. : L*****x3FA5LXz8uQ9k7BdPM85FTrZJom9mdNGtmTtgwt5KATfh\n\n");
        printf("  -r     random mode: sample the keyspace (no 64-bit ceiling)\n");
        printf("         supports 1..%d unknowns; use for > 10 slots\n\n", RP_MAX);
        return 1;
    }

    std::string mask = argv[1];
    int dev = 0; bool quiet = false; bool randMode = false;
    std::string btcF = "btc.txt", outF = "found.txt", hitF = "wifaddfound.txt";
    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i],"-d")   && i+1 < argc) dev  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"-btc") && i+1 < argc) btcF = argv[++i];
        else if (!strcmp(argv[i],"-out") && i+1 < argc) outF = argv[++i];
        else if (!strcmp(argv[i],"-hit") && i+1 < argc) hitF = argv[++i];
        else if (!strcmp(argv[i],"-r"))  randMode = true;
        else if (!strcmp(argv[i],"-q")) quiet = true;
    }

    int L = (int)mask.length();
    if (L != 51 && L != 52) {
        printf("  ERROR: WIF must be 51 or 52 chars, got %d\n", L); return 1;
    }
    bool comp = (L == 52);
    int plen = comp ? 38 : 37;

    std::vector<Int> P(L);
    P[0].SetInt32(1);
    for (int i = 1; i < L; i++) { P[i].Set(&P[i-1]); P[i].Mult((uint64_t)58); }

    std::vector<int> gaps;
    Int fixed; fixed.SetInt32(0);
    for (int i = 0; i < L; i++) {
        if (isGap(mask[i])) { gaps.push_back(i); continue; }
        int d = alphaIdx(mask[i]);
        if (d < 0) { printf("  ERROR: '%c' at %d not Base58\n", mask[i], i+1); return 1; }
        Int tm; tm.Set(&P[L-1-i]); tm.Mult((uint64_t)d);
        fixed.Add(&tm);
    }
    int nh = (int)gaps.size();
    int slotCap = randMode ? RP_MAX : 10;
    if (nh < 1 || nh > slotCap) {
        printf("  ERROR: need 1..%d unknowns, got %d%s\n", slotCap, nh,
               (!randMode && nh > 10) ? "   (use -r for more than 10)" : "");
        return 1;
    }

    /* sequential mode counts the whole keyspace in a uint64; random mode never
     * enumerates, so the 58^slots ceiling simply does not apply there. */
    uint64_t space = 1;
    bool spaceKnown = true;
    for (int i = 0; i < nh; i++) {
        if (space > (uint64_t)-1 / 58) {
            if (!randMode) { printf("  ERROR: keyspace > 64 bit (use -r)\n"); return 1; }
            spaceKnown = false; break;
        }
        space *= 58;
    }

    cudaDeviceProp pr;
    if (cudaSetDevice(dev) != cudaSuccess || cudaGetDeviceProperties(&pr, dev) != cudaSuccess) {
        printf("  ERROR: no CUDA device %d\n", dev); return 1;
    }

    /* the last hole is the sweep slot */
    int sA = nh - 1;
    int sB = nh >= 2 ? nh - 2 : nh - 1;
    uint64_t coarseTotal = space / 58;
    uint32_t sweepSpan = 58;

    printf("\n  CGTWIF_Reaper  (engine #2 / Horner walker)\n");
    printf("  ============================================================\n");
    printf("  GPU        : %s   sm_%d%d   %d SM\n", pr.name, pr.major, pr.minor,
           pr.multiProcessorCount);
    printf("  Mode       : %s\n", randMode ? "RANDOM (sampling)" : "SEQUENTIAL");
    printf("  Mask       : %s\n", mask.c_str());
    printf("  Payload    : %d bytes  (%s)\n", plen, comp ? "compressed" : "uncompressed");
    printf("  Gaps       : %d  ->  ", nh);
    for (int i = 0; i < nh; i++) printf("%d%s", gaps[i]+1, i+1 < nh ? "," : "");
    printf("\n  Keyspace   : %s\n", spaceKnown ? std::to_string(space).c_str() : "> 2^64 (random mode)");
    printf("  Sweep slot : #%d (position %d)\n", sA, gaps[sA]+1);
    printf("  Outputs    : %s  /  %s\n", outF.c_str(), hitF.c_str());
    printf("  ============================================================\n\n");

    uint64_t hFixed[5]; toLimbs(fixed, hFixed);
    cudaMemcpyToSymbol(c_fixed, hFixed, sizeof(hFixed));

    static uint64_t hWt[RP_MAX][5];
    memset(hWt, 0, sizeof(hWt));
    for (int i = 0; i < nh; i++) toLimbs(P[L-1-gaps[i]], hWt[i]);
    cudaMemcpyToSymbol(c_wt, hWt, sizeof(hWt));
    cudaMemcpyToSymbol(c_nholes, &nh, sizeof(int));
    cudaMemcpyToSymbol(c_sweepA, &sA, sizeof(int));
    cudaMemcpyToSymbol(c_sweepB, &sB, sizeof(int));

    uint32_t *dBag = NULL, *dBagN = NULL;
    cudaMalloc(&dBag, RP_BAG * 4 * sizeof(uint32_t));
    cudaMalloc(&dBagN, sizeof(uint32_t));

    std::set<std::string> btc;
    if (FILE* bf = fopen(btcF.c_str(), "r")) {
        char ln[512];
        while (fgets(ln, sizeof(ln), bf)) {
            std::string a(ln);
            while (!a.empty() && (a.back()=='\n'||a.back()=='\r'||a.back()==' '||a.back()=='\t'))
                a.pop_back();
            if (!a.empty()) btc.insert(a);
        }
        fclose(bf);
        printf("  btc.txt    : %llu addresses\n\n", (unsigned long long)btc.size());
    } else {
        printf("  btc.txt    : not found (checksum hits still logged)\n\n");
    }

    Secp256K1 secp; secp.Init();

    auto t0 = std::chrono::steady_clock::now();
    uint64_t swept = 0, nvalid = 0, nhit = 0;
    double lastP = 0;

    /* shared survivor handler: given a fully-built WIF, verify base58+checksum
     * on the host, derive both addresses, and log / match against btc.txt. */
    auto handle = [&](const std::string& wif) {
        unsigned char bin[64]; size_t bl = plen;
        if (!b58decode(bin, &bl, wif.c_str(), wif.size())) return;
        if ((int)bl != plen) return;

        char hx[80];
        tohex_dst((char*)(bin + 1), 32, hx);
        nvalid++;
        if (FILE* f = fopen(outF.c_str(), "a")) { fprintf(f, "%s\n", wif.c_str()); fclose(f); }

        Int pk; pk.SetBase16(hx);
        Point pub = secp.ComputePublicKey(&pk);
        unsigned char r1[20], r2[20];
        secp.GetHash160(P2PKH, true,  pub, r1);
        secp.GetHash160(P2PKH, false, pub, r2);
        char ac[64], au[64];
        addressToBase58((char*)r1, ac, false);
        addressToBase58((char*)r2, au, false);

        bool got = btc.count(ac) || btc.count(au);
        if (!quiet || got) {
            printf("\n  [OK] %s\n       C %s\n       U %s\n       K %s\n",
                   wif.c_str(), ac, au, hx);
        }
        if (got) {
            nhit++;
            const char* w = btc.count(ac) ? ac : au;
            if (FILE* f = fopen(hitF.c_str(), "a")) {
                fprintf(f, "WIF         : %s\nPRIVKEY_HEX : %s\n", wif.c_str(), hx);
                fprintf(f, "ADDR_COMP   : %s\nADDR_UNCOMP : %s\n", ac, au);
                fprintf(f, "MATCHED     : %s\n\n", w);
                fclose(f);
            }
            printf("  >>> BTC HIT %s  saved to %s\n", w, hitF.c_str());
        }
    };

    if (randMode) {
        /* ---- random sampling: no keyspace ceiling, runs until interrupted or
         * (when the space is small enough to count) until it is exhausted. --- */
        uint64_t threads = (uint64_t)pr.multiProcessorCount * RP_TPB * 512;
        int blocks = (int)((threads + RP_TPB - 1) / RP_TPB);
        uint64_t perLaunch = threads * RP_LANE * 58ULL;   /* swept slot walks 58 */
        std::mt19937_64 rng(0xC0FFEEULL ^ (uint64_t)time(NULL));

        for (uint64_t seedIdx = 0; ; seedIdx++) {
            uint64_t seed = rng();
            cudaMemset(dBagN, 0, sizeof(uint32_t));
            if (comp) rp_rand_kernel<38><<<blocks, RP_TPB>>>(seed, dBag, dBagN);
            else      rp_rand_kernel<37><<<blocks, RP_TPB>>>(seed, dBag, dBagN);

            cudaError_t e = cudaDeviceSynchronize();
            if (e != cudaSuccess) { printf("\n  CUDA: %s\n", cudaGetErrorString(e)); break; }

            uint32_t n = 0;
            cudaMemcpy(&n, dBagN, sizeof(uint32_t), cudaMemcpyDeviceToHost);
            if (n) {
                uint32_t k = n > RP_BAG ? RP_BAG : n;
                std::vector<uint32_t> raw(k * 4);
                cudaMemcpy(raw.data(), dBag, k * 4 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
                for (uint32_t i = 0; i < k; i++) {
                    uint64_t gid = ((uint64_t)raw[i*4+1] << 32) | raw[i*4];
                    uint32_t lane = raw[i*4+2];
                    uint32_t swd  = raw[i*4+3];      /* swept-slot digit */
                    std::string wif = mask;
                    for (int s = 0; s < nh; s++)
                        wif[gaps[s]] = (s == sA) ? ALPHA[swd]
                                                 : ALPHA[rp_digit(seed, gid, lane, s)];
                    handle(wif);
                }
            }

            swept += perLaunch;
            double sec = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - t0).count();
            if (sec - lastP > 0.4) {
                lastP = sec;
                printf("\r  [%7.1fs] sampled %.3e   %8.2f Gkey/s   ok %llu  hit %llu      ",
                       sec, (double)swept, sec > 0 ? swept / sec / 1e9 : 0,
                       (unsigned long long)nvalid, (unsigned long long)nhit);
                fflush(stdout);
            }
        }
    } else {
    /* one thread per coarse combo; each sweeps 58 candidates internally */
    uint64_t perLaunch = (uint64_t)pr.multiProcessorCount * RP_TPB * 512;

    for (uint64_t cb = 0; cb < coarseTotal; cb += perLaunch) {
        uint64_t cN = (cb + perLaunch > coarseTotal) ? (coarseTotal - cb) : perLaunch;
        int blocks = (int)((cN + RP_TPB - 1) / RP_TPB);

        cudaMemset(dBagN, 0, sizeof(uint32_t));
        if (comp) rp_kernel<38><<<blocks, RP_TPB>>>(cb, cb + cN, dBag, dBagN);
        else      rp_kernel<37><<<blocks, RP_TPB>>>(cb, cb + cN, dBag, dBagN);

        cudaError_t e = cudaDeviceSynchronize();
        if (e != cudaSuccess) { printf("\n  CUDA: %s\n", cudaGetErrorString(e)); break; }

        uint32_t n = 0;
        cudaMemcpy(&n, dBagN, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        if (n) {
            uint32_t k = n > RP_BAG ? RP_BAG : n;
            std::vector<uint32_t> raw(k * 3);
            cudaMemcpy(raw.data(), dBag, k * 3 * sizeof(uint32_t), cudaMemcpyDeviceToHost);

            for (uint32_t i = 0; i < k; i++) {
                uint64_t coarse = ((uint64_t)raw[i*3+1] << 32) | raw[i*3];
                uint32_t fastD  = raw[i*3+2];

                std::string wif = mask;
                uint64_t q = coarse;
                for (int s = nh - 1; s >= 0; s--) {
                    if (s == sA) continue;
                    wif[gaps[s]] = ALPHA[q % 58]; q /= 58;
                }
                wif[gaps[sA]] = ALPHA[fastD];
                handle(wif);
            }
        }

        swept += cN * sweepSpan;
        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        if (sec - lastP > 0.4 || swept >= space) {
            lastP = sec;
            printf("\r  [%7.1fs] %6.2f%%   %8.2f Gkey/s   ok %llu  hit %llu      ",
                   sec, 100.0 * swept / space, sec > 0 ? swept / sec / 1e9 : 0,
                   (unsigned long long)nvalid, (unsigned long long)nhit);
            fflush(stdout);
        }
    }
    }

    double sec = std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - t0).count();
    printf("\n\n  Reaper finished: %.2fs   %llu keys   avg %.2f Gkey/s   ok %llu   hit %llu\n\n",
           sec, (unsigned long long)swept, sec > 0 ? swept / sec / 1e9 : 0,
           (unsigned long long)nvalid, (unsigned long long)nhit);

    cudaFree(dBag);
    cudaFree(dBagN);
    return 0;
}
