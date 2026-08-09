/* ============================================================================
 *  cryptographytube  -  SHA-256  (host, scalar)
 *  Author: Sisujhon
 *
 *  Clean-room implementation of the SHA-256 compression function as specified
 *  in FIPS 180-4.  Written from the standard: eight working variables, the
 *  64-entry round-constant table (first 32 bits of the fractional parts of the
 *  cube roots of the first 64 primes) and the standard message schedule.  The
 *  message is padded the usual way (0x80, zero fill, 64-bit big-endian bit
 *  length) and processed one 64-byte block at a time.
 * ==========================================================================*/
#include "sha256.h"
#include <string.h>

/* rotate right */
static inline uint32_t rotr32(uint32_t v, unsigned n) {
    return (v >> n) | (v << (32 - n));
}

/* round constants: frac(cbrt(prime_i)) * 2^32, i = 0..63 */
static const uint32_t RK[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

/* IV: frac(sqrt(prime_i)) * 2^32, i = 0..7 */
static const uint32_t IV[8] = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
};

/* compress one 64-byte block (big-endian words) into state h[0..7] */
static void sha256_block(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i * 4 + 0] << 24)
             | ((uint32_t)blk[i * 4 + 1] << 16)
             | ((uint32_t)blk[i * 4 + 2] <<  8)
             | ((uint32_t)blk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + RK[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/* write state as 32 big-endian output bytes */
static inline void sha256_emit(const uint32_t h[8], uint8_t* out32) {
    for (int i = 0; i < 8; i++) {
        out32[i * 4 + 0] = (uint8_t)(h[i] >> 24);
        out32[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out32[i * 4 + 2] = (uint8_t)(h[i] >>  8);
        out32[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* --- generic one-shot -------------------------------------------------- */
void sha256(uint8_t* data, size_t len, uint8_t* out32) {
    uint32_t h[8];
    memcpy(h, IV, sizeof(h));

    /* whole blocks straight from the input */
    size_t full = len & ~(size_t)63;
    for (size_t off = 0; off < full; off += 64)
        sha256_block(h, data + off);

    /* final block(s): copy the tail, append 0x80, then the length. If the tail
     * plus the mandatory 9 bytes overflows 64, a second padded block is run. */
    uint8_t tail[128];
    size_t rem = len - full;
    memcpy(tail, data + full, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - (rem + 1));

    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        tail[padded - 1 - i] = (uint8_t)(bits >> (8 * i));

    sha256_block(h, tail);
    if (padded == 128) sha256_block(h, tail + 64);

    sha256_emit(h, out32);
}

/* --- fixed 33-byte input (compressed pubkey): single padded block ------ */
void sha256_33(uint8_t* data, uint8_t* out32) {
    uint32_t h[8];
    memcpy(h, IV, sizeof(h));

    uint8_t blk[64];
    memcpy(blk, data, 33);
    blk[33] = 0x80;
    memset(blk + 34, 0, 64 - 34);
    /* 33 bytes = 264 bits -> 0x0108 in the last two length bytes */
    blk[62] = 0x01;
    blk[63] = 0x08;

    sha256_block(h, blk);
    sha256_emit(h, out32);
}

/* --- fixed 65-byte input (uncompressed pubkey): two blocks ------------- */
void sha256_65(uint8_t* data, uint8_t* out32) {
    uint32_t h[8];
    memcpy(h, IV, sizeof(h));

    /* first full 64-byte block is raw input */
    sha256_block(h, data);

    /* second block: 1 leftover byte, pad, 65*8 = 520 bits = 0x0208 */
    uint8_t blk[64];
    blk[0] = data[64];
    blk[1] = 0x80;
    memset(blk + 2, 0, 64 - 2);
    blk[62] = 0x02;
    blk[63] = 0x08;

    sha256_block(h, blk);
    sha256_emit(h, out32);
}
