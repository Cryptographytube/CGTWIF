/* ============================================================================
 *  cryptographytube  -  RIPEMD-160  (host, scalar)
 *  Author: Sisujhon
 *
 *  Clean-room implementation of RIPEMD-160 (Dobbertin-Bosselaers-Preneel).
 *  RIPEMD-160 runs two parallel 80-step "lines" over each 512-bit block and
 *  mixes their outputs into the chaining state.  Words are little-endian.
 * ==========================================================================*/
#include "ripemd160.h"
#include <string.h>

static inline uint32_t rol(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32 - n));
}

/* the five boolean round functions */
static inline uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static inline uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static inline uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static inline uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

/* message word order, left line then right line */
static const int RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
static const int RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};

/* rotate amounts, left line then right line */
static const int SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
static const int SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

/* additive constants per 16-step group, left line and right line */
static const uint32_t KL[5] = { 0x00000000u,0x5a827999u,0x6ed9eba1u,0x8f1bbcdcu,0xa953fd4eu };
static const uint32_t KR[5] = { 0x50a28be6u,0x5c4dd124u,0x6d703ef3u,0x7a6d76e9u,0x00000000u };

static inline uint32_t fsel(int round, uint32_t x, uint32_t y, uint32_t z) {
    switch (round) {
        case 0: return f1(x, y, z);
        case 1: return f2(x, y, z);
        case 2: return f3(x, y, z);
        case 3: return f4(x, y, z);
        default:return f5(x, y, z);
    }
}

/* compress one 64-byte block into state s[0..4] */
static void rmd_block(uint32_t s[5], const unsigned char blk[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = ((uint32_t)blk[i * 4 + 0])
             | ((uint32_t)blk[i * 4 + 1] <<  8)
             | ((uint32_t)blk[i * 4 + 2] << 16)
             | ((uint32_t)blk[i * 4 + 3] << 24);
    }

    uint32_t al = s[0], bl = s[1], cl = s[2], dl = s[3], el = s[4];
    uint32_t ar = s[0], br = s[1], cr = s[2], dr = s[3], er = s[4];

    for (int i = 0; i < 80; i++) {
        int grp = i / 16;

        uint32_t t = rol(al + fsel(grp, bl, cl, dl) + x[RL[i]] + KL[grp], SL[i]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;

        int rgrp = 4 - grp;
        t = rol(ar + fsel(rgrp, br, cr, dr) + x[RR[i]] + KR[grp], SR[i]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }

    /* combine the two lines back into the chaining value */
    uint32_t tmp = s[1] + cl + dr;
    s[1] = s[2] + dl + er;
    s[2] = s[3] + el + ar;
    s[3] = s[4] + al + br;
    s[4] = s[0] + bl + cr;
    s[0] = tmp;
}

static const uint32_t RMD_IV[5] = {
    0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
};

static void rmd_run(const unsigned char* data, size_t len, unsigned char* out20) {
    uint32_t s[5];
    memcpy(s, RMD_IV, sizeof(s));

    size_t full = len & ~(size_t)63;
    for (size_t off = 0; off < full; off += 64)
        rmd_block(s, data + off);

    unsigned char tail[128];
    size_t rem = len - full;
    memcpy(tail, data + full, rem);
    tail[rem] = 0x80;
    size_t padded = (rem + 1 <= 56) ? 64 : 128;
    memset(tail + rem + 1, 0, padded - (rem + 1));

    uint64_t bits = (uint64_t)len * 8;                  /* little-endian length */
    for (int i = 0; i < 8; i++)
        tail[padded - 8 + i] = (unsigned char)(bits >> (8 * i));

    rmd_block(s, tail);
    if (padded == 128) rmd_block(s, tail + 64);

    for (int i = 0; i < 5; i++) {
        out20[i * 4 + 0] = (unsigned char)(s[i]);
        out20[i * 4 + 1] = (unsigned char)(s[i] >>  8);
        out20[i * 4 + 2] = (unsigned char)(s[i] >> 16);
        out20[i * 4 + 3] = (unsigned char)(s[i] >> 24);
    }
}

void ripemd160(unsigned char* data, int len, unsigned char* out20) {
    rmd_run(data, (size_t)len, out20);
}

/* fixed 32-byte input: one padded block */
void ripemd160_32(unsigned char* data32, unsigned char* out20) {
    rmd_run(data32, 32, out20);
}
