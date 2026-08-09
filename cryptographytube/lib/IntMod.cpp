/* ============================================================================
 *  cryptographytube  -  Int : secp256k1 field arithmetic (host)
 *  Author: Sisujhon
 *
 *  Modular arithmetic over the secp256k1 prime
 *      P = 2^256 - 2^32 - 977.
 *  Because 2^256 = P + 2^32 + 977, any value can be reduced mod P by folding
 *  its high half back down with the single 64-bit constant
 *      R = 2^32 + 977 = 4294968273,
 *  which is the whole trick behind the fast reduction here: multiply the part
 *  above bit 255 by R, add it back to the low 256 bits, and repeat until the
 *  high part vanishes (it shrinks by ~223 bits per pass, so 2-3 passes).
 *
 *  Inversion is Fermat: a^(P-2) mod P by square-and-multiply.
 * ==========================================================================*/
#include "Int.h"
#include <string.h>

static const uint64_t FOLD_R = 4294968273ULL;   /* 2^32 + 977 */

static Int  gP;              /* field prime, set by SetupField */
static bool gPset = false;

void Int::SetupField(Int* p) {
    gP.Set(p);
    gPset = true;
}

/* -------- unsigned compare of the low `n` limbs -------------------------- */
static int cmpN(const uint64_t* a, const uint64_t* b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* -------- reduce a value held in t[0..8] down to t[0..3] (mod P) --------- */
static void foldReduce(uint64_t t[9]) {
    while (t[4] | t[5] | t[6] | t[7] | t[8]) {
        uint64_t M[5] = { t[4], t[5], t[6], t[7], t[8] };
        t[4] = t[5] = t[6] = t[7] = t[8] = 0;

        /* t[0..] += M * R  (M is the old high part, R the fold constant) */
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            uint64_t hi;
            uint64_t lo = _umul128(M[k], FOLD_R, &hi);
            unsigned char c1 = _addcarry_u64(0, t[k], lo, &t[k]);
            unsigned char c2 = _addcarry_u64(0, t[k], carry, &t[k]);
            carry = hi + c1 + c2;
        }
        /* the leftover carry lands just above the low part */
        for (int idx = 5; carry && idx < 9; idx++) {
            unsigned char c = _addcarry_u64(0, t[idx], carry, &t[idx]);
            carry = c;
        }
    }
    /* low 256 bits may still be >= P: at most a couple of subtractions */
    while (cmpN(t, gP.bits64, 4) >= 0) {
        unsigned char b = 0;
        for (int i = 0; i < 4; i++)
            b = _subborrow_u64(b, t[i], gP.bits64[i], &t[i]);
    }
}

/* --------------------------------------------------------------- ModAdd */
void Int::ModAdd(Int* a, Int* b) {
    uint64_t t[9] = {0};
    unsigned char c = 0;
    for (int i = 0; i < 5; i++)
        c = _addcarry_u64(c, a->bits64[i], b->bits64[i], &t[i]);
    foldReduce(t);
    for (int i = 0; i < 4; i++) bits64[i] = t[i];
    bits64[4] = 0;
}

/* --------------------------------------------------------------- ModSub */
void Int::ModSub(Int* a, Int* b) {
    if (cmpN(a->bits64, b->bits64, 5) >= 0) {          /* a >= b */
        unsigned char br = 0;
        for (int i = 0; i < 5; i++)
            br = _subborrow_u64(br, a->bits64[i], b->bits64[i], &bits64[i]);
    } else {                                           /* (a + P) - b */
        uint64_t t[5];
        unsigned char c = 0;
        for (int i = 0; i < 5; i++)
            c = _addcarry_u64(c, a->bits64[i], gP.bits64[i], &t[i]);
        unsigned char br = 0;
        for (int i = 0; i < 5; i++)
            br = _subborrow_u64(br, t[i], b->bits64[i], &bits64[i]);
    }
    bits64[4] = 0;
}

/* --------------------------------------------------------------- ModNeg */
void Int::ModNeg() {
    if (IsZero()) return;
    uint64_t t[5];
    unsigned char br = 0;
    for (int i = 0; i < 5; i++)
        br = _subborrow_u64(br, gP.bits64[i], bits64[i], &t[i]);
    for (int i = 0; i < 4; i++) bits64[i] = t[i];
    bits64[4] = 0;
}

/* --------------------------------------------------------------- ModMul */
void Int::ModMul(Int* a, Int* b) {
    /* full 256x256 -> 512-bit product (field elements have limb[4]==0) */
    uint64_t t[9] = {0};
    for (int i = 0; i < 4; i++) {
        if (a->bits64[i] == 0) continue;
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t hi;
            uint64_t lo = _umul128(a->bits64[i], b->bits64[j], &hi);
            uint64_t s;
            unsigned char c1 = _addcarry_u64(0, t[i + j], lo, &s);
            unsigned char c2 = _addcarry_u64(0, s, carry, &t[i + j]);
            carry = hi + c1 + c2;
        }
        t[i + 4] += carry;
    }
    foldReduce(t);
    for (int i = 0; i < 4; i++) bits64[i] = t[i];
    bits64[4] = 0;
}

void Int::ModMul(Int* a) {
    Int self(this);
    ModMul(&self, a);
}

/* --------------------------------------------------------------- ModInv */
/* this = this^(P-2) mod P  (Fermat's little theorem) */
void Int::ModInv() {
    if (IsZero()) return;

    Int base(this);
    Int e; e.Set(&gP);                     /* exponent = P - 2 */
    { Int two((uint64_t)2); e.Sub(&two); }

    Int r((uint64_t)1);
    for (int i = 255; i >= 0; i--) {
        r.ModMul(&r, &r);                  /* r = r^2 */
        if ((e.bits64[i >> 6] >> (i & 63)) & 1ULL)
            r.ModMul(&r, &base);           /* r *= base */
    }
    Set(&r);
}
