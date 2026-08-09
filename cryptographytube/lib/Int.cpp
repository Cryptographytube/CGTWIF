/* ============================================================================
 *  cryptographytube  -  Int : big-integer core (host)
 *  Author: Sisujhon
 *
 *  Plain (non-modular) 320-bit integer arithmetic: construction, add/sub,
 *  multiply, binary long division, left shift, unsigned comparison and
 *  base conversion.  The secp256k1 field operations live in IntMod.cpp.
 *
 *  Layout is five little-endian 64-bit limbs; all values handled here are
 *  non-negative and comfortably below 2^256, so comparisons treat the limbs
 *  as an unsigned 320-bit magnitude.
 * ==========================================================================*/
#include "Int.h"
#include <string.h>

/* ------------------------------------------------------------------ ctors */
Int::Int() {
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = 0;
}
Int::Int(int64_t v) {
    bits64[0] = (uint64_t)v;
    uint64_t s = (v < 0) ? ~0ULL : 0ULL;      /* sign extend */
    for (int i = 1; i < NB64BLOCK; i++) bits64[i] = s;
}
Int::Int(uint64_t v) {
    bits64[0] = v;
    for (int i = 1; i < NB64BLOCK; i++) bits64[i] = 0;
}
Int::Int(Int* a) { Set(a); }

/* ---------------------------------------------------------------- setters */
void Int::SetInt32(uint32_t v) {
    bits64[0] = v;
    for (int i = 1; i < NB64BLOCK; i++) bits64[i] = 0;
}
void Int::Set(Int* a) {
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = a->bits64[i];
}
void Int::SetBase16(char* hex) {
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = 0;
    const char* p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    int len = (int)strlen(p);
    int bit = 0;
    for (int i = len - 1; i >= 0 && bit < NB64BLOCK * 64; i--) {
        char c = p[i];
        uint32_t nib;
        if      (c >= '0' && c <= '9') nib = c - '0';
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
        else continue;
        bits64[bit / 64] |= (uint64_t)nib << (bit % 64);
        bit += 4;
    }
}

/* -------------------------------------------------------------- add / sub */
void Int::Add(uint64_t a) {
    unsigned char c = _addcarry_u64(0, bits64[0], a, &bits64[0]);
    for (int i = 1; i < NB64BLOCK; i++)
        c = _addcarry_u64(c, bits64[i], 0, &bits64[i]);
}
void Int::Add(Int* a) {
    unsigned char c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        c = _addcarry_u64(c, bits64[i], a->bits64[i], &bits64[i]);
}
void Int::AddOne() { Add((uint64_t)1); }

void Int::Sub(Int* a) {
    unsigned char b = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        b = _subborrow_u64(b, bits64[i], a->bits64[i], &bits64[i]);
}

/* -------------------------------------------------------------- multiply */
/* low 320 bits of this * scalar */
void Int::Mult(uint64_t a) {
    uint64_t out[NB64BLOCK] = {0};
    uint64_t carry = 0;
    for (int i = 0; i < NB64BLOCK; i++) {
        uint64_t hi;
        uint64_t lo = _umul128(bits64[i], a, &hi);
        unsigned char c = _addcarry_u64(0, lo, carry, &out[i]);
        carry = hi + c;                              /* hi < 2^64-1 so no wrap */
    }
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = out[i];
}

/* low 320 bits of this * a (schoolbook) */
void Int::Mult(Int* a) {
    uint64_t out[NB64BLOCK] = {0};
    for (int i = 0; i < NB64BLOCK; i++) {
        if (bits64[i] == 0) continue;
        uint64_t carry = 0;
        for (int j = 0; i + j < NB64BLOCK; j++) {
            uint64_t hi;
            uint64_t lo = _umul128(bits64[i], a->bits64[j], &hi);
            uint64_t t;
            unsigned char c1 = _addcarry_u64(0, out[i + j], lo, &t);
            unsigned char c2 = _addcarry_u64(0, t, carry, &out[i + j]);
            carry = hi + c1 + c2;                    /* cannot overflow 64 bits */
        }
    }
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = out[i];
}

/* ---------------------------------------------------------------- shift */
void Int::ShiftL(uint32_t n) {
    if (n == 0) return;
    uint32_t limbShift = n / 64, bitShift = n % 64;
    uint64_t out[NB64BLOCK] = {0};
    for (int i = NB64BLOCK - 1; i >= 0; i--) {
        int src = i - (int)limbShift;
        if (src < 0) continue;
        uint64_t v = bits64[src] << bitShift;
        if (bitShift && src - 1 >= 0)
            v |= bits64[src - 1] >> (64 - bitShift);
        out[i] = v;
    }
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = out[i];
}

/* ---------------------------------------------------------- comparison */
static int ucmp(const uint64_t* a, const uint64_t* b) {   /* unsigned magnitude */
    for (int i = NB64BLOCK - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}
bool Int::IsLower(Int* a)   { return ucmp(bits64, a->bits64) < 0; }
bool Int::IsGreater(Int* a) { return ucmp(bits64, a->bits64) > 0; }
bool Int::IsEqual(Int* a)   { return ucmp(bits64, a->bits64) == 0; }
bool Int::IsZero() {
    for (int i = 0; i < NB64BLOCK; i++) if (bits64[i]) return false;
    return true;
}

/* ---------------------------------------------------- binary long division */
/* this = this / a ; if mod != NULL, *mod = this % a */
void Int::Div(Int* a, Int* mod) {
    if (a->IsZero()) return;                 /* undefined; leave unchanged */
    if (ucmp(bits64, a->bits64) < 0) {       /* dividend < divisor */
        if (mod) mod->Set(this);
        for (int i = 0; i < NB64BLOCK; i++) bits64[i] = 0;
        return;
    }
    uint64_t dividend[NB64BLOCK];
    for (int i = 0; i < NB64BLOCK; i++) dividend[i] = bits64[i];

    uint64_t q[NB64BLOCK] = {0};
    uint64_t r[NB64BLOCK] = {0};

    for (int bit = NB64BLOCK * 64 - 1; bit >= 0; bit--) {
        /* r <<= 1 */
        uint64_t carry = 0;
        for (int i = 0; i < NB64BLOCK; i++) {
            uint64_t nc = r[i] >> 63;
            r[i] = (r[i] << 1) | carry;
            carry = nc;
        }
        /* bring down bit `bit` of the dividend */
        r[0] |= (dividend[bit / 64] >> (bit % 64)) & 1ULL;
        /* if r >= a : r -= a ; set quotient bit */
        if (ucmp(r, a->bits64) >= 0) {
            unsigned char b = 0;
            for (int i = 0; i < NB64BLOCK; i++)
                b = _subborrow_u64(b, r[i], a->bits64[i], &r[i]);
            q[bit / 64] |= 1ULL << (bit % 64);
        }
    }
    for (int i = 0; i < NB64BLOCK; i++) bits64[i] = q[i];
    if (mod) for (int i = 0; i < NB64BLOCK; i++) mod->bits64[i] = r[i];
}

/* ------------------------------------------------------- small in-place div */
uint32_t Int::divSmall(uint32_t d) {                 /* this /= d, return rem */
    uint64_t rem = 0;
    for (int i = NB32BLOCK - 1; i >= 0; i--) {
        uint64_t acc = (rem << 32) | (uint64_t)bits[i];
        bits[i] = (uint32_t)(acc / d);
        rem = acc % d;
    }
    return (uint32_t)rem;
}

/* --------------------------------------------------------------- getters */
unsigned char Int::GetByte(int n) {                  /* little-endian byte n */
    return (unsigned char)(bits64[n >> 3] >> ((n & 7) * 8));
}
void Int::Get32Bytes(unsigned char* buff) {          /* big-endian 32 bytes */
    for (int i = 0; i < 32; i++) buff[i] = GetByte(31 - i);
}

double Int::ToDouble() {
    double base = 1.0, sum = 0.0;
    for (int i = 0; i < NB64BLOCK; i++) {
        sum += (double)bits64[i] * base;
        base *= 18446744073709551616.0;              /* 2^64 */
    }
    return sum;
}

std::string Int::GetBase10() {
    if (IsZero()) return "0";
    Int t(this);
    std::string s;
    while (!t.IsZero()) s += (char)('0' + t.divSmall(10));
    return std::string(s.rbegin(), s.rend());
}

std::string Int::GetBaseN(int n, char* charset) {
    if (IsZero()) return std::string(1, charset[0]);
    Int t(this);
    std::string s;
    while (!t.IsZero()) s += charset[t.divSmall((uint32_t)n)];
    return std::string(s.rbegin(), s.rend());
}
