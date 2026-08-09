/* ============================================================================
 *  cryptographytube  -  Int : fixed-size big integer (host)
 *  Author: Sisujhon
 *
 *  Original clean-room 256-bit integer used by the host-side key/address
 *  pipeline.  The value is stored as five little-endian 64-bit limbs
 *  (bits64[0] is least significant); the extra top limb gives headroom for
 *  carries and sign during intermediate arithmetic.  A parallel 32-bit view
 *  (bits[10]) shares the same storage so callers may poke individual words.
 *
 *  Only the operations the scanner and the elliptic-curve layer actually use
 *  are exposed: ordinary big-integer add/sub/mul/div/shift/compare, base
 *  conversion, and the secp256k1 field operations (add/sub/neg/mul/inverse).
 * ==========================================================================*/
#ifndef CGT_INT_H
#define CGT_INT_H

#include <string>
#include <stdint.h>

#define BISIZE   256
#define NB64BLOCK  5
#define NB32BLOCK 10

class Int {

public:

    Int();
    Int(int64_t v);
    Int(uint64_t v);
    Int(Int* a);

    /* ---- setters ---------------------------------------------------- */
    void SetInt32(uint32_t v);
    void Set(Int* a);
    void SetBase16(char* hex);

    /* ---- plain big-integer arithmetic ------------------------------- */
    void Add(uint64_t a);
    void Add(Int* a);
    void AddOne();
    void Sub(Int* a);
    void Mult(uint64_t a);
    void Mult(Int* a);
    void Div(Int* a, Int* mod = 0);
    void ShiftL(uint32_t n);

    /* ---- comparison ------------------------------------------------- */
    bool IsLower(Int* a);
    bool IsGreater(Int* a);
    bool IsEqual(Int* a);
    bool IsZero();

    /* ---- conversion ------------------------------------------------- */
    double        ToDouble();
    std::string   GetBase10();
    std::string   GetBaseN(int n, char* charset);
    unsigned char GetByte(int n);
    void          Get32Bytes(unsigned char* buff);   /* big-endian */

    /* ---- secp256k1 field arithmetic (mod P) ------------------------- */
    static void SetupField(Int* p);      /* record the field prime */
    void ModAdd(Int* a, Int* b);         /* this = a + b   (mod P)  */
    void ModSub(Int* a, Int* b);         /* this = a - b   (mod P)  */
    void ModMul(Int* a, Int* b);         /* this = a * b   (mod P)  */
    void ModMul(Int* a);                 /* this = this*a  (mod P)  */
    void ModNeg();                       /* this = -this   (mod P)  */
    void ModInv();                       /* this = this^-1 (mod P)  */

    /* storage: 5x64-bit == 10x32-bit, little-endian, [0] least significant */
    union {
        uint32_t bits[NB32BLOCK];
        uint64_t bits64[NB64BLOCK];
    };

private:
    uint32_t divSmall(uint32_t d);       /* this /= d, returns remainder */
};

/* --- 64x64 -> 128 helpers ------------------------------------------------ */
#if defined(_WIN64) || defined(WIN64)
#include <intrin.h>
#else
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi) {
    unsigned __int128 p = (unsigned __int128)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
}
static inline unsigned char _addcarry_u64(unsigned char c, uint64_t a,
                                          uint64_t b, uint64_t* out) {
    unsigned __int128 s = (unsigned __int128)a + b + c;
    *out = (uint64_t)s;
    return (unsigned char)(s >> 64);
}
static inline unsigned char _subborrow_u64(unsigned char c, uint64_t a,
                                           uint64_t b, uint64_t* out) {
    unsigned __int128 d = (unsigned __int128)a - b - c;
    *out = (uint64_t)d;
    return (unsigned char)((d >> 64) & 1);
}
#endif

#endif /* CGT_INT_H */
