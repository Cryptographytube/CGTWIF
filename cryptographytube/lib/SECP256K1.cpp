/* ============================================================================
 *  cryptographytube  -  Secp256K1 : curve operations (host)
 *  Author: Sisujhon
 *
 *  Clean-room secp256k1 public-key derivation.  Group arithmetic runs in
 *  Jacobian coordinates (X:Y:Z) so the scalar multiply needs a single modular
 *  inverse at the end (Point::Reduce).  The curve is y^2 = x^3 + 7 (a = 0).
 * ==========================================================================*/
#include "SECP256k1.h"
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include <string.h>

/* field prime, group order and generator, all big-endian hex */
static char P_HEX[]  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
static char N_HEX[]  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static char GX_HEX[] = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static char GY_HEX[] = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

Secp256K1::Secp256K1() {}
Secp256K1::~Secp256K1() {}

void Secp256K1::Init() {
    P.SetBase16(P_HEX);
    Int::SetupField(&P);          /* arm the modular reduction */
    order.SetBase16(N_HEX);
    G.x.SetBase16(GX_HEX);
    G.y.SetBase16(GY_HEX);
    G.z.SetInt32(1);
}

/* ---- Jacobian point doubling (a = 0) ----------------------------------- *
 * A = X^2 ; M = 3A ; Y2 = Y^2 ; S = 4*X*Y2
 * X' = M^2 - 2S ; Y' = M*(S - X') - 8*Y2^2 ; Z' = 2*Y*Z                     */
Point Secp256K1::DblJ(Point& p) {
    Point r;
    if (p.y.IsZero()) { r.Clear(); return r; }   /* vertical tangent -> inf */

    Int A;  A.ModMul(&p.x, &p.x);
    Int M;  M.ModAdd(&A, &A); M.ModAdd(&M, &A);   /* 3*X^2 */
    Int Y2; Y2.ModMul(&p.y, &p.y);
    Int S;  S.ModMul(&p.x, &Y2);
    S.ModAdd(&S, &S); S.ModAdd(&S, &S);           /* 4*X*Y^2 */

    Int M2;   M2.ModMul(&M, &M);
    Int twoS; twoS.ModAdd(&S, &S);
    r.x.ModSub(&M2, &twoS);                       /* X' */

    Int SmX; SmX.ModSub(&S, &r.x);
    Int Y4;  Y4.ModMul(&Y2, &Y2);
    Int e8;  e8.ModAdd(&Y4, &Y4); e8.ModAdd(&e8, &e8); e8.ModAdd(&e8, &e8);
    r.y.ModMul(&M, &SmX);
    r.y.ModSub(&r.y, &e8);                         /* Y' */

    r.z.ModMul(&p.y, &p.z);
    r.z.ModAdd(&r.z, &r.z);                        /* Z' = 2*Y*Z */
    return r;
}

/* ---- general Jacobian point addition ----------------------------------- */
Point Secp256K1::AddJ(Point& p, Point& q) {
    if (p.isZero()) return q;
    if (q.isZero()) return p;

    Point r;
    Int Z1Z1; Z1Z1.ModMul(&p.z, &p.z);
    Int Z2Z2; Z2Z2.ModMul(&q.z, &q.z);
    Int U1; U1.ModMul(&p.x, &Z2Z2);
    Int U2; U2.ModMul(&q.x, &Z1Z1);
    Int S1; S1.ModMul(&p.y, &q.z); S1.ModMul(&S1, &Z2Z2);   /* Y1*Z2^3 */
    Int S2; S2.ModMul(&q.y, &p.z); S2.ModMul(&S2, &Z1Z1);   /* Y2*Z1^3 */

    Int H; H.ModSub(&U2, &U1);
    Int R; R.ModSub(&S2, &S1);
    if (H.IsZero()) {
        if (R.IsZero()) return DblJ(p);           /* p == q */
        r.Clear(); return r;                      /* p == -q -> infinity */
    }

    Int H2; H2.ModMul(&H, &H);
    Int H3; H3.ModMul(&H2, &H);
    Int U1H2; U1H2.ModMul(&U1, &H2);
    Int R2; R2.ModMul(&R, &R);
    Int t2; t2.ModAdd(&U1H2, &U1H2);
    r.x.ModSub(&R2, &H3); r.x.ModSub(&r.x, &t2);  /* X3 = R^2 - H^3 - 2*U1H2 */

    Int UmX; UmX.ModSub(&U1H2, &r.x);
    r.y.ModMul(&R, &UmX);
    Int S1H3; S1H3.ModMul(&S1, &H3);
    r.y.ModSub(&r.y, &S1H3);                       /* Y3 */

    r.z.ModMul(&p.z, &q.z); r.z.ModMul(&r.z, &H);  /* Z3 = Z1*Z2*H */
    return r;
}

/* ---- k*G by binary double-and-add, LSB first --------------------------- */
Point Secp256K1::ComputePublicKey(Int* privKey) {
    Point acc; acc.Clear();       /* point at infinity */
    Point base(G);                /* running 2^i * G    */
    for (int i = 0; i < 256; i++) {
        if ((privKey->bits64[i >> 6] >> (i & 63)) & 1ULL) {
            if (acc.isZero()) acc.Set(base);
            else              acc = AddJ(acc, base);
        }
        base = DblJ(base);
    }
    if (!acc.isZero()) acc.Reduce();   /* one inversion -> affine */
    return acc;
}

/* ---- HASH160 of the SEC-encoded public key ----------------------------- */
void Secp256K1::GetHash160(int type, bool compressed, Point& pubKey, unsigned char* hash) {
    unsigned char sha[32];
    if (type != P2SH) {
        /* P2PKH / BECH32 : HASH160 of the raw public key encoding */
        unsigned char buf[65];
        if (compressed) {
            buf[0] = (unsigned char)(0x02 | (pubKey.y.GetByte(0) & 1));
            pubKey.x.Get32Bytes(buf + 1);
            sha256_33(buf, sha);
        } else {
            buf[0] = 0x04;
            pubKey.x.Get32Bytes(buf + 1);
            pubKey.y.Get32Bytes(buf + 33);
            sha256_65(buf, sha);
        }
        ripemd160_32(sha, hash);
    } else {
        /* P2SH : HASH160 of the 1-of-1 redeem script 0x00 0x14 <hash160> */
        unsigned char script[22];
        script[0] = 0x00;
        script[1] = 0x14;
        GetHash160(P2PKH, compressed, pubKey, script + 2);
        sha256(script, 22, sha);
        ripemd160_32(sha, hash);
    }
}
