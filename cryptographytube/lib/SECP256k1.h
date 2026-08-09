/* ============================================================================
 *  cryptographytube  -  Secp256K1 : curve operations (host)
 *  Author: Sisujhon
 *
 *  Original clean-room secp256k1 public-key derivation for the host side.
 *  Only what the scanner needs is implemented:
 *      Init()               load the field prime, generator and order
 *      ComputePublicKey()   k*G by projective double-and-add
 *      GetHash160()         HASH160 of the compressed / uncompressed key
 *
 *  Group arithmetic is done in Jacobian coordinates so the whole scalar
 *  multiply needs just one modular inverse (in Point::Reduce) at the end.
 *  The curve is  y^2 = x^3 + 7  (a = 0, b = 7).
 * ==========================================================================*/
#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"

/* address type selector (only P2PKH is used by the engines) */
#define P2PKH  0
#define P2SH   1
#define BECH32 2

class Secp256K1 {
public:
    Secp256K1();
    ~Secp256K1();

    void  Init();
    Point ComputePublicKey(Int* privKey);
    void  GetHash160(int type, bool compressed, Point& pubKey, unsigned char* hash);

    Point G;         /* generator            */
    Int   P;         /* field characteristic */
    Int   order;     /* group order          */

private:
    Point AddJ(Point& p, Point& q);   /* Jacobian point addition */
    Point DblJ(Point& p);             /* Jacobian point doubling */
};

#endif /* SECP256K1H */
