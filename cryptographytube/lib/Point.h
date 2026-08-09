/* ============================================================================
 *  cryptographytube  -  Point : secp256k1 group element (host)
 *  Author: Sisujhon
 *
 *  A curve point in Jacobian projective coordinates (X : Y : Z), where the
 *  affine point is (X/Z^2, Y/Z^3) and Z == 0 marks the point at infinity.
 *  Working projectively lets the scalar multiply run with a single field
 *  inversion at the very end (Reduce), instead of one per group operation.
 * ==========================================================================*/
#ifndef CGT_POINT_H
#define CGT_POINT_H

#include "Int.h"

class Point {
public:
    Point();
    Point(const Point& p);
    ~Point();

    void Set(Point& p);
    void Clear();
    bool isZero();          /* point at infinity (Z == 0) */
    bool equals(Point& p);
    void Reduce();          /* projective -> affine (Z := 1) */

    Int x;
    Int y;
    Int z;
};

#endif /* CGT_POINT_H */
