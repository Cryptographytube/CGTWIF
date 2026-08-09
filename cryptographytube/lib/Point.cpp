/* ============================================================================
 *  cryptographytube  -  Point : secp256k1 group element (host)
 *  Author: Sisujhon
 * ==========================================================================*/
#include "Point.h"

Point::Point() {}
Point::~Point() {}

Point::Point(const Point& p) {
    x.Set((Int*)&p.x);
    y.Set((Int*)&p.y);
    z.Set((Int*)&p.z);
}

void Point::Set(Point& p) {
    x.Set(&p.x);
    y.Set(&p.y);
    z.Set(&p.z);
}

void Point::Clear() {
    x.SetInt32(0);
    y.SetInt32(0);
    z.SetInt32(0);
}

bool Point::isZero() {
    return z.IsZero();
}

bool Point::equals(Point& p) {
    return x.IsEqual(&p.x) && y.IsEqual(&p.y) && z.IsEqual(&p.z);
}

/* Jacobian (X:Y:Z) -> affine (X/Z^2 : Y/Z^3 : 1) */
void Point::Reduce() {
    Int zinv(&z);
    zinv.ModInv();
    Int zinv2; zinv2.ModMul(&zinv, &zinv);
    Int zinv3; zinv3.ModMul(&zinv2, &zinv);
    x.ModMul(&x, &zinv2);
    y.ModMul(&y, &zinv3);
    z.SetInt32(1);
}
