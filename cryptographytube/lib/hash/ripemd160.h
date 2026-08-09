/* ============================================================================
 *  cryptographytube  -  RIPEMD-160  (host, scalar)
 *  Author: Sisujhon
 *
 *  Original clean-room implementation.  Exposes an arbitrary-length one-shot
 *  and the fixed 32-byte variant used by the address pipeline (RIPEMD160 of a
 *  SHA-256 digest -> HASH160).
 * ==========================================================================*/
#ifndef CGT_RIPEMD160_H
#define CGT_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

void ripemd160(unsigned char* data, int len, unsigned char* out20);
void ripemd160_32(unsigned char* data32, unsigned char* out20);

#endif /* CGT_RIPEMD160_H */
