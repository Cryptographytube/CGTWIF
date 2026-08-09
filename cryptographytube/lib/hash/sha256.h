/* ============================================================================
 *  cryptographytube  -  SHA-256  (host, scalar)
 *  Author: Sisujhon
 *
 *  Original clean-room implementation of FIPS 180-4 SHA-256.  Only the three
 *  entry points the address pipeline needs are exposed:
 *      sha256      arbitrary length one-shot
 *      sha256_33   fixed 33-byte input  (compressed public key)
 *      sha256_65   fixed 65-byte input  (uncompressed public key)
 * ==========================================================================*/
#ifndef CGT_SHA256_H
#define CGT_SHA256_H

#include <stdint.h>
#include <stddef.h>

void sha256(uint8_t* data, size_t len, uint8_t* out32);
void sha256_33(uint8_t* data, uint8_t* out32);
void sha256_65(uint8_t* data, uint8_t* out32);

#endif /* CGT_SHA256_H */
