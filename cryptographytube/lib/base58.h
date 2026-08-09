#ifndef CGT_BASE58_H
#define CGT_BASE58_H

/* ============================================================================
 *  cryptographytube  -  Base58 / Base58Check codec (host)
 *  Author: Sisujhon
 *
 *  Clean-room Base58 encode/decode for Bitcoin keys and addresses.
 *      b58enc    binary  -> Base58 text   (used for the P2PKH address)
 *      b58tobin  Base58   -> binary        (used to unpack a WIF)
 *  Decode right-aligns the big-endian value into the caller's buffer and
 *  writes the canonical byte length back through binsz, matching what the
 *  scanner expects when it pulls the 32-byte key out of a decoded WIF.
 * ==========================================================================*/

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool b58enc(char* b58, size_t* b58sz, const void* bin, size_t binsz);
bool b58tobin(void* bin, size_t* binsz, const char* b58, size_t b58sz);

#ifdef __cplusplus
}
#endif

#endif /* CGT_BASE58_H */
