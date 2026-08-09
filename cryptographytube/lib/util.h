/* ============================================================================
 *  cryptographytube  -  small host-side helpers
 *  Author: Sisujhon
 *
 *  Hex formatting, a Base58Check address builder and thin Base58 wrappers
 *  used by the scanner engines.
 * ==========================================================================*/
#ifndef CGT_UTIL_H
#define CGT_UTIL_H

#include <string>
#include <stddef.h>

/* hex helpers */
char* tohex(char* ptr, int length);                 /* malloc'd hex string   */
void  tohex_dst(char* ptr, int length, char* dst);  /* hex into caller buffer*/
int   hexchr2bin(char hex, char* out);
int   hexs2bin(char* hex, unsigned char* out);
int   isValidHex(char* data);

/* Base58Check P2PKH/P2SH address from a 20-byte HASH160 */
void addressToBase58(char* rmd, char* dst, bool p2sh);

/* Base58 wrappers (see base58.h) */
bool b58encode(char* b58, size_t* b58sz, const void* data, size_t binsz);
bool b58decode(unsigned char* bin, size_t* binszp, const char* b58, size_t b58sz);

/* misc */
std::string formatDouble(const char* formatStr, double value);

#endif /* CGT_UTIL_H */
