/* ============================================================================
 *  cryptographytube  -  small host-side helpers
 *  Author: Sisujhon
 * ==========================================================================*/
#include <stdint.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include "util.h"
#include "hash/sha256.h"
#include "base58.h"

/* ---- hex ---------------------------------------------------------------- */
char* tohex(char* ptr, int length) {
    char* buf = (char*)malloc((size_t)length * 2 + 1);
    if (!buf) return NULL;
    for (int i = 0; i < length; i++)
        sprintf(buf + i * 2, "%.2x", (unsigned char)ptr[i]);
    buf[length * 2] = '\0';
    return buf;
}

void tohex_dst(char* ptr, int length, char* dst) {
    for (int i = 0; i < length; i++)
        sprintf(dst + i * 2, "%.2x", (unsigned char)ptr[i]);
    dst[length * 2] = '\0';
}

int hexchr2bin(char hex, char* out) {
    if (!out) return 0;
    if      (hex >= '0' && hex <= '9') *out = hex - '0';
    else if (hex >= 'A' && hex <= 'F') *out = hex - 'A' + 10;
    else if (hex >= 'a' && hex <= 'f') *out = hex - 'a' + 10;
    else return 0;
    return 1;
}

int hexs2bin(char* hex, unsigned char* out) {
    if (!hex || !*hex || !out) return 0;
    int len = (int)strlen(hex);
    if (len & 1) return 0;
    len /= 2;
    for (int i = 0; i < len; i++) {
        char hi, lo;
        if (!hexchr2bin(hex[i * 2], &hi) || !hexchr2bin(hex[i * 2 + 1], &lo))
            return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return len;
}

int isValidHex(char* data) {
    for (int i = 0; data[i]; i++) {
        char c = data[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* ---- Base58Check address ------------------------------------------------ *
 * digest = version || hash160 || checksum, where the checksum is the first 4
 * bytes of SHA256(SHA256(version || hash160)).  The 25 bytes are then Base58
 * encoded.  Version 0x00 -> P2PKH ('1...'), 0x05 -> P2SH ('3...').          */
void addressToBase58(char* rmd, char* dst, bool p2sh) {
    unsigned char digest[25];
    digest[0] = p2sh ? 0x05 : 0x00;
    memcpy(digest + 1, rmd, 20);

    unsigned char h1[32], h2[32];
    sha256(digest, 21, h1);        /* first hash over version||hash160 */
    sha256(h1, 32, h2);            /* double SHA-256 */
    memcpy(digest + 21, h2, 4);    /* 4-byte checksum */

    size_t sz = 40;
    if (!b58encode(dst, &sz, digest, 25))
        fprintf(stderr, "addressToBase58: buffer too small\n");
}

/* ---- Base58 wrappers ---------------------------------------------------- */
bool b58encode(char* b58, size_t* b58sz, const void* data, size_t binsz) {
    return b58enc(b58, b58sz, data, binsz);
}

bool b58decode(unsigned char* bin, size_t* binszp, const char* b58, size_t b58sz) {
    return b58tobin(bin, binszp, b58, b58sz);
}

/* ---- misc --------------------------------------------------------------- */
std::string formatDouble(const char* formatStr, double value) {
    char buf[128] = {0};
    snprintf(buf, sizeof(buf), formatStr, value);
    return std::string(buf);
}
