/* ============================================================================
 *  cryptographytube  -  Base58 / Base58Check codec (host)
 *  Author: Sisujhon
 *
 *  Original implementation.  Base58 is plain base conversion of a byte string
 *  read as one big-endian integer, using the Bitcoin alphabet.  Leading zero
 *  bytes map to leading '1' characters and vice versa.
 * ==========================================================================*/
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base58.h"

/* Bitcoin Base58 alphabet (no 0 O I l) */
static const char B58[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* value 0..57 of a Base58 character, or -1 if not in the alphabet */
static int b58val(char c) {
    for (int i = 0; i < 58; i++)
        if (B58[i] == c) return i;
    return -1;
}

/* ----------------------------------------------------------------- encode */
/* Encode `binsz` bytes into a NUL-terminated Base58 string.  *b58sz is the
 * size of the output buffer on entry; on success it becomes the string
 * length including the NUL.  Returns false (and the required size) if the
 * buffer is too small.                                                     */
bool b58enc(char* b58, size_t* b58sz, const void* bin, size_t binsz) {
    const uint8_t* data = (const uint8_t*)bin;

    /* leading zero bytes become leading '1's */
    size_t zeros = 0;
    while (zeros < binsz && data[zeros] == 0) zeros++;

    /* upper bound on base58 digits: log(256)/log(58) ~= 1.365 per byte */
    size_t cap = (binsz - zeros) * 138 / 100 + 1;
    uint8_t* buf = (uint8_t*)malloc(cap);
    if (!buf) return false;
    memset(buf, 0, cap);

    /* repeated 256 -> 58 base conversion; buf holds digits big-endian, so
     * multiplying the running value by 256 and adding each input byte means
     * sweeping the whole width low-to-high and letting the carry ripple up */
    for (size_t i = zeros; i < binsz; i++) {
        int carry = data[i];
        for (size_t j = cap; j-- > 0; ) {
            carry += 256 * buf[j];
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        /* cap was sized with headroom, so the sweep always absorbs the carry */
    }

    /* skip the leading zero digits that were never written into */
    size_t start = 0;
    while (start < cap && buf[start] == 0) start++;

    size_t need = zeros + (cap - start) + 1;   /* + NUL */
    if (*b58sz < need) {
        *b58sz = need;
        free(buf);
        return false;
    }

    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) b58[o++] = '1';
    for (size_t i = start; i < cap; i++)  b58[o++] = B58[buf[i]];
    b58[o] = '\0';
    *b58sz = o + 1;

    free(buf);
    return true;
}

/* ----------------------------------------------------------------- decode */
/* Decode a Base58 string into `bin`.  *binsz is the buffer size on entry;
 * the decoded value is stored big-endian, right-aligned (leading bytes are
 * zero-padded).  On success *binsz is updated to the canonical byte length
 * (leading zero bytes collapsed to the '1' prefix count).  Returns false on
 * an invalid character or if the value does not fit in the buffer.         */
bool b58tobin(void* bin, size_t* binsz, const char* b58, size_t b58sz) {
    uint8_t* out = (uint8_t*)bin;
    size_t   cap = *binsz;

    if (!b58sz) b58sz = strlen(b58);

    memset(out, 0, cap);

    /* count and skip leading '1' characters (encoded leading zero bytes) */
    size_t zeros = 0;
    size_t i = 0;
    while (i < b58sz && b58[i] == '1') { zeros++; i++; }

    /* accumulate: out = out * 58 + digit, big-endian across the buffer */
    for (; i < b58sz; i++) {
        int v = b58val(b58[i]);
        if (v < 0) return false;              /* not a Base58 digit */

        int carry = v;
        for (size_t k = cap; k-- > 0; ) {
            carry += 58 * out[k];
            out[k] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
        if (carry) return false;              /* overflowed the buffer */
    }

    /* canonical length = (bytes of the non-zero part) + (encoded leading
     * zeros).  The buffer's leading zero run covers both the right-align
     * padding and the value's own leading zeros, so subtracting it leaves the
     * non-zero part; the '1'-prefix zeros are then added back on top.        */
    size_t lead = 0;
    while (lead < cap && out[lead] == 0) lead++;
    *binsz = (cap - lead) + zeros;

    return true;
}
