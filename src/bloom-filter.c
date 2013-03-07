#include <zlib.h>
#include "bloom-filter.h"
#include "log.h"

/* The hash value returned from the hash function might be processed in 1 or more chunks.
 * For instance, a 32-bit value might be processed as 2 shorts. This would mean
 * that a particular key is represented by 2 separate bits in the bit array.
 * In conjunction with the size of the chunk we want to deal with (16 bits),
 * we get the value of num_chunks based on the size of the return value from
 * the specific hash function we end up calling.
 */
static int num_chunks;
// Arbitrarily, we're going to process return from hash function 16 bits at a time
const int bits_in_chunk = 16;

/* Calculate the byte location in the array, then the bit location in the byte
 */
static void byte_bit_location(unsigned long *startvalue, unsigned short *bytevalue, unsigned char *bitvalue) {
    unsigned short hashvalue;

    hashvalue = *startvalue & 0xffff;
    // divide by 8 to get byte, then mod by 8 to get bit; or shift and mask instead
    *bitvalue = hashvalue & 0x7;
    *bytevalue = hashvalue >> 3;
    // bitvalue represents bit in byte, e.g. if bitvalue starts at 7, it ends up at
    // 128, or 0x80, or 1000 0000
    *bitvalue = 1 << *bitvalue;
    *startvalue >>= bits_in_chunk;
}

/* Generic wrapper. For now, calls adler32
 */
static long hashfunction(unsigned long salt, const char *key) {
    // While the utilities we are using don't assume null-terminated c strings,
    // and so rely on key length variable, with keys being strings
    // klen should always be strlen(key). Relying on calculating the klen elsewhere
    // and passing it through is less robust than calculating it here.
    int klen = strlen(key);
    // adler returns a 32 bits in value, so process as 2 shorts
    num_chunks = 32 / bits_in_chunk;
    return adler32(salt, (const Bytef *)key, klen);
}

// salt_value is both the initial salt, plus the return from calculating the hash value
int bloom_add(const char *key, unsigned long salt_value, unsigned char *bloombits) {
    unsigned char bitvalue;
    unsigned short bytevalue;

    log_print(LOG_DEBUG, "bloom_add: enter \'%s\' :: salt %ul", key, salt_value);
    salt_value = hashfunction(salt_value, key);
    for (int idx = 0; idx < num_chunks; idx++) {
        byte_bit_location(&salt_value, &bytevalue, &bitvalue);
        log_print(LOG_DEBUG, "bloom_add: iter %d :: key: \'%s\' :: salt: %ul :: byte %d :: bit %d", idx, key, salt_value, bytevalue, bitvalue);
        bloombits[bytevalue] |= bitvalue;
    }
    return 0;
}

bool bloom_exists(const char *key, unsigned long salt_value, unsigned char *bloombits) {
    unsigned char bitvalue;
    unsigned short bytevalue;

    log_print(LOG_DEBUG, "bloom_exists: enter \'%s\' :: salt %ul", key, salt_value);
    salt_value = hashfunction(salt_value, key);
    for (int idx = 0; idx < num_chunks; idx++) {
        byte_bit_location(&salt_value, &bytevalue, &bitvalue);
        log_print(LOG_DEBUG, "bloom_exists: iter %d :: key: \'%s\' :: salt: %ul :: byte %d :: bit %d", idx, key, salt_value, bytevalue, bitvalue);
        if ((bloombits[bytevalue] & bitvalue) == 0) return false;
    }
    return true;
}
