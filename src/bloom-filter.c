#include <zlib.h>
#include "bloom-filter.h"
#include "log.h"

// adler32 returns 32-bit number, not 64-bit

// We are not using a byte to store a value
int bloom_add(const char *key, int klen, unsigned long adler, char *bloombits) {
    int idx;
    unsigned short hashvalue;

    log_print(LOG_INFO, "bloom_add: enter \'%s\' :: a %ul", key, adler);
    adler = adler32(adler, (const Bytef *)key, klen);
    for (idx = 0; idx < 2; idx++) {
        hashvalue = adler & 0xffff;
        log_print(LOG_INFO, "bloom_add: \'%s\' :: v %ul :: a %ul :: kl %d", key, hashvalue, adler, klen);
        bloombits[hashvalue] = 1;
        adler >>= 16;
    }
    return 0;
}

bool bloom_exists(const char *key, int klen, unsigned long adler, char *bloombits) {
    int idx;
    unsigned short hashvalue;

    log_print(LOG_INFO, "bloom_exists: enter \'%s\' :: a %ul", key, adler);
    adler = adler32(adler, (const Bytef *)key, klen);
    for (idx = 0; idx < 2; idx++) {
        hashvalue = adler & 0xffff;
        log_print(LOG_INFO, "bloom_exists: \'%s\' :: v %ul :: %ul :: kl %d", key, hashvalue, adler, klen);
        if (bloombits[hashvalue] != 1) return false;
        adler >>= 16;
    }
    return true;
}
