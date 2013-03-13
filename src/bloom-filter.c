#include <limits.h>
#include <time.h>
#include <linux/time.h>
#include <zlib.h>
#include <malloc.h>

#include "bloom-filter.h"
#include "log.h"

/* Options that the bloom filter will use, but not visible to clients */
struct bloomfilter_options_t {
    // Area for storing the bloom filter bits
    unsigned char *bitfield;
    // Expected max number of items this instantiation of the filter needs to deal with
    // This will determine the size of the bitfield and the way it is processed.
    // This can be user-supplied.
    unsigned int maxkeys;
    // The initial salt value
    // This can be user-supplied.
    unsigned long salt;

    /* The hash value returned from the hash function might be processed in 1 or more chunks.
     * For instance, a 32-bit value might be processed as 2 shorts. This would mean
     * that a particular key is represented by 2 separate bits in the bit array.
     * In conjunction with the size of the chunk we want to deal with (16 bits),
     * we get the value of num_chunks based on the size of the return value from
     * the specific hash function we end up calling.
     */
    unsigned int bits_in_chunk;
    unsigned int num_chunks;
    unsigned int bits_in_hash_return;
    unsigned long filtersize;

    unsigned long (*hashfcn) (unsigned long, const void *, size_t);
};

/* For passing values around */
typedef struct values_s {
    unsigned char bitvalue;
    unsigned short bytevalue;
    unsigned long hashvalue;
} values_t;

/* Default salt value */
static long set_salt(void) {
    //struct timespec ts;
    //clock_gettime(CLOCK_MONOTONIC, &ts);
    //return ts.tv_nsec;
    log_print(LOG_DEBUG, "set_salt");

    return time(NULL);
}

/* calculate the sizes of values for the filter and for accessing it.
 * Based on investigations online, size of filter should be 1.44x the
 * max number of keys expected. Make this adjustment.
 * We use two bits to represent the key. Just because...
 * We use an integer of some size to index it.
 * If the filter size is small enough to be indexed with a uchar (maxkeys < 88), do so;
 * if it requires a ushort (maxkeys < 22755), use it;
 * if it requires a uint (maxkeys < 1,491,308), use it;
 * otherwise bail.
 */

static int calculate_sizes(bloomfilter_options_t *options) {
    options->filtersize = options->maxkeys * 1.44;
    if (((options->filtersize * 2) <= UCHAR_MAX) && (options->bits_in_hash_return >= 16)) {
        options->bits_in_chunk = 8;
        options->num_chunks = 2;
        options->filtersize = ((UCHAR_MAX) / 8) + 1; // divide by 8 to get number of bytes
    }
    else if (((options->filtersize * 2) <= USHRT_MAX) && options->bits_in_hash_return >= 32) {
        options->bits_in_chunk = 16;
        options->num_chunks = 2;
        options->filtersize = ((USHRT_MAX) / 8) + 1; // divide by 8 to get number of bytes
        log_print(LOG_DEBUG, "calculate_sizes: %d %d %d", options->bits_in_chunk, options->num_chunks, options->filtersize);

    }
    else if (((options->filtersize * 2) <= UINT_MAX) && options->bits_in_hash_return >= 64) {
        options->bits_in_chunk = 32;
        options->num_chunks = 2;
        options->filtersize = ((UINT_MAX) / 8) + 1; // divide by 8 to get number of bytes
    }
    else {
        return -1;
    }
    return 0;
}

/* Generic wrapper. For now, calls adler32
 */
static unsigned long hashfunction(unsigned long salt, const void *key, size_t klen) {
    return adler32(salt, (const Bytef *)key, klen);
}

/* Initialize the filter */
bloomfilter_options_t *bloomfilter_init(unsigned long maxkeys, unsigned long salt,
        unsigned long (*hashfcn)(unsigned long, const void *, size_t), unsigned int bits_in_hash_return, char **errptr) {
    bloomfilter_options_t *options;
    bool err = false;

    options = calloc(1, sizeof(bloomfilter_options_t));
    if (options == NULL) {
        errptr = calloc(256, sizeof(char *));
        if (errptr == NULL) {
            // How do you tell them what the error is if you couldn't allocate the errptr?
            err = true;
            goto finish;
        }
        strcpy(*errptr, "Failed to alloc options");
        err = true;
        goto finish;
    }

    if (maxkeys == 0) {
        options->maxkeys = 22755; // expected max keys; actually the calculated value that can use a short as an index, our default
        log_print(LOG_DEBUG, "bloomfilter_init: max_keys %d", options->maxkeys);
    }
    else {
        options->maxkeys = maxkeys;
    }

    if (salt == 0) {
        options->salt = set_salt();
        log_print(LOG_DEBUG, "bloomfilter_init: set_salt %d", options->salt);
    }
    else {
        options->salt = salt;
    }

    if (hashfcn == NULL) {
        options->hashfcn = &hashfunction;
        options->bits_in_hash_return = 32; // because our default is adler32
        log_print(LOG_DEBUG, "bloomfilter_init: hashfcn %d", options->bits_in_hash_return);
    }
    else {
        options->hashfcn = hashfcn;
        if (bits_in_hash_return == 0) {
            errptr = calloc(256, sizeof(char *));
            if (errptr == NULL) {
                // How do you tell them what the error is if you couldn't allocate the errptr?
                err = true;
                goto finish;
            }
            strcpy(*errptr, "If hash function is passed in, bits_in_hash_return must be non-zero");
            err = true;
            goto finish;
        }
    }

    if (calculate_sizes(options) < 0) {
        errptr = calloc(256, sizeof(char *));
        if (errptr == NULL) {
            // How do you tell them what the error is if you couldn't allocate the errptr?
            err = true;
            goto finish;
        }
        strcpy(*errptr, "Can't create filter; maxkeys too large for bits in hash function return");
        err = true;
        goto finish;
    }

    options->bitfield = calloc(options->filtersize, sizeof(void *));
    if (options->bitfield == NULL) {
        errptr = calloc(256, sizeof(char *));
        if (errptr == NULL) {
            // How do you tell them what the error is if you couldn't allocate the errptr?
            err = true;
            goto finish;
        }
        strcpy(*errptr, "Can't create filter; failed to allocate bitfield");
        err = true;
        goto finish;
    }
    log_print(LOG_DEBUG, "bloomfilter_init: bitfield %d", options->filtersize);

finish:
    if (err) {
        if (options) {
            free (options);
            options = NULL;
        }
    }

    return options;
}

/* Calculate the byte location in the array, then the bit location in the byte
 */
static values_t byte_bit_location(unsigned long startvalue, int bits_in_chunk) {
    unsigned short hashvalue;
    values_t values;

    hashvalue = startvalue & 0xffff;
    // divide by 8 to get byte, then mod by 8 to get bit; or shift and mask instead
    values.bitvalue = hashvalue & 0x7;
    // bitvalue represents bit in byte, e.g. if bitvalue starts at 7, it ends up at
    // 128, or 0x80, or 1000 0000
    values.bitvalue = 1 << values.bitvalue;
    values.bytevalue = hashvalue >> 3;
    startvalue >>= bits_in_chunk;
    values.hashvalue = startvalue;
    return values;
}

/* Add a key to the bloom filter */
int bloomfilter_add(bloomfilter_options_t *options, const void *key, size_t klen) {
    values_t values;

    log_print(LOG_DEBUG, "bloomfilter_add: enter \'%s\' :: salt %ul", key, options->salt);
    values.hashvalue = options->hashfcn(options->salt, key, klen);
    for (unsigned int idx = 0; idx < options->num_chunks; idx++) {
        values = byte_bit_location(values.hashvalue, options->bits_in_chunk);
        log_print(LOG_DEBUG, "bloomfilter_add: iter %d :: key: \'%s\' :: salt: %ul :: byte %d :: bit %d", idx, key, values.hashvalue, values.bytevalue, values.bitvalue);
        options->bitfield[values.bytevalue] |= values.bitvalue;
    }
    return 0;
}

/* See if key exists in the bloom filter */
bool bloomfilter_exists(bloomfilter_options_t * options, const void *key, size_t klen) {
    values_t values;

    log_print(LOG_DEBUG, "bloomfilter_exists: enter \'%s\' :: salt %ul", key, options->salt);
    values.hashvalue = options->hashfcn(options->salt, key, klen);
    for (unsigned int idx = 0; idx < options->num_chunks; idx++) {
        values = byte_bit_location(values.hashvalue, options->bits_in_chunk);
        log_print(LOG_DEBUG, "bloomfilter_exists: iter %d :: key: \'%s\' :: salt: %ul :: byte %d :: bit %d", idx, key, values.hashvalue, values.bytevalue, values.bitvalue);
        if ((options->bitfield[values.bytevalue] & values.bitvalue) == 0) return false;
    }
    return true;
}

void bloomfilter_destroy(bloomfilter_options_t * options) {
    if (options) {
        log_print(LOG_DEBUG, "bloomfilter_destroy: destroy");
        if (options->bitfield) free(options->bitfield);
        free(options);
    }
}
