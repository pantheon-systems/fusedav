#include <stdbool.h>
extern const int bits_in_chunk;

int bloom_add(const char *key, unsigned long salt, unsigned char *bloombits);
bool bloom_exists(const char *key, unsigned long salt, unsigned char *bloombits);
