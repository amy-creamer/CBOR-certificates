/* C509 Certificate native encoder/decoder */

#include <cstdint>

typedef struct {
    size_t length;
    uint8_t *data;
} biguint_t;

typedef