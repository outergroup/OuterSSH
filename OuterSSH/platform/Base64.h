#ifndef OUTERSSH_BASE64_H
#define OUTERSSH_BASE64_H
#include <stddef.h>
static inline size_t outerssh_base64_encode(unsigned char *output, const unsigned char *input, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t written = 0;
    for(size_t index = 0; index < length; index += 3) {
        size_t remaining = length - index;
        unsigned int value = (unsigned int)input[index] << 16;
        if(remaining > 1) value |= (unsigned int)input[index + 1] << 8;
        if(remaining > 2) value |= input[index + 2];
        output[written++] = alphabet[(value >> 18) & 63];
        output[written++] = alphabet[(value >> 12) & 63];
        output[written++] = remaining > 1 ? alphabet[(value >> 6) & 63] : '=';
        output[written++] = remaining > 2 ? alphabet[value & 63] : '=';
    }
    output[written] = 0; return written;
}
#endif
