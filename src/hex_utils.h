#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C++"
{
#endif

    size_t bytes_to_hex(char *hex, size_t hex_len, const uint8_t *bytes, size_t bytes_len);

    /* ================================================== */
    /* ================================================== */
    /* ================================================== */

#ifndef HEX_UTILS_NO_IMPL

    size_t bytes_to_hex(char *hex, size_t hex_len, const uint8_t *bytes, size_t bytes_len)
    {
        static const char charset[17] = "0123456789abcdef";

        if (hex == NULL || hex_len == 0)
        {
            return 0;
        }

        *hex = '\0';

        if (bytes == NULL || bytes_len == 0)
        {
            return 0;
        }

        size_t hex_min_len = (bytes_len * 2) + 1;
        if (hex_len < hex_min_len)
        {
            return 0;
        }

        const uint8_t *bytes_end = (bytes + bytes_len);

        uint8_t b;
        for (; bytes < bytes_end; ++bytes)
        {
            b = *bytes;

            *hex++ = charset[(b & 0xf0) >> 4];
            *hex++ = charset[b & 0x0f];
        }

        *hex = '\0';

        return bytes_len;
    }

#endif // HEX_UTILS_NO_IMPL

#ifdef __cplusplus
}
#endif

#endif // HEX_UTILS_H