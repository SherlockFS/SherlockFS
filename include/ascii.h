#ifndef ASCII_H
#define ASCII_H

#include <stdbool.h>

/**
 * @brief Check if a string contain only readable ASCII characters.
 *
 * @param chaine String to test.
 * @return 0 if success, -1 otherwise.
 */
bool is_readable_ascii(const char *chaine);

#endif