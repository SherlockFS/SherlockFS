#include "ascii.h"

bool is_readable_ascii(const char *chaine) {
    while (*chaine) {
        if ((unsigned char)(*chaine) < 32 || (unsigned char)(*chaine) > 127) {
            return false;
        }
        chaine++;
    }
    return true;
}