#include "readfs.h"

#include <stdio.h>
#include <stdlib.h>

#include "print.h"
#include "xalloc.h"

struct CryptFS *read_cryptfs_headers(const char *device_path)
{
    FILE *device = fopen(device_path, "r");
    if (device == NULL)
        error_exit("Cannot open device '%s'.\n", EXIT_FAILURE, device_path);

    struct CryptFS *cryptfs =
        xaligned_calloc(CRYPTFS_BLOCK_SIZE_BYTES, 1, sizeof(struct CryptFS));
    if (fread(cryptfs, sizeof(struct CryptFS), 1, device) != 1)
        error_exit("Cannot read the filesystem structure.\n", EXIT_FAILURE);

    fclose(device);

    return cryptfs;
}
