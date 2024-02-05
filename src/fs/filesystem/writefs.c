#include "writefs.h"

#include <stdio.h>
#include <stdlib.h>

#include "print.h"

void write_cryptfs_headers(const char *device_path,
                           const struct CryptFS *cryptfs)
{
    FILE *device = fopen(device_path, "r+");

    if (device == NULL)
        error_exit("Cannot open device '%s'.\n", EXIT_FAILURE, device_path);

    if (fwrite(cryptfs, sizeof(struct CryptFS), 1, device) != 1)
        error_exit("Cannot write the filesystem structure.\n", EXIT_FAILURE);

    fclose(device);
}
