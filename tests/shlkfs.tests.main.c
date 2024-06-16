#include "adduser.h"
#include "ascii.h"
#include "block.h"
#include "cryptfs.h"
#include "crypto.h"
#include "deluser.h"
#include "entries.h"
#include "fat.h"
#include "format.h"
#include "fuse_mount.h"
#include "fuse_ps_info.h"
#include "hash.h"
#include "io.h"
#include "maths.h"
#include "passphrase.h"
#include "print.h"
#include "readfs.h"
#include "writefs.h"
#include "xalloc.h"

int main(void)
{
    // Test SherlockFS stuff here
    print_info("Hello, SherlockFS!\n");

    return 0;
}
