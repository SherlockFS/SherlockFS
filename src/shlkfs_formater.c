#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"
#include "format.h"
#include "io.h"
#include "passphrase.h"
#include "print.h"
#include "xalloc.h"

static void ask_new_password(char **passphrase)
{
    printf("Do you want to secure your new key with a passphrase? [y/n]: ");
    char answer = getchar();
    getchar(); // Consume the newline

    if (answer != 'y' && answer != 'Y')
    {
        print_warning("No passphrase will be used. The key may be exposed.\n");
        (void)passphrase;
    }
    else
        *passphrase = ask_user_passphrase(true);
}

int main(int argc, char *argv[])
{
    char *passphrase = NULL;
    char *path = NULL;
    char *label = NULL;
    EVP_PKEY *existing_rsa_keypair = NULL;

    switch (argc)
    {
    case 2:
        path = argv[1];
        break;
    case 3:
        path = argv[1];
        label = argv[2];
        break;
    default:
        printf("SherlockFS v%d - Format a device\n", CRYPTFS_VERSION);
        printf("\tUsage: %s <device> [label]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // ALREADY FORMATTED
    if (is_already_formatted(path))
    {
        print_warning(
            "The device is already formatted. Do you want to overwrite it? "
            "[y/n]: ");
        char answer = get_char_from_stdin();
        if (answer != 'y' && answer != 'Y')
        {
            print_info("Aborting...");
            return 0;
        }
        else
            print_info("Overwriting...\n");
    }

    // KEYS ALREADY PRESENT IN HOME
    if (keypair_in_home_exist())
    {
        print_info("Keys already generated, do you want to use them? [y/n] ");
        char answer = get_char_from_stdin();
        if (answer == 'y' || answer == 'Y')
            existing_rsa_keypair = load_rsa_keypair_from_home(&passphrase);
        else
            ask_new_password(&passphrase);
    }
    else
        ask_new_password(&passphrase);

    format_fs(path, NULL, NULL, label, passphrase, existing_rsa_keypair);
    print_success("The device `%s` has been formatted successfully!\n", path);

    free(passphrase);
    if (existing_rsa_keypair != NULL)
        EVP_PKEY_free(existing_rsa_keypair);

    return 0;
}
