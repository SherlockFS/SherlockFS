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
    EVP_PKEY *existing_rsa_keypair = NULL;

    switch (argc)
    {
    case 2:
        path = argv[1];

        break;
    case 3:
        path = argv[1];
        passphrase = argv[2];
        break;

    default:
        printf("Usage: %s <device> [RSA key passphrase]\n", argv[0]);
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
            printf("Aborting...\n");
            return 0;
        }
        else
            printf("Overwriting...\n");
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

    format_fs(path, passphrase, existing_rsa_keypair);
    print_success("The device `%s` has been formatted successfully!\n", path);

    if (passphrase)
        free(passphrase);

    return 0;
}
