#include "passphrase.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "print.h"
#include "xalloc.h"

#define PASSPHRASE_MAX_LENGTH 50

char *ask_user_passphrase(bool confirm)
{
    char *passphrase = NULL;
    char *passphrase_check = NULL;

    // Only echo '*' characters
    struct termios old_settings, new_settings;

    if (tcgetattr(STDIN_FILENO, &old_settings) < 0)
        internal_error_exit("Failed to get terminal settings", EXIT_FAILURE);

    new_settings = old_settings;
    new_settings.c_lflag &= ~ECHO;
    new_settings.c_lflag &= ~ICANON;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_settings) < 0)
        internal_error_exit("Failed to set terminal settings", EXIT_FAILURE);

    while (true)
    {
        confirm
            ? printf("Enter a passphrase (MAX : %u): ", PASSPHRASE_MAX_LENGTH)
            : printf("Enter passphrase: ");

        if (scanf("%ms", &passphrase) != 1 || printf("\n") < 0)
            internal_error_exit("Failed to read passphrase", EXIT_FAILURE);
        if (strlen(passphrase) <= PASSPHRASE_MAX_LENGTH)
        {
            if (confirm)
            {
                // Ask again to be sure the user entered the passphrase
                // correctly
                printf("Enter the same passphrase again: ");

                if (scanf("%ms", &passphrase_check) != 1 || printf("\n") < 0)
                    internal_error_exit("Failed to read second passphrase",
                                        EXIT_FAILURE);
                if (strcmp(passphrase, passphrase_check) == 0)
                {
                    print_success("Passphrase is valid!\n");
                    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
                    free(passphrase_check);
                    getchar(); // Consume the newline
                    return passphrase;
                }
                else
                {
                    print_warning("Passphrases do not match\n");
                    free(passphrase_check);
                    free(passphrase);
                }
            }
            else
            {
                tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
                getchar(); // Consume the newline
                return passphrase;
            }
        }

        else
            print_warning("Passphrase is of size %d, but the maximum allowed "
                          "size is %d",
                          strlen(passphrase), PASSPHRASE_MAX_LENGTH);
    };

    return NULL;
}

bool rsa_private_is_encrypted(const char *rsa_path)
{
    FILE *file = fopen(rsa_path, "r");
    if (!file)
        return false;
    char line[sizeof("-----BEGIN ENCRYPTED PRIVATE KEY-----")];
    bool is_private = false;
    if (fgets(line, sizeof(line), file))
        is_private = strstr(line, "ENCRYPTED");

    fclose(file);
    return is_private;
}
