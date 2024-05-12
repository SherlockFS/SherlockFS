#include "print.h"

#include <err.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static int print_level = PRINT_LEVEL_INFO;

#define BACKTRACE_SIZE 10

#define YELLOW_STR(STR) "\x1b[33m" STR "\x1b[0m"
#define RED_STR(STR) "\x1b[31m" STR "\x1b[0m"
#define GREEN_STR(STR) "\x1b[32m" STR "\x1b[0m"
#define BLUE_STR(STR) "\x1b[34m" STR "\x1b[0m"
#define MAGENTA_STR(STR) "\x1b[35m" STR "\x1b[0m"

void set_verbosity_level(int level)
{
    print_level = level;
}

void internal_error_exit(const char *msg, int error_code, ...)
{
    if (print_level >= PRINT_LEVEL_ERROR)
    {
        va_list args;
        va_start(args, error_code);
        fprintf(stderr, RED_STR("[INTERNAL ERROR]: "));
        vfprintf(stderr, msg, args);

#ifndef INTERNAL_ERROR_NO_BACKTRACE
        // Printing backtrace
        void *array[BACKTRACE_SIZE];
        size_t size;
        char **strings;
        size_t i;
        size = backtrace(array, BACKTRACE_SIZE);
        strings = backtrace_symbols(array, size);
        fprintf(
            stderr,
            RED_STR("[CRYPTFS STACK FRAMES]: ") "Obtained %zd stack frames.\n",
            size);
        for (i = 0; i < size; i++)
            fprintf(stderr, RED_STR("[CRYPTFS STACK FRAMES]: ") "%s\n",
                    strings[i]);
        free(strings);
#endif
        va_end(args);
    }
    exit(error_code);
}

void error_exit(const char *msg, int error_code, ...)
{
    if (print_level >= PRINT_LEVEL_ERROR)
    {
        va_list args;
        va_start(args, error_code);

        fprintf(stderr, RED_STR("[ERROR]: "));
        vfprintf(stderr, msg, args);
        va_end(args);
    }

    exit(error_code);
}

void warning_exit(const char *msg, int error_code, ...)
{
    if (print_level >= PRINT_LEVEL_WARNING)
    {
        va_list args;
        va_start(args, error_code);

        fprintf(stderr, YELLOW_STR("[WARNING]: "));
        vfprintf(stderr, msg, args);
        va_end(args);
    }
    exit(error_code);
}

void print_error(const char *msg, ...)
{
    if (print_level < PRINT_LEVEL_ERROR)
        return;

    va_list args;
    va_start(args, msg);
    fprintf(stderr, RED_STR("[ERROR]: "));
    vfprintf(stderr, msg, args);
    va_end(args);
}

void print_warning(const char *msg, ...)
{
    if (print_level < PRINT_LEVEL_WARNING)
        return;

    va_list args;
    va_start(args, msg);
    fprintf(stderr, YELLOW_STR("[WARNING]: "));
    vfprintf(stderr, msg, args);
    va_end(args);
}

void print_info(const char *msg, ...)
{
    if (print_level < PRINT_LEVEL_INFO)
        return;

    va_list args;
    va_start(args, msg);
    fprintf(stdout, BLUE_STR("[INFO]: "));
    vfprintf(stdout, msg, args);
    va_end(args);
}

void print_success(const char *msg, ...)
{
    if (print_level < PRINT_LEVEL_SUCCESS)
        return;
    va_list args;
    va_start(args, msg);
    fprintf(stdout, GREEN_STR("[SUCCESS]: "));
    vfprintf(stdout, msg, args);
    va_end(args);
}

void print_debug(const char *msg, ...)
{
    if (print_level < PRINT_LEVEL_DEBUG)
        return;
#ifndef NO_PRINT_DEBUG
    va_list args;
    va_start(args, msg);
    fprintf(stdout, MAGENTA_STR("[DEBUG]: "));
    vfprintf(stdout, msg, args);
    va_end(args);
#else
    (void)msg;
#endif
}
