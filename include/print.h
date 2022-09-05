#ifndef PRINT_H
#define PRINT_H

/**
 * @brief Prints an error message on stderr and exits the program.
 * This function also prints the backtrace of the program.
 *
 * @param msg The error message to print.
 * @param error_code The error code to exit with.
 */
void internal_error_exit(const char *msg, int error_code, ...);

/**
 * @brief Prints an error message on stderr and exits the program.
 *
 * @param msg The error message to print.
 * @param error_code The error code to exit with.
 */
void error_exit(const char *msg, int error_code, ...);

/**
 * @brief Prints an error message on stderr.
 *
 * @param msg The error message to print.
 */
void print_error(const char *msg, ...);

/**
 * @brief Prints a warning message on stderr.
 *
 * @param msg The warning message to print.
 */
void print_warning(const char *msg, ...);

/**
 * @brief Prints an info message on stderr.
 *
 * @param msg The info message to print.
 */
void print_info(const char *msg, ...);

/**
 * @brief Prints a debug message on stderr.
 *
 * @param msg The debug message to print.
 */
void print_success(const char *msg, ...);

#endif /* PRINT_H */
