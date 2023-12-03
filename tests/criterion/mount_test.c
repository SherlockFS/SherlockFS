#include <criterion/criterion.h>
#include <criterion/redirect.h>

// #include "mount.h"

// Test(mount_exists, not_exist, .timeout = 10, .init = cr_redirect_stdout)
// {
//     int result = mount_exists("build/tests/mount_exists.not_exist.test.cfs",
//     "build/tests/mount_exists.not_exist.test.cfs"); cr_assert_eq(result, -1,
//     "result = %d", result);
// }

// Test(mount_exists, not_a_cryptfs, .timeout = 10, .init = cr_redirect_stdout)
// {
//     int result =
//     mount_exists("build/tests/mount_exists.not_a_cryptfs.test.cfs",
//     "build/tests/mount_exists.not_a_cryptfs.test.cfs"); cr_assert_eq(result,
//     1, "result = %d", result);
// }

// Test(mount_exists, exist, .timeout = 10, .init = cr_redirect_stdout)
// {
//     int result = mount_exists("build/tests/mount_exists.exist.test.cfs",
//     "build/tests/mount_exists.exist.test.cfs"); cr_assert_eq(result, 0,
//     "result = %d", result);
// }
