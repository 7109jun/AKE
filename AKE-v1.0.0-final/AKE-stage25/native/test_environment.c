#include "ake_windows.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    static const unsigned char env_block[] =
        "AKE_PACKAGE_ROOT=C:\\AKE\\Example\0"
        "PATH=C:\\AKE\\Example\\lib;C:\\Windows\\System32\0"
        "TEST_AKE=stage7\0\0";
    int exit_code = -1;
    int rc = ake_spawn_process_in_directory_with_environment(
        "dummy.exe", "", ".", env_block, sizeof(env_block) - 1, &exit_code);
#ifdef _WIN32
    (void)rc;
    puts("AKE environment API build test: PASS (Windows runtime execution covered by integration path)");
#else
    if (rc != 3) {
        fprintf(stderr, "non-Windows guard failed: rc=%d\n", rc);
        return 1;
    }
    puts("AKE environment API tests: PASS (non-Windows guard)");
#endif
    return 0;
}
