#include "ake_windows.h"
#include "ake_isolation.h"
#include <stdio.h>

int main(void) {
    int exit_code = -1;
    int rc = ake_spawn_process_in_directory("", "", ".", &exit_code);
    if (rc != 2) {
        fprintf(stderr, "invalid program test failed: rc=%d\n", rc);
        return 1;
    }
#ifdef _WIN32
    rc = ake_spawn_process_in_directory("C:\\Windows\\System32\\cmd.exe", "/c exit 7", ".", &exit_code);
    if (rc != 0 || exit_code != 7) {
        fprintf(stderr, "Windows process test failed: rc=%d exit=%d\n", rc, exit_code);
        return 1;
    }
    static const unsigned char envblock[] = "Path=C:\\Windows\\System32\\WindowsPowerShell\\v1.0;\0\0";
    rc = ake_spawn_isolated_process(
        "C:\\Windows\\System32\\cmd.exe", "/c exit 9", ".",
        envblock, sizeof(envblock),
        "AKE_Test_Limits", 2, 0, 0, 2,
        256ULL * 1024ULL * 1024ULL, 5000, 8, 10ULL * 10000000ULL,
        &exit_code);
    if (rc != 0 || exit_code != 9) {
        fprintf(stderr, "Windows resource-limit process test failed: rc=%d exit=%d\n", rc, exit_code);
        return 1;
    }
    puts("AKE runtime process tests: PASS");
#else
    rc = ake_spawn_process_in_directory("dummy.exe", "", ".", &exit_code);
    if (rc != 3) {
        fprintf(stderr, "non-Windows guard test failed: rc=%d\n", rc);
        return 1;
    }
    rc = ake_spawn_isolated_process("dummy.exe", "", ".",
        (const unsigned char*)"X=1\0\0", 4, "AKE_Test_Limits", 2, 0, 0, 0,
        256ULL * 1024ULL * 1024ULL, 5000, 8, 10ULL * 10000000ULL, &exit_code);
    if (rc != 3) {
        fprintf(stderr, "non-Windows resource ABI guard test failed: rc=%d\n", rc);
        return 1;
    }
    puts("AKE runtime process tests: PASS (non-Windows guard)");
#endif
    return 0;
}
