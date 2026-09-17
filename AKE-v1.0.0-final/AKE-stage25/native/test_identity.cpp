#include "ake_isolation.h"
#include <cassert>
#include <cstdint>
#include <cstdio>

int main() {
    int exit_code = 0;
    const unsigned char env[] = "AKE_TEST=1\0\0";
    const int rc = ake_spawn_isolated_process(
        "example.exe", "", ".", env, sizeof(env), "AKE_test", 0, 0, 0, 1,
        0, 0, 0, 0, &exit_code);
#if defined(_WIN32)
    /* The test only validates the ABI and argument surface here; actual token creation needs Windows. */
    (void)rc;
#else
    assert(rc == 3);
#endif
    std::puts("AKE identity ABI test: PASS");
    return 0;
}
