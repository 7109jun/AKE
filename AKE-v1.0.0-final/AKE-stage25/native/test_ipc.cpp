#include "ake_ipc.h"
#include <cstdio>
#include <cstring>

int main() {
    char out[512]{};
    if (ake_ipc_validate_component("AKE_demo-01") != 0) return 1;
    if (ake_ipc_validate_component("bad/name") == 0) return 2;
    if (ake_ipc_build_pipe_name("AKE_demo-01", "default", out, sizeof(out)) != 0) return 3;
    if (std::strstr(out, "default") == nullptr) return 4;
#ifdef _WIN32
    if (std::strstr(out, "\\\\.\\pipe\\AKE\\") == nullptr) return 5;
#else
    if (std::strstr(out, "ake-ipc/") == nullptr) return 5;
#endif
    std::puts("AKE IPC tests: PASS");
    return 0;
}
