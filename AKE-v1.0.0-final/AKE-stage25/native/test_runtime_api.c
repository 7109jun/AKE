#include "ake_runtime.h"
#include <stdio.h>
#include <stdint.h>

int main(void) {
    int running = 0;
    int exit_code = 0;
    int rc = ake_query_process(1u, &running, &exit_code);
#ifdef _WIN32
    if (rc != 0) {
        fprintf(stderr, "query process API failed: %d\n", rc);
        return 1;
    }
#else
    if (rc != 3) {
        fprintf(stderr, "non-Windows query stub returned %d\n", rc);
        return 1;
    }
#endif
    printf("AKE runtime ABI test: PASS\n");
    return 0;
}
