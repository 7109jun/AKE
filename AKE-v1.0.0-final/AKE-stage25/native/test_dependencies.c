#include <stdio.h>
#include <string.h>
#include "ake_core.h"

static int expect_ok(const char *path) {
    char out[8192];
    int rc = ake_package_info(path, out, sizeof(out));
    if (rc != 0) { fprintf(stderr, "expected OK, rc=%d: %s\n", rc, out); return 0; }
    return strstr(out, "dependency=") != NULL;
}

static int expect_bad(const char *path) {
    char out[8192];
    int rc = ake_package_info(path, out, sizeof(out));
    if (rc == 0) { fprintf(stderr, "expected rejection\n"); return 0; }
    return strstr(out, "dependency") != NULL;
}

int main(void) {
    if (!expect_ok("/tmp/dep.ake")) return 1;
    if (!expect_bad("/tmp/dep-bad.ake")) return 2;
    puts("AKE dependency metadata tests: PASS");
    return 0;
}
