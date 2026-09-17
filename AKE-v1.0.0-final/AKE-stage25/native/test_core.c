#include "ake_core.h"
#include <stdio.h>
#include <string.h>

static int check(int condition, const char *name) {
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); return 0; }
    printf("PASS: %s\n", name);
    return 1;
}

int main(int argc, char **argv) {
    int ok = 1;
    char error[512];
    ok &= check(ake_has_valid_extension("Example.ake"), ".ake accepted");
    ok &= check(!ake_has_valid_extension("Example.tar.xz"), "non-.ake rejected");
    ok &= check(ake_is_safe_relative_path("bin/example.exe"), "safe relative path");
    ok &= check(!ake_is_safe_relative_path("../../Windows/system32"), "parent traversal rejected");
    ok &= check(!ake_is_safe_relative_path("C:\\Windows"), "absolute drive path rejected");

    if (argc > 1) {
        int rc = ake_validate_package(argv[1], error, sizeof(error));
        ok &= check(rc == 0, "valid AKE package");
        char info[4096];
        rc = ake_package_info(argv[1], info, sizeof(info));
        ok &= check(rc == 0 && strstr(info, "entry=bin/Example.exe") != NULL, "metadata and entry parsed");
    }
    return ok ? 0 : 1;
}
