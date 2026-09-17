#include "ake_extract.h"
#include "ake_core.h"
#include "ake_pack.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long file_size(const char *path) {
    FILE *fp = fopen(path, "rb");
    long n;
    assert(fp);
    fseek(fp, 0, SEEK_END);
    n = ftell(fp);
    fclose(fp);
    return n;
}

int main(void) {
    char error[512];
    const char *pkg = "testpkg-stage4.ake";
    const char *dst = "stage4-extracted";
    remove(pkg);
#ifdef _WIN32
    system("rmdir /s /q stage4-extracted >nul 2>&1");
#else
    system("rm -rf stage4-extracted");
#endif

    assert(ake_pack_directory("testpkg", pkg, error, sizeof(error)) == 0);
    assert(ake_extract_package(pkg, dst, error, sizeof(error)) == 0);
    assert(file_size("stage4-extracted/bin/Example.exe") == 12);
    assert(file_size("stage4-extracted/config/app.ini") == 10);
    assert(file_size("stage4-extracted/lib/Example.dll") == 17);
    assert(file_size("stage4-extracted/metadata/package.ake") > 0);
    assert(ake_validate_package(pkg, error, sizeof(error)) == 0);

    remove(pkg);
#ifdef _WIN32
    system("rmdir /s /q stage4-extracted >nul 2>&1");
#else
    system("rm -rf stage4-extracted");
#endif
    puts("AKE extraction tests: PASS");
    return 0;
}
