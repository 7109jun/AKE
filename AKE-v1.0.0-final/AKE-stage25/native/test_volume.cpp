#include "ake_volume.h"
#include <cstdio>
#ifdef _WIN32
int main() { std::puts("AKE volume native test: Windows integration required"); return 0; }
#else
#include <string>
#include <sys/stat.h>
#include <unistd.h>
static bool exists(const char *p) { struct stat st{}; return stat(p, &st) == 0; }
int main() {
    char base[] = "/tmp/ake-volume-test-XXXXXX"; char *root = mkdtemp(base); if (!root) return 1;
    std::string root_s(root), source = root_s + "/source", runtime = root_s + "/runtime", parent = runtime + "/data", target = parent + "/state";
    if (mkdir(source.c_str(), 0700) != 0 || mkdir(runtime.c_str(), 0700) != 0 || mkdir(parent.c_str(), 0700) != 0) return 2;
    int rc = ake_mount_volume(source.c_str(), target.c_str(), 0);
    if (rc != 0 || !exists(target.c_str())) return 3;
    rc = ake_unmount_volume(target.c_str());
    if (rc != 0 || exists(target.c_str())) return 4;
    rmdir(source.c_str()); rmdir(parent.c_str()); rmdir(runtime.c_str()); rmdir(root);
    std::puts("AKE volume native test: PASS"); return 0;
}
#endif
