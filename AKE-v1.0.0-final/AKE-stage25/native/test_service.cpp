#include "ake_service.h"
#include <cstdio>
int main(){
    char e[256] = {};
    char state[64] = {};
    unsigned int pid = 0;
    if (ake_service_install("", "", "", "", 0, 0, 1, 5, 5000, 2, 86400, e, sizeof(e)) != 3) { std::fprintf(stderr,"unexpected install stub behavior\n"); return 1; }
    if (ake_service_query("", state, sizeof(state), &pid, e, sizeof(e)) != 3) { std::fprintf(stderr,"unexpected query stub behavior\n"); return 1; }
    if (ake_service_start("",e,sizeof(e)) != 3) return 1;
    if (ake_service_stop("",e,sizeof(e)) != 3) return 1;
    if (ake_service_delete("",e,sizeof(e)) != 3) return 1;
    std::puts("AKE service native ABI test: PASS");
    return 0;
}
