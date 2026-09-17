#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

int ake_network_policy_parse_for_test(const char *value, int *mode);

#ifdef __cplusplus
}
#endif

int main(void) {
    const char *values[] = {"host", "deny", "internet", "internet-server", "private-network", "internet-and-private"};
    const int expected[] = {0, 1, 2, 3, 4, 5};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        int mode = -1;
        if (ake_network_policy_parse_for_test(values[i], &mode) != 0 || mode != expected[i]) {
            fprintf(stderr, "network policy failed: %s -> %d\n", values[i], mode);
            return 1;
        }
    }
    int mode = -1;
    if (ake_network_policy_parse_for_test("bogus", &mode) == 0) {
        fprintf(stderr, "invalid network policy was accepted\n");
        return 1;
    }
    puts("AKE network policy tests: PASS");
    return 0;
}
