#ifndef AKE_ISOLATION_H
#define AKE_ISOLATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* filesystem_mode: 0=package policy, 1=AppContainer, 2=host */
/* process_mode:    0=job-contained children, 1=normal host process */
int ake_spawn_isolated_process(
    const char *program,
    const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8,
    size_t environment_size,
    const char *container_name,
    int filesystem_mode,
    int process_mode,
    int network_mode,
    int identity_mode,
    uint64_t memory_limit_bytes,
    uint32_t cpu_rate_percent_x100,
    uint32_t active_process_limit,
    uint64_t process_user_time_100ns,
    int *exit_code);

#ifdef __cplusplus
}
#endif

#endif
