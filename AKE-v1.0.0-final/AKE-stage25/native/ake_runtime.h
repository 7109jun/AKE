#ifndef AKE_RUNTIME_H
#define AKE_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts a tracked, non-blocking AKE process. Returns 0 on success and pid_out is set. */
int ake_spawn_isolated_process_detached(
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
    const char *job_name,
    const char *log_path,
    uint32_t *pid_out);

/* running=1 while active, running=0 after exit; exit_code is valid when stopped. */
int ake_query_process(uint32_t pid, int *running, int *exit_code);

/* Terminates the named AKE job if present, otherwise terminates the PID. */
int ake_terminate_job_or_process(const char *job_name, uint32_t pid);

#ifdef __cplusplus
}
#endif

#endif
