#ifndef AKE_SERVICE_H
#define AKE_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int ake_service_install(const char *name,const char *display_name,const char *description,const char *binary_path,int start_mode,int account_mode,int restart_mode,uint32_t restart_retries,uint32_t restart_delay_ms,uint32_t restart_backoff,uint32_t restart_reset_sec,char *error,size_t error_size);
int ake_service_delete(const char *name,char *error,size_t error_size);
int ake_service_start(const char *name,char *error,size_t error_size);
int ake_service_stop(const char *name,char *error,size_t error_size);
int ake_service_query(const char *name,char *state,size_t state_size,uint32_t *pid,char *error,size_t error_size);
int ake_service_host(const char *service_name,const char *program,const char *arguments,const char *working_directory,const unsigned char *environment_block_utf8,size_t environment_size,const char *container_name,int filesystem_mode,int process_mode,int network_mode,int identity_mode,uint64_t memory_limit_bytes,uint32_t cpu_rate_percent_x100,uint32_t active_process_limit,uint64_t process_user_time_100ns,const char *job_name,int restart_mode);
#ifdef __cplusplus
}
#endif
#endif
