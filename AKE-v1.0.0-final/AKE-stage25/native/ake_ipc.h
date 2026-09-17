#ifndef AKE_IPC_H
#define AKE_IPC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ake_ipc_validate_component(const char *value);
int ake_ipc_build_pipe_name(const char *container_name, const char *channel,
                            char *out, size_t out_size);

/* One-request framed UTF-8 named-pipe exchange. */
int ake_ipc_server_once(const char *pipe_name,
                        const unsigned char *response, size_t response_size,
                        uint32_t timeout_ms);
int ake_ipc_client_call(const char *pipe_name,
                        const unsigned char *request, size_t request_size,
                        unsigned char *response, size_t response_capacity,
                        size_t *response_size, uint32_t timeout_ms);

const char *ake_ipc_version(void);

#ifdef __cplusplus
}
#endif

#endif
