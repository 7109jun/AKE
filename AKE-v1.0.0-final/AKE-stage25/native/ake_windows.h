#ifndef AKE_WINDOWS_H
#define AKE_WINDOWS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *ake_platform_name(void);
int ake_spawn_process(const char *program, const char *arguments);
int ake_spawn_process_in_directory(const char *program, const char *arguments,
                                   const char *working_directory, int *exit_code);
int ake_http_download(const char *url, const char *destination, char *error, size_t error_size);
int ake_registry_set_classes(const char *key, const char *value_name, const char *value_data, char *error, size_t error_size);
int ake_registry_query_classes(const char *key, const char *value_name, char *out, size_t out_size);
int ake_registry_delete_classes(const char *key, const char *value_name, char *error, size_t error_size);
int ake_registry_delete_tree_classes(const char *key, char *error, size_t error_size);
int ake_create_shortcut(const char *kind, const char *name, const char *target, const char *arguments, const char *working_directory, char *error, size_t error_size);
int ake_remove_shortcut(const char *kind, const char *name, char *error, size_t error_size);
int ake_spawn_process_in_directory_with_environment(
    const char *program,
    const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8,
    size_t environment_size,
    int *exit_code);

#ifdef __cplusplus
}
#endif

#endif
