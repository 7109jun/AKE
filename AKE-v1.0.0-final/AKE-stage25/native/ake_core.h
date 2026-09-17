#ifndef AKE_CORE_H
#define AKE_CORE_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

int ake_has_valid_extension(const char *path);
int ake_is_safe_relative_path(const char *path);
int ake_validate_package_path(const char *path, char *error, size_t error_size);
int ake_validate_package(const char *path, char *error, size_t error_size);
int ake_package_info(const char *path, char *out, size_t out_size);
int ake_package_dependencies(const char *path, char *out, size_t out_size);
const char *ake_core_version(void);

#ifdef __cplusplus
}
#endif

#endif
