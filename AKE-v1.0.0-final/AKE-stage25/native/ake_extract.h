#ifndef AKE_EXTRACT_H
#define AKE_EXTRACT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Safely extract an AKE package into a new directory. */
int ake_extract_package(const char *package_path,
                        const char *destination,
                        char *error,
                        size_t error_size);

#ifdef __cplusplus
}
#endif

#endif
