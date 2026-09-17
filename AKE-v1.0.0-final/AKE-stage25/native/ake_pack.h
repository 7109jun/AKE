#ifndef AKE_PACK_H
#define AKE_PACK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Create an AKE package from a directory tree. */
int ake_pack_directory(const char *source_dir,
                       const char *output_path,
                       char *error,
                       size_t error_size);

#ifdef __cplusplus
}
#endif

#endif
