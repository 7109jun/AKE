#ifndef AKE_VOLUME_H
#define AKE_VOLUME_H

#ifdef __cplusplus
extern "C" {
#endif

/* Mounts a host directory at target. mode is 0=rw, 1=ro policy hint. */
int ake_mount_volume(const char *source, const char *target, int read_only);
int ake_unmount_volume(const char *target);

#ifdef __cplusplus
}
#endif

#endif
