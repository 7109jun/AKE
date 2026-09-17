#define _POSIX_C_SOURCE 200809L

#include "ake_extract.h"
#include "ake_core.h"

#include <errno.h>
#include <limits.h>
#include <lzma.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#define AKE_MKDIR(path) _mkdir(path)
#define AKE_RMDIR(path) _rmdir(path)
#define AKE_STAT _stat64
#define AKE_STAT_STRUCT struct _stat64
#else
#include <dirent.h>
#include <unistd.h>
#define AKE_MKDIR(path) mkdir((path), 0755)
#define AKE_RMDIR(path) rmdir(path)
#define AKE_STAT stat
#define AKE_STAT_STRUCT struct stat
#endif

#define AKE_MAX_ARCHIVE_SIZE (512u * 1024u * 1024u)
#define AKE_MAX_ENTRIES 100000u
#define AKE_TAR_BLOCK 512u
#define AKE_MAX_PATH 4096u

typedef struct {
    unsigned char *data;
    size_t size;
    size_t capacity;
} byte_buffer;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_set;

static void set_error(char *error, size_t error_size, const char *message) {
    if (!error || error_size == 0) return;
    snprintf(error, error_size, "%s", message ? message : "unknown error");
}

static void set_error_errno(char *error, size_t error_size, const char *prefix) {
    if (!error || error_size == 0) return;
#ifdef _WIN32
    snprintf(error, error_size, "%s (win32=%lu)", prefix, (unsigned long)GetLastError());
#else
    snprintf(error, error_size, "%s: %s", prefix, strerror(errno));
#endif
}

static char *dup_string(const char *s) {
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s) + 1u;
    p = (char *)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static int buffer_reserve(byte_buffer *b, size_t extra) {
    if (extra > AKE_MAX_ARCHIVE_SIZE - b->size) return 0;
    size_t needed = b->size + extra;
    if (needed <= b->capacity) return 1;
    size_t next = b->capacity ? b->capacity : 65536u;
    while (next < needed) {
        if (next > AKE_MAX_ARCHIVE_SIZE / 2u) {
            next = AKE_MAX_ARCHIVE_SIZE;
            break;
        }
        next *= 2u;
    }
    unsigned char *p = (unsigned char *)realloc(b->data, next);
    if (!p) return 0;
    b->data = p;
    b->capacity = next;
    return 1;
}

static void buffer_free(byte_buffer *b) {
    free(b->data);
    memset(b, 0, sizeof(*b));
}

static int read_xz(const char *path, byte_buffer *out, char *error, size_t error_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        set_error_errno(error, error_size, "cannot open package");
        return 0;
    }

    unsigned char magic[6];
    if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) ||
        memcmp(magic, "\xFD" "7zXZ\x00", 6) != 0) {
        fclose(fp);
        set_error(error, error_size, "AKE payload is not XZ-compressed");
        return 0;
    }
    rewind(fp);

    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret rc = lzma_stream_decoder(&stream, UINT64_MAX, LZMA_CONCATENATED);
    if (rc != LZMA_OK) {
        fclose(fp);
        set_error(error, error_size, "failed to initialize XZ decoder");
        return 0;
    }

    unsigned char inbuf[65536];
    unsigned char outbuf[65536];
    size_t produced_total = 0;
    stream.next_in = NULL;
    stream.avail_in = 0;
    int eof = 0;
    int ok = 1;

    for (;;) {
        if (stream.avail_in == 0 && !eof) {
            size_t got = fread(inbuf, 1, sizeof(inbuf), fp);
            if (got < sizeof(inbuf)) {
                if (ferror(fp)) {
                    set_error(error, error_size, "failed reading package");
                    ok = 0;
                    break;
                }
                eof = 1;
            }
            stream.next_in = inbuf;
            stream.avail_in = got;
        }

        stream.next_out = outbuf;
        stream.avail_out = sizeof(outbuf);
        rc = lzma_code(&stream, eof ? LZMA_FINISH : LZMA_RUN);
        size_t produced = sizeof(outbuf) - stream.avail_out;
        if (produced) {
            if (!buffer_reserve(out, produced)) {
                set_error(error, error_size, "decompressed package exceeds 512 MiB limit");
                ok = 0;
                break;
            }
            memcpy(out->data + out->size, outbuf, produced);
            out->size += produced;
            produced_total += produced;
            (void)produced_total;
        }

        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) {
            set_error(error, error_size, "invalid XZ stream");
            ok = 0;
            break;
        }
        if (eof && stream.avail_in == 0 && produced == 0) {
            set_error(error, error_size, "truncated XZ stream");
            ok = 0;
            break;
        }
    }

    lzma_end(&stream);
    fclose(fp);
    return ok;
}

static int is_zero_block(const unsigned char *block) {
    size_t i;
    for (i = 0; i < AKE_TAR_BLOCK; ++i) if (block[i] != 0) return 0;
    return 1;
}

static size_t field_len(const unsigned char *field, size_t size) {
    size_t n = 0;
    while (n < size && field[n] != 0) n++;
    while (n > 0 && field[n - 1] == ' ') n--;
    return n;
}

static int parse_octal(const unsigned char *field, size_t size, uint64_t *value) {
    size_t i = 0;
    uint64_t result = 0;
    int saw_digit = 0;
    while (i < size && (field[i] == ' ' || field[i] == '\0')) i++;
    for (; i < size && field[i] != '\0'; ++i) {
        unsigned char c = field[i];
        if (c == ' ') break;
        if (c < '0' || c > '7') return 0;
        saw_digit = 1;
        if (result > (UINT64_MAX >> 3u)) return 0;
        result = (result << 3u) + (uint64_t)(c - '0');
    }
    if (!saw_digit) return 0;
    *value = result;
    return 1;
}

static int tar_path(const unsigned char *header, char *out, size_t out_size) {
    size_t name_len = field_len(header, 100u);
    size_t prefix_len = field_len(header + 345u, 155u);
    if (name_len == 0) return 0;
    if (prefix_len) {
        int n = snprintf(out, out_size, "%.*s/%.*s", (int)prefix_len,
                         (const char *)(header + 345u), (int)name_len,
                         (const char *)header);
        return n >= 0 && (size_t)n < out_size;
    }
    if (name_len + 1u > out_size) return 0;
    memcpy(out, header, name_len);
    out[name_len] = '\0';
    return 1;
}

static int tar_checksum_valid(const unsigned char *header) {
    uint64_t stored = 0;
    if (!parse_octal(header + 148u, 8u, &stored)) return 0;
    uint64_t sum = 0;
    size_t i;
    for (i = 0; i < AKE_TAR_BLOCK; ++i) {
        if (i >= 148u && i < 156u) sum += (uint64_t)' ';
        else sum += header[i];
    }
    return sum == stored;
}

static int string_set_add(string_set *set, const char *value) {
    size_t i;
    for (i = 0; i < set->count; ++i) {
        if (strcmp(set->items[i], value) == 0) return 0;
    }
    if (set->count >= AKE_MAX_ENTRIES) return -1;
    if (set->count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2u : 128u;
        if (next > AKE_MAX_ENTRIES) next = AKE_MAX_ENTRIES;
        char **p = (char **)realloc(set->items, next * sizeof(*p));
        if (!p) return -1;
        set->items = p;
        set->capacity = next;
    }
    set->items[set->count] = dup_string(value);
    if (!set->items[set->count]) return -1;
    set->count++;
    return 1;
}

static void string_set_free(string_set *set) {
    size_t i;
    for (i = 0; i < set->count; ++i) free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof(*set));
}

static int path_join(const char *root, const char *relative, char *out, size_t out_size) {
    size_t nr = strlen(root);
    size_t np = strlen(relative);
    int n;
    char sep = '/';
    if (nr == 0 || np == 0) return 0;
#ifdef _WIN32
    sep = '\\';
#endif
    if (root[nr - 1u] == '/' || root[nr - 1u] == '\\')
        n = snprintf(out, out_size, "%s%s", root, relative);
    else
        n = snprintf(out, out_size, "%s%c%s", root, sep, relative);
    return n >= 0 && (size_t)n < out_size;
}

static int dir_exists(const char *path) {
    AKE_STAT_STRUCT st;
    return AKE_STAT(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int path_exists(const char *path) {
    AKE_STAT_STRUCT st;
    return AKE_STAT(path, &st) == 0;
}

static int ensure_dir(const char *path, char *error, size_t error_size) {
    if (dir_exists(path)) return 1;
    if (path_exists(path)) {
        set_error(error, error_size, "destination path conflicts with a file");
        return 0;
    }
    if (AKE_MKDIR(path) != 0 && errno != EEXIST) {
        set_error_errno(error, error_size, "cannot create directory");
        return 0;
    }
    return dir_exists(path);
}

static int ensure_parent_dirs(const char *full_path, const char *root,
                              char *error, size_t error_size) {
    char path[AKE_MAX_PATH];
    size_t root_len = strlen(root);
    size_t len = strlen(full_path);
    size_t i;
    if (len >= sizeof(path)) {
        set_error(error, error_size, "destination path is too long");
        return 0;
    }
    memcpy(path, full_path, len + 1u);
    for (i = len; i > root_len; --i) {
        if (path[i - 1u] == '/' || path[i - 1u] == '\\') {
            path[i - 1u] = '\0';
            break;
        }
    }
    if (strlen(path) <= root_len) return 1;

    /* Build missing components from root outward. */
    size_t start = root_len;
    while (start < strlen(path) && (path[start] == '/' || path[start] == '\\')) start++;
    for (i = start; i < strlen(path); ++i) {
        if (path[i] != '/' && path[i] != '\\') continue;
        char saved = path[i];
        path[i] = '\0';
        if (!ensure_dir(path, error, error_size)) return 0;
        path[i] = saved;
    }
    return ensure_dir(path, error, error_size);
}

static int write_file(const char *path, const unsigned char *data, uint64_t size,
                      char *error, size_t error_size) {
    FILE *fp;
    uint64_t left = size;
    if (path_exists(path)) {
        set_error(error, error_size, "archive path already exists in destination");
        return 0;
    }
    fp = fopen(path, "wb");
    if (!fp) {
        set_error_errno(error, error_size, "cannot create extracted file");
        return 0;
    }
    while (left) {
        size_t chunk = (left > 65536u) ? 65536u : (size_t)left;
        if (fwrite(data, 1, chunk, fp) != chunk) {
            fclose(fp);
            set_error_errno(error, error_size, "failed writing extracted file");
            return 0;
        }
        data += chunk;
        left -= chunk;
    }
    if (fclose(fp) != 0) {
        set_error_errno(error, error_size, "failed closing extracted file");
        return 0;
    }
    return 1;
}

#ifndef _WIN32
static int remove_tree(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    struct dirent *ent;
    int ok = 1;
    while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char child[AKE_MAX_PATH];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) { ok = 0; break; }
        AKE_STAT_STRUCT st;
        if (AKE_STAT(child, &st) != 0) { ok = 0; break; }
        if (S_ISDIR(st.st_mode)) {
            if (!remove_tree(child)) { ok = 0; break; }
        } else if (remove(child) != 0) {
            ok = 0; break;
        }
    }
    closedir(dir);
    if (ok && AKE_RMDIR(path) != 0) ok = 0;
    return ok;
}
#else
static int remove_tree(const char *path) {
    WIN32_FIND_DATAA data;
    char pattern[AKE_MAX_PATH];
    int n = snprintf(pattern, sizeof(pattern), "%s\\*", path);
    if (n < 0 || (size_t)n >= sizeof(pattern)) return 0;
    HANDLE h = FindFirstFileA(pattern, &data);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int ok = 1;
    do {
        if (!strcmp(data.cFileName, ".") || !strcmp(data.cFileName, "..")) continue;
        char child[AKE_MAX_PATH];
        n = snprintf(child, sizeof(child), "%s\\%s", path, data.cFileName);
        if (n < 0 || (size_t)n >= sizeof(child)) { ok = 0; break; }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!remove_tree(child)) { ok = 0; break; }
        } else if (!DeleteFileA(child)) {
            ok = 0; break;
        }
    } while (FindNextFileA(h, &data));
    FindClose(h);
    if (!ok) return 0;
    return RemoveDirectoryA(path) ? 1 : 0;
}
#endif

int ake_extract_package(const char *package_path, const char *destination,
                        char *error, size_t error_size) {
    byte_buffer archive = {0};
    string_set names = {0};
    size_t pos = 0;
    size_t entries = 0;
    int zero_blocks = 0;
    int created_destination = 0;
    int ok = 0;

    if (error && error_size) error[0] = '\0';
    if (!package_path || !*package_path || !destination || !*destination) {
        set_error(error, error_size, "package and destination are required");
        return 1;
    }
    if (ake_validate_package(package_path, error, error_size) != 0) return 2;
    if (strlen(destination) >= AKE_MAX_PATH) {
        set_error(error, error_size, "destination path is too long");
        return 3;
    }

    if (path_exists(destination)) {
        if (!dir_exists(destination)) {
            set_error(error, error_size, "destination already exists and is not a directory");
            return 4;
        }
        /* Requiring an empty directory prevents pre-existing junctions/symlinks
           or unrelated files from becoming extraction targets. */
        set_error(error, error_size, "destination directory must not already exist");
        return 4;
    }

    if (!ensure_dir(destination, error, error_size)) return 5;
    created_destination = 1;

    if (!read_xz(package_path, &archive, error, error_size)) goto fail;

    while (pos + AKE_TAR_BLOCK <= archive.size) {
        const unsigned char *header = archive.data + pos;
        char name[512];
        uint64_t file_size = 0;
        size_t data_pos;
        size_t padded;
        unsigned char type;
        char target[AKE_MAX_PATH];

        if (is_zero_block(header)) {
            zero_blocks++;
            pos += AKE_TAR_BLOCK;
            if (zero_blocks == 2) break;
            continue;
        }
        zero_blocks = 0;
        if (!tar_checksum_valid(header)) {
            set_error(error, error_size, "invalid TAR header checksum");
            goto fail;
        }
        if (!tar_path(header, name, sizeof(name)) || !ake_is_safe_relative_path(name)) {
            set_error(error, error_size, "archive contains an unsafe path");
            goto fail;
        }
        if (entries++ >= AKE_MAX_ENTRIES) {
            set_error(error, error_size, "too many archive entries");
            goto fail;
        }
        if (string_set_add(&names, name) != 1) {
            set_error(error, error_size, "archive contains duplicate paths");
            goto fail;
        }
        type = header[156];
        if (!parse_octal(header + 124u, 12u, &file_size)) {
            set_error(error, error_size, "invalid TAR file size");
            goto fail;
        }
        if (file_size > archive.size - pos - AKE_TAR_BLOCK) {
            set_error(error, error_size, "truncated TAR entry");
            goto fail;
        }
        data_pos = pos + AKE_TAR_BLOCK;
        if (file_size > SIZE_MAX - 511u) {
            set_error(error, error_size, "TAR entry size overflow");
            goto fail;
        }
        padded = (size_t)((file_size + 511u) & ~((uint64_t)511u));
        if (padded > archive.size - data_pos) {
            set_error(error, error_size, "truncated TAR entry padding");
            goto fail;
        }
        if (!path_join(destination, name, target, sizeof(target))) {
            set_error(error, error_size, "destination path is too long");
            goto fail;
        }

        if (type == '5') {
            if (file_size != 0) {
                set_error(error, error_size, "directory TAR entry has non-zero size");
                goto fail;
            }
            if (!ensure_parent_dirs(target, destination, error, error_size)) goto fail;
            if (!ensure_dir(target, error, error_size)) goto fail;
        } else if (type == 0 || type == '0') {
            if (!ensure_parent_dirs(target, destination, error, error_size)) goto fail;
            if (!write_file(target, archive.data + data_pos, file_size, error, error_size)) goto fail;
        } else {
            set_error(error, error_size, "only regular files and directories are allowed");
            goto fail;
        }
        pos = data_pos + padded;
    }

    if (zero_blocks < 2) {
        set_error(error, error_size, "TAR end-of-archive marker is missing");
        goto fail;
    }

    /* There must be no non-zero trailing bytes after the TAR terminator. */
    while (pos < archive.size) {
        if (archive.data[pos++] != 0) {
            set_error(error, error_size, "non-zero data after TAR end marker");
            goto fail;
        }
    }

    ok = 1;
    goto done;

fail:
    if (created_destination) (void)remove_tree(destination);

done:
    string_set_free(&names);
    buffer_free(&archive);
    return ok ? 0 : 6;
}
