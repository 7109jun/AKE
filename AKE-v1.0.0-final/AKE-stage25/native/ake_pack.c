#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "ake_pack.h"
#include "ake_core.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lzma.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define AKE_MAX_ARCHIVE_SIZE (512u * 1024u * 1024u)
#define AKE_MAX_ENTRIES 100000u
#define AKE_TAR_BLOCK 512u

typedef struct {
    char *source;
    char *archive;
    int is_dir;
    uint64_t size;
} pack_entry;

typedef struct {
    pack_entry *items;
    size_t count;
    size_t capacity;
    uint64_t total_data;
} entry_list;

static void set_error(char *error, size_t error_size, const char *message) {
    if (!error || !error_size) return;
    snprintf(error, error_size, "%s", message ? message : "unknown error");
}

static void set_error_errno(char *error, size_t error_size, const char *prefix) {
    if (!error || !error_size) return;
#ifdef _WIN32
    DWORD code = GetLastError();
    snprintf(error, error_size, "%s (win32=%lu)", prefix, (unsigned long)code);
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

static void entry_list_free(entry_list *list) {
    size_t i;
    if (!list) return;
    for (i = 0; i < list->count; ++i) {
        free(list->items[i].source);
        free(list->items[i].archive);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int compare_entries(const void *a, const void *b) {
    const pack_entry *ea = (const pack_entry *)a;
    const pack_entry *eb = (const pack_entry *)b;
    int cmp = strcmp(ea->archive, eb->archive);
    if (cmp) return cmp;
    return strcmp(ea->source, eb->source);
}

static int add_entry(entry_list *list, const char *source, const char *archive,
                     int is_dir, uint64_t size, char *error, size_t error_size) {
    pack_entry *p;
    if (list->count >= AKE_MAX_ENTRIES) {
        set_error(error, error_size, "source directory has too many entries");
        return 0;
    }
    if (!ake_is_safe_relative_path(archive)) {
        set_error(error, error_size, "source contains an unsafe archive path");
        return 0;
    }
    if (strlen(archive) > 255u) {
        set_error(error, error_size, "archive path exceeds TAR ustar path limit");
        return 0;
    }
    if (!is_dir) {
        if (size > AKE_MAX_ARCHIVE_SIZE || list->total_data > AKE_MAX_ARCHIVE_SIZE - size) {
            set_error(error, error_size, "package data exceeds 512 MiB limit");
            return 0;
        }
        list->total_data += size;
    }
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2u : 128u;
        pack_entry *items;
        if (next > AKE_MAX_ENTRIES) next = AKE_MAX_ENTRIES;
        items = (pack_entry *)realloc(list->items, next * sizeof(*items));
        if (!items) {
            set_error(error, error_size, "out of memory while building package index");
            return 0;
        }
        list->items = items;
        list->capacity = next;
    }
    p = &list->items[list->count];
    p->source = dup_string(source);
    p->archive = dup_string(archive);
    p->is_dir = is_dir;
    p->size = size;
    if (!p->source || !p->archive) {
        free(p->source);
        free(p->archive);
        p->source = NULL;
        p->archive = NULL;
        set_error(error, error_size, "out of memory while storing package entry");
        return 0;
    }
    list->count++;
    return 1;
}

static int join_path(const char *a, const char *b, char **out) {
    size_t na = strlen(a);
    size_t nb = strlen(b);
    size_t extra = (na && a[na - 1u] != '/' && a[na - 1u] != '\\') ? 1u : 0u;
    char *p = (char *)malloc(na + extra + nb + 1u);
    if (!p) return 0;
    memcpy(p, a, na);
    if (extra) {
#ifdef _WIN32
        p[na] = '\\';
#else
        p[na] = '/';
#endif
    }
    memcpy(p + na + extra, b, nb);
    p[na + extra + nb] = '\0';
    *out = p;
    return 1;
}

static char *archive_child(const char *base, const char *name) {
    size_t nb = strlen(base);
    size_t nn = strlen(name);
    size_t extra = nb ? 1u : 0u;
    char *p = (char *)malloc(nb + extra + nn + 1u);
    size_t i;
    if (!p) return NULL;
    memcpy(p, base, nb);
    if (extra) p[nb] = '/';
    memcpy(p + nb + extra, name, nn);
    p[nb + extra + nn] = '\0';
    for (i = 0; i < nb + extra + nn; ++i) if (p[i] == '\\') p[i] = '/';
    return p;
}

#ifdef _WIN32
static int collect_dir(entry_list *list, const char *source_dir, const char *archive_dir,
                       char *error, size_t error_size) {
    char *pattern = NULL;
    WIN32_FIND_DATAA data;
    HANDLE h;
    DWORD attrs;
    int ok = 1;

    attrs = GetFileAttributesA(source_dir);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        set_error_errno(error, error_size, "cannot stat source directory");
        return 0;
    }
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        set_error(error, error_size, "source path is not a directory");
        return 0;
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        set_error(error, error_size, "source directory is a reparse point");
        return 0;
    }

    pattern = (char *)malloc(strlen(source_dir) + 4u);
    if (!pattern) { set_error(error, error_size, "out of memory"); return 0; }
    strcpy(pattern, source_dir);
    {
        size_t n = strlen(pattern);
        if (n && pattern[n - 1u] != '\\' && pattern[n - 1u] != '/') pattern[n++] = '\\';
        pattern[n++] = '*';
        pattern[n] = '\0';
    }
    h = FindFirstFileA(pattern, &data);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE) {
        set_error_errno(error, error_size, "cannot enumerate source directory");
        return 0;
    }

    do {
        char *child_source = NULL;
        char *child_archive = NULL;
        DWORD a = data.dwFileAttributes;
        uint64_t size = ((uint64_t)data.nFileSizeHigh << 32u) | (uint64_t)data.nFileSizeLow;
        if (!strcmp(data.cFileName, ".") || !strcmp(data.cFileName, "..")) continue;
        if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
            set_error(error, error_size, "source contains a reparse point/symlink");
            ok = 0;
            break;
        }
        if (!join_path(source_dir, data.cFileName, &child_source)) {
            set_error(error, error_size, "out of memory"); ok = 0; break;
        }
        child_archive = archive_child(archive_dir, data.cFileName);
        if (!child_archive) {
            free(child_source); set_error(error, error_size, "out of memory"); ok = 0; break;
        }
        if (a & FILE_ATTRIBUTE_DIRECTORY) {
            if (!add_entry(list, child_source, child_archive, 1, 0, error, error_size) ||
                !collect_dir(list, child_source, child_archive, error, error_size)) {
                ok = 0;
            }
        } else {
            if (!add_entry(list, child_source, child_archive, 0, size, error, error_size)) ok = 0;
        }
        free(child_source);
        free(child_archive);
    } while (ok && FindNextFileA(h, &data));

    if (ok && GetLastError() != ERROR_NO_MORE_FILES) {
        set_error_errno(error, error_size, "failed while enumerating source directory");
        ok = 0;
    }
    FindClose(h);
    return ok;
}
#else
static int collect_dir(entry_list *list, const char *source_dir, const char *archive_dir,
                       char *error, size_t error_size) {
    DIR *dir;
    struct dirent *ent;
    struct stat st;
    int ok = 1;

    if (lstat(source_dir, &st) != 0) {
        set_error_errno(error, error_size, "cannot stat source directory");
        return 0;
    }
    if (!S_ISDIR(st.st_mode)) {
        set_error(error, error_size, "source path is not a directory");
        return 0;
    }

    dir = opendir(source_dir);
    if (!dir) {
        set_error_errno(error, error_size, "cannot open source directory");
        return 0;
    }
    while (ok && (ent = readdir(dir)) != NULL) {
        char *child_source = NULL;
        char *child_archive = NULL;
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        if (!join_path(source_dir, ent->d_name, &child_source)) {
            set_error(error, error_size, "out of memory"); ok = 0; break;
        }
        if (lstat(child_source, &st) != 0) {
            free(child_source); set_error_errno(error, error_size, "cannot stat source entry"); ok = 0; break;
        }
        if (S_ISLNK(st.st_mode)) {
            free(child_source); set_error(error, error_size, "source contains a symlink"); ok = 0; break;
        }
        child_archive = archive_child(archive_dir, ent->d_name);
        if (!child_archive) {
            free(child_source); set_error(error, error_size, "out of memory"); ok = 0; break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!add_entry(list, child_source, child_archive, 1, 0, error, error_size) ||
                !collect_dir(list, child_source, child_archive, error, error_size)) ok = 0;
        } else if (S_ISREG(st.st_mode)) {
            if (!add_entry(list, child_source, child_archive, 0, (uint64_t)st.st_size, error, error_size)) ok = 0;
        } else {
            set_error(error, error_size, "source contains an unsupported file type");
            ok = 0;
        }
        free(child_source);
        free(child_archive);
    }
    closedir(dir);
    return ok;
}
#endif

static uint64_t tar_checksum(const unsigned char *header) {
    uint64_t sum = 0;
    size_t i;
    for (i = 0; i < AKE_TAR_BLOCK; ++i) {
        if (i >= 148u && i < 156u) sum += (unsigned char)' ';
        else sum += header[i];
    }
    return sum;
}

static int write_octal(unsigned char *dst, size_t width, uint64_t value) {
    char tmp[32];
    size_t digits = 0;
    size_t i;
    if (width < 2u) return 0;
    do {
        tmp[digits++] = (char)('0' + (value & 7u));
        value >>= 3u;
    } while (value && digits < sizeof(tmp));
    if (value) return 0;
    if (digits + 2u > width) return 0;
    memset(dst, '0', width);
    dst[width - 2u] = '\0';
    for (i = 0; i < digits; ++i) dst[width - 2u - i - 1u] = (unsigned char)tmp[i];
    dst[width - 1u] = ' ';
    return 1;
}

static int split_tar_name(const char *name, unsigned char *header) {
    size_t n = strlen(name);
    const char *slash;
    if (n == 0 || n > 255u) return 0;
    memset(header, 0, AKE_TAR_BLOCK);
    if (n <= 100u) {
        memcpy(header, name, n);
        return 1;
    }
    slash = strrchr(name, '/');
    if (!slash) return 0;
    if ((size_t)(slash - name) > 155u) return 0;
    if (strlen(slash + 1) > 100u) return 0;
    memcpy(header + 345u, name, (size_t)(slash - name));
    memcpy(header, slash + 1, strlen(slash + 1));
    return 1;
}

static int write_tar_header(FILE *fp, const pack_entry *entry) {
    unsigned char h[AKE_TAR_BLOCK];
    uint64_t checksum;
    memset(h, 0, sizeof(h));
    if (!split_tar_name(entry->archive, h)) return 0;
    memcpy(h + 100u, "0000644\0", 8u);
    memcpy(h + 108u, "0000000\0", 8u);
    memcpy(h + 116u, "0000000\0", 8u);
    if (!write_octal(h + 124u, 12u, entry->is_dir ? 0u : entry->size)) return 0;
    if (!write_octal(h + 136u, 12u, 0u)) return 0;
    h[156] = entry->is_dir ? '5' : '0';
    memcpy(h + 257u, "ustar\0", 6u);
    memcpy(h + 263u, "00", 2u);
    memcpy(h + 265u, "ake", 3u);
    checksum = tar_checksum(h);
    /* POSIX TAR checksum is six octal digits, NUL, then space. */
    if (checksum > 0777777u) return 0;
    if (snprintf((char *)(h + 148u), 8u, "%06o ", (unsigned int)checksum) != 7) return 0;
    return fwrite(h, 1, sizeof(h), fp) == sizeof(h);
}

static int write_padding(FILE *fp, uint64_t size) {
    unsigned char zeros[AKE_TAR_BLOCK] = {0};
    size_t pad = (size_t)((AKE_TAR_BLOCK - (size % AKE_TAR_BLOCK)) % AKE_TAR_BLOCK);
    if (!pad) return 1;
    return fwrite(zeros, 1, pad, fp) == pad;
}

static int copy_file(FILE *out, const char *source, uint64_t size, uint64_t *written,
                     char *error, size_t error_size) {
    FILE *in = fopen(source, "rb");
    unsigned char buf[65536];
    uint64_t remaining = size;
    if (!in) {
        set_error_errno(error, error_size, "cannot open source file");
        return 0;
    }
    while (remaining) {
        size_t want = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        size_t got = fread(buf, 1, want, in);
        if (got != want) {
            fclose(in); set_error_errno(error, error_size, "failed reading source file"); return 0;
        }
        if (fwrite(buf, 1, got, out) != got) {
            fclose(in); set_error_errno(error, error_size, "failed writing TAR archive"); return 0;
        }
        remaining -= got;
        *written += got;
    }
    fclose(in);
    return 1;
}

static int write_tar(const entry_list *list, const char *tar_path, char *error, size_t error_size) {
    FILE *fp = fopen(tar_path, "wb");
    unsigned char zero[AKE_TAR_BLOCK] = {0};
    size_t i;
    uint64_t written = 0;
    if (!fp) { set_error_errno(error, error_size, "cannot create temporary TAR"); return 0; }

    for (i = 0; i < list->count; ++i) {
        const pack_entry *e = &list->items[i];
        if (!write_tar_header(fp, e)) {
            fclose(fp); set_error(error, error_size, "failed writing TAR header"); return 0;
        }
        written += AKE_TAR_BLOCK;
        if (!e->is_dir) {
            if (!copy_file(fp, e->source, e->size, &written, error, error_size) ||
                !write_padding(fp, e->size)) {
                fclose(fp); if (!error || !*error) set_error(error, error_size, "failed writing TAR payload"); return 0;
            }
            written += (uint64_t)((AKE_TAR_BLOCK - (e->size % AKE_TAR_BLOCK)) % AKE_TAR_BLOCK);
        }
        if (written > AKE_MAX_ARCHIVE_SIZE + (uint64_t)list->count * AKE_TAR_BLOCK + 1024u * 1024u) {
            fclose(fp); set_error(error, error_size, "TAR archive exceeds size limit"); return 0;
        }
    }
    if (fwrite(zero, 1, sizeof(zero), fp) != sizeof(zero) ||
        fwrite(zero, 1, sizeof(zero), fp) != sizeof(zero)) {
        fclose(fp); set_error(error, error_size, "failed writing TAR terminator"); return 0;
    }
    fclose(fp);
    return 1;
}

static int compress_xz(const char *tar_path, const char *output_path, char *error, size_t error_size) {
    FILE *in = fopen(tar_path, "rb");
    FILE *out = NULL;
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret rc;
    unsigned char inbuf[65536];
    unsigned char outbuf[65536];
    int eof = 0;
    int ok = 1;

    if (!in) { set_error_errno(error, error_size, "cannot open temporary TAR"); return 0; }
    out = fopen(output_path, "wb");
    if (!out) {
        fclose(in); set_error_errno(error, error_size, "cannot create AKE output"); return 0;
    }
    rc = lzma_easy_encoder(&strm, 6, LZMA_CHECK_CRC64);
    if (rc != LZMA_OK) {
        fclose(in); fclose(out); set_error(error, error_size, "failed to initialize XZ encoder"); return 0;
    }

    strm.next_in = NULL;
    strm.avail_in = 0;
    while (1) {
        if (strm.avail_in == 0 && !eof) {
            size_t got = fread(inbuf, 1, sizeof(inbuf), in);
            if (got < sizeof(inbuf)) {
                if (ferror(in)) { set_error_errno(error, error_size, "failed reading temporary TAR"); ok = 0; break; }
                eof = 1;
            }
            strm.next_in = inbuf;
            strm.avail_in = got;
        }
        strm.next_out = outbuf;
        strm.avail_out = sizeof(outbuf);
        rc = lzma_code(&strm, eof ? LZMA_FINISH : LZMA_RUN);
        {
            size_t produced = sizeof(outbuf) - strm.avail_out;
            if (produced && fwrite(outbuf, 1, produced, out) != produced) {
                set_error_errno(error, error_size, "failed writing XZ output"); ok = 0; break;
            }
        }
        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) {
            set_error(error, error_size, "XZ compression failed"); ok = 0; break;
        }
    }
    lzma_end(&strm);
    fclose(in);
    if (fclose(out) != 0) {
        set_error_errno(error, error_size, "failed closing AKE output"); ok = 0;
    }
    return ok;
}

static int has_extension_ake(const char *path) {
    return ake_has_valid_extension(path);
}

static int has_required_source_dirs(const char *source_dir, char *error, size_t error_size) {
    const char *names[] = {"bin", "config", "lib", "metadata"};
    size_t i;
    for (i = 0; i < 4u; ++i) {
        char *p = NULL;
#ifndef _WIN32
        struct stat st;
#endif
        if (!join_path(source_dir, names[i], &p)) {
            set_error(error, error_size, "out of memory"); return 0;
        }
#ifdef _WIN32
        DWORD attrs = GetFileAttributesA(p);
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY) || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
#else
        if (lstat(p, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
#endif
            free(p);
            set_error(error, error_size, "required directory missing from source: one of bin/config/lib/metadata");
            return 0;
        }
        free(p);
    }
    return 1;
}

static int validate_source_metadata_exists(const char *source_dir, char *error, size_t error_size) {
#ifndef _WIN32
    struct stat st;
#endif
    {
        char *meta_dir = NULL;
        char *meta_file = NULL;
        if (!join_path(source_dir, "metadata", &meta_dir) || !join_path(meta_dir, "package.ake", &meta_file)) {
            free(meta_dir);
            free(meta_file);
            set_error(error, error_size, "out of memory");
            return 0;
        }
#ifdef _WIN32
        {
            DWORD attrs = GetFileAttributesA(meta_file);
            if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                free(meta_dir); free(meta_file); set_error(error, error_size, "metadata/package.ake is missing from source"); return 0;
            }
        }
#else
        if (lstat(meta_file, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            free(meta_dir); free(meta_file); set_error(error, error_size, "metadata/package.ake is missing from source"); return 0;
        }
#endif
        free(meta_dir);
        free(meta_file);
    }
    return 1;
}

static int make_temp_tar_path(const char *output, char **out) {
    size_t n = strlen(output);
    char *p = (char *)malloc(n + 10u);
    if (!p) return 0;
    snprintf(p, n + 10u, "%s.tmp.tar", output);
    *out = p;
    return 1;
}

static void remove_file(const char *path) {
    if (path) remove(path);
}

int ake_pack_directory(const char *source_dir, const char *output_path,
                       char *error, size_t error_size) {
    entry_list list = {0};
    char *temp_tar = NULL;
    char *root_archive = NULL;
    int rc = 0;
    size_t i;

    if (error && error_size) error[0] = '\0';
    if (!source_dir || !*source_dir || !output_path || !*output_path) {
        set_error(error, error_size, "source directory and output package are required");
        return 1;
    }
    if (!has_extension_ake(output_path)) {
        set_error(error, error_size, "output package extension must be .ake");
        return 2;
    }
    if (!has_required_source_dirs(source_dir, error, error_size)) return 3;
    if (!validate_source_metadata_exists(source_dir, error, error_size)) return 3;

    if (!make_temp_tar_path(output_path, &temp_tar)) {
        set_error(error, error_size, "out of memory");
        return 4;
    }
    root_archive = dup_string("");
    if (!root_archive) {
        free(temp_tar); set_error(error, error_size, "out of memory"); return 4;
    }
    if (!collect_dir(&list, source_dir, root_archive, error, error_size)) {
        entry_list_free(&list); free(root_archive); free(temp_tar); return 5;
    }
    qsort(list.items, list.count, sizeof(list.items[0]), compare_entries);

    /* The validator limits the decompressed TAR stream to 512 MiB, so account
       for every header, padded payload and the two terminating blocks too. */
    {
        uint64_t estimated_tar = 1024u;
        for (i = 0; i < list.count; ++i) {
            uint64_t padded = (list.items[i].size + 511u) & ~((uint64_t)511u);
            if (estimated_tar > UINT64_MAX - 512u - padded) {
                set_error(error, error_size, "TAR size calculation overflow");
                entry_list_free(&list); free(root_archive); free(temp_tar); return 6;
            }
            estimated_tar += 512u + (list.items[i].is_dir ? 0u : padded);
            if (estimated_tar > AKE_MAX_ARCHIVE_SIZE) {
                set_error(error, error_size, "TAR archive exceeds 512 MiB decompressed limit");
                entry_list_free(&list); free(root_archive); free(temp_tar); return 6;
            }
        }
    }

    /* Basic invariant checks before writing. */
    for (i = 0; i < list.count; ++i) {
        if (!strcmp(list.items[i].archive, "metadata/package.ake")) {
            if (list.items[i].is_dir || list.items[i].size == 0 || list.items[i].size > 64u * 1024u) {
                set_error(error, error_size, "metadata/package.ake must be a non-empty file <= 64 KiB");
                entry_list_free(&list); free(root_archive); free(temp_tar); return 6;
            }
        }
    }

    remove_file(temp_tar);
    if (!write_tar(&list, temp_tar, error, error_size) ||
        !compress_xz(temp_tar, output_path, error, error_size)) {
        remove_file(temp_tar);
        remove_file(output_path);
        entry_list_free(&list); free(root_archive); free(temp_tar); return 7;
    }
    remove_file(temp_tar);

    /* Every package produced by the packer must pass the normal reader. */
    {
        char verify_error[512];
        if (ake_validate_package(output_path, verify_error, sizeof(verify_error)) != 0) {
            set_error(error, error_size, "generated package failed self-validation");
            remove_file(output_path);
            rc = 8;
        }
    }

    entry_list_free(&list);
    free(root_archive);
    free(temp_tar);
    return rc;
}
