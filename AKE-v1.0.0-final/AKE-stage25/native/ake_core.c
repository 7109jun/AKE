#include "ake_core.h"
#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define AKE_MAX_ARCHIVE_SIZE (512u * 1024u * 1024u)
#define AKE_MAX_ENTRIES 100000u
#define AKE_MAX_METADATA (64u * 1024u)

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} byte_buffer;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_set;

static int ascii_ieq(char a, char b) {
    if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
    if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
    return a == b;
}

static void set_error(char *error, size_t error_size, const char *message) {
    if (!error || error_size == 0) return;
    snprintf(error, error_size, "%s", message ? message : "unknown error");
}

static void set_errorf(char *error, size_t error_size, const char *prefix, const char *value) {
    if (!error || error_size == 0) return;
    snprintf(error, error_size, "%s%s", prefix, value ? value : "");
}

static int buffer_reserve(byte_buffer *b, size_t extra) {
    if (extra > AKE_MAX_ARCHIVE_SIZE - b->size) return 0;
    size_t needed = b->size + extra;
    if (needed <= b->capacity) return 1;
    size_t capacity = b->capacity ? b->capacity : 65536u;
    while (capacity < needed) {
        if (capacity > AKE_MAX_ARCHIVE_SIZE / 2u) {
            capacity = AKE_MAX_ARCHIVE_SIZE;
            break;
        }
        capacity *= 2u;
    }
    char *p = (char *)realloc(b->data, capacity);
    if (!p) return 0;
    b->data = p;
    b->capacity = capacity;
    return 1;
}

static void buffer_free(byte_buffer *b) {
    free(b->data);
    memset(b, 0, sizeof(*b));
}

static char *ake_strdup(const char *value) {
    size_t n = strlen(value) + 1u;
    char *p = (char *)malloc(n);
    if (!p) return NULL;
    memcpy(p, value, n);
    return p;
}

static int ake_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb) return (ca < cb) ? -1 : 1;
        ++a; ++b;
    }
    return ((unsigned char)*a > (unsigned char)*b) - ((unsigned char)*a < (unsigned char)*b);
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
    set->items[set->count] = ake_strdup(value);
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

int ake_has_valid_extension(const char *path) {
    if (!path || !*path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return 0;
    const char *ext = dot + 1;
    return strlen(ext) == 3 && ascii_ieq(ext[0], 'a') && ascii_ieq(ext[1], 'k') && ascii_ieq(ext[2], 'e');
}

int ake_is_safe_relative_path(const char *path) {
    if (!path || !*path) return 0;
    if (path[0] == '/' || path[0] == '\\') return 0;
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':') return 0;

    const char *p = path;
    while (*p) {
        while (*p == '/' || *p == '\\') p++;
        const char *start = p;
        while (*p && *p != '/' && *p != '\\') p++;
        size_t len = (size_t)(p - start);
        if (len == 2 && start[0] == '.' && start[1] == '.') return 0;
        if (len == 0) break;
    }
    return 1;
}

int ake_validate_package_path(const char *path, char *error, size_t error_size) {
    if (error && error_size) error[0] = '\0';
    if (!path || !*path) {
        set_error(error, error_size, "empty package path");
        return 1;
    }
    if (!ake_has_valid_extension(path)) {
        set_error(error, error_size, "package extension must be .ake");
        return 2;
    }
    return 0;
}

static int is_zero_block(const unsigned char *block) {
    size_t i;
    for (i = 0; i < 512u; ++i) if (block[i] != 0) return 0;
    return 1;
}

static size_t field_len(const unsigned char *field, size_t size) {
    size_t n = 0;
    while (n < size && field[n] != 0) n++;
    while (n > 0 && (field[n - 1] == ' ' || field[n - 1] == '\0')) n--;
    return n;
}

static int parse_octal(const unsigned char *field, size_t size, size_t *value) {
    size_t i = 0;
    size_t result = 0;
    while (i < size && (field[i] == ' ' || field[i] == '\0')) i++;
    if (i == size) { *value = 0; return 1; }
    int saw_digit = 0;
    for (; i < size && field[i] != '\0'; ++i) {
        unsigned char c = field[i];
        if (c == ' ') break;
        if (c < '0' || c > '7') return 0;
        saw_digit = 1;
        if (result > (SIZE_MAX >> 3)) return 0;
        result = (result << 3) + (size_t)(c - '0');
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
        int n = snprintf(out, out_size, "%.*s/%.*s", (int)prefix_len, (const char *)(header + 345u), (int)name_len, (const char *)header);
        return n >= 0 && (size_t)n < out_size;
    }
    if (name_len + 1u > out_size) return 0;
    memcpy(out, header, name_len);
    out[name_len] = '\0';
    return 1;
}

static int read_xz(const char *path, byte_buffer *out, char *error, size_t error_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { set_error(error, error_size, "cannot open package"); return 0; }

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
    stream.next_in = NULL;
    stream.avail_in = 0;
    int eof = 0;
    int ok = 1;

    for (;;) {
        if (stream.avail_in == 0 && !eof) {
            size_t got = fread(inbuf, 1, sizeof(inbuf), fp);
            if (got < sizeof(inbuf)) {
                if (ferror(fp)) { ok = 0; set_error(error, error_size, "failed reading package"); break; }
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
                ok = 0;
                set_error(error, error_size, "decompressed package exceeds 512 MiB limit");
                break;
            }
            memcpy(out->data + out->size, outbuf, produced);
            out->size += produced;
        }

        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) {
            ok = 0;
            set_error(error, error_size, "invalid XZ stream");
            break;
        }
        if (eof && stream.avail_in == 0 && produced == 0) {
            ok = 0;
            set_error(error, error_size, "truncated XZ stream");
            break;
        }
    }

    lzma_end(&stream);
    fclose(fp);
    return ok;
}

static int metadata_get(const char *text, const char *wanted, char *out, size_t out_size) {
    char line[4096];
    const char *p = text;
    while (*p) {
        const char *end = strchr(p, '\n');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        while (len && (p[len - 1] == '\r' || p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
        size_t start = 0;
        while (start < len && (p[start] == ' ' || p[start] == '\t')) start++;
        if (len - start >= sizeof(line)) return -1;
        memcpy(line, p + start, len - start);
        line[len - start] = '\0';
        if (line[0] && line[0] != '#' && line[0] != ';') {
            char *eq = strchr(line, '=');
            if (!eq) return -2;
            *eq = '\0';
            char *key = line;
            char *value = eq + 1;
            while (*key == ' ' || *key == '\t') key++;
            char *key_end = key + strlen(key);
            while (key_end > key && (key_end[-1] == ' ' || key_end[-1] == '\t')) *--key_end = '\0';
            while (*value == ' ' || *value == '\t') value++;
            if (ake_stricmp(key, wanted) == 0) {
                if (strlen(value) + 1u > out_size) return -3;
                strcpy(out, value);
                return 1;
            }
        }
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

static int has_required_fields(const char *metadata, char values[7][1024], char *error, size_t error_size) {
    const char *keys[7] = {"name", "id", "version", "publisher", "architecture", "entry", "ake_version"};
    size_t i;
    for (i = 0; i < 7; ++i) {
        int rc = metadata_get(metadata, keys[i], values[i], sizeof(values[i]));
        if (rc != 1) {
            if (rc < 0) set_error(error, error_size, "malformed metadata/package.ake");
            else set_errorf(error, error_size, "missing metadata field: ", keys[i]);
            return 0;
        }
    }
    return 1;
}

static int tar_checksum_valid(const unsigned char *header) {
    size_t stored = 0;
    if (!parse_octal(header + 148u, 8u, &stored)) return 0;
    unsigned long long sum = 0;
    size_t i;
    for (i = 0; i < 512u; ++i) {
        if (i >= 148u && i < 156u) sum += (unsigned long long)' ';
        else sum += (unsigned long long)header[i];
    }
    return sum == stored;
}

static int validate_tar(byte_buffer *archive, char *metadata, size_t metadata_size, char *error, size_t error_size, size_t *entry_count) {
    size_t pos = 0;
    string_set names = {0};
    int zero_blocks = 0;
    int have_bin = 0, have_config = 0, have_lib = 0, have_metadata = 0;
    *entry_count = 0;
    metadata[0] = '\0';

    while (pos + 512u <= archive->size) {
        const unsigned char *h = (const unsigned char *)(archive->data + pos);
        if (is_zero_block(h)) {
            zero_blocks++;
            pos += 512u;
            if (zero_blocks == 2) break;
            continue;
        }
        zero_blocks = 0;
        char name[512];
        if (!tar_path(h, name, sizeof(name))) {
            string_set_free(&names);
            set_error(error, error_size, "invalid TAR path");
            return 0;
        }
        if (strncmp(name, "bin", 3) == 0 && (name[3] == '\0' || name[3] == '/')) have_bin = 1;
        if (strncmp(name, "config", 6) == 0 && (name[6] == '\0' || name[6] == '/')) have_config = 1;
        if (strncmp(name, "lib", 3) == 0 && (name[3] == '\0' || name[3] == '/')) have_lib = 1;
        if (strncmp(name, "metadata", 8) == 0 && (name[8] == '\0' || name[8] == '/')) have_metadata = 1;
        if (!ake_is_safe_relative_path(name)) {
            string_set_free(&names);
            set_error(error, error_size, "archive contains an unsafe path");
            return 0;
        }
        if (!tar_checksum_valid(h)) {
            string_set_free(&names);
            set_error(error, error_size, "invalid TAR header checksum");
            return 0;
        }
        int add_rc = string_set_add(&names, name);
        if (add_rc == 0) {
            string_set_free(&names);
            set_error(error, error_size, "archive contains duplicate paths");
            return 0;
        }
        if (add_rc < 0) {
            string_set_free(&names);
            set_error(error, error_size, "too many archive entries");
            return 0;
        }
        (*entry_count)++;

        unsigned char type = h[156];
        size_t file_size = 0;
        if (!parse_octal(h + 124u, 12u, &file_size)) {
            string_set_free(&names);
            set_error(error, error_size, "invalid TAR file size");
            return 0;
        }
        if (file_size > archive->size - pos - 512u) {
            string_set_free(&names);
            set_error(error, error_size, "truncated TAR entry");
            return 0;
        }
        size_t data_pos = pos + 512u;
        size_t padded = (file_size + 511u) & ~(size_t)511u;
        if (padded > archive->size - data_pos) {
            string_set_free(&names);
            set_error(error, error_size, "truncated TAR entry padding");
            return 0;
        }
        if (type == '5') {
            /* Directory. */
        } else if (type == 0 || type == '\0' || type == '0') {
            if (strcmp(name, "metadata/package.ake") == 0) {
                if (file_size == 0 || file_size >= metadata_size) {
                    string_set_free(&names);
                    set_error(error, error_size, "metadata/package.ake is too large or empty");
                    return 0;
                }
                memcpy(metadata, archive->data + data_pos, file_size);
                metadata[file_size] = '\0';
            }
        } else {
            string_set_free(&names);
            set_error(error, error_size, "only regular files and directories are allowed");
            return 0;
        }

        pos = data_pos + padded;
    }

    int complete = zero_blocks >= 2;
    string_set_free(&names);
    if (!complete) {
        set_error(error, error_size, "TAR end-of-archive marker is missing");
        return 0;
    }
    if (!have_bin || !have_config || !have_lib || !have_metadata) {
        set_error(error, error_size, "required AKE directories are missing");
        return 0;
    }
    return 1;
}


static int is_dependency_id_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

static int valid_dependency_expression(const char *expr) {
    if (!expr || !*expr) return 0;
    const char *p = expr;
    const char *op = NULL;
    int previous_dot = 0;
    if (!((expr[0] >= 'A' && expr[0] <= 'Z') || (expr[0] >= 'a' && expr[0] <= 'z') ||
          (expr[0] >= '0' && expr[0] <= '9'))) return 0;
    while (*p && is_dependency_id_char(*p)) {
        if (*p == '.') {
            if (previous_dot) return 0;
            previous_dot = 1;
        } else {
            previous_dot = 0;
        }
        ++p;
    }
    if (p == expr || p[-1] == '.' || (size_t)(p - expr) > 128u) return 0;
    if (*p == '\0') return 1;
    op = p;
    if (*op == '>' || *op == '<' || *op == '=') {
        if (op[1] == '=') op += 2;
        else op += 1;
    } else {
        return 0;
    }
    if (*op == '\0') return 0;
    size_t n = strlen(op);
    if (n > 128u) return 0;
    size_t dots = 0;
    int have_digit = 0;
    for (size_t i = 0; i < n; ++i) {
        char c = op[i];
        if (c >= '0' && c <= '9') { have_digit = 1; continue; }
        if (c == '.') { ++dots; continue; }
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '+') continue;
        return 0;
    }
    return have_digit && dots <= 16u;
}

static int validate_dependencies(const char *metadata, char *error, size_t error_size) {
    const char *p = metadata;
    while (p && *p) {
        const char *line_end = strchr(p, '\n');
        size_t len = line_end ? (size_t)(line_end - p) : strlen(p);
        if (len >= 12u && strncmp(p, "dependency=", 11u) == 0) {
            char dep[258];
            if (len - 11u >= sizeof(dep)) {
                set_error(error, error_size, "dependency expression is too long");
                return 0;
            }
            memcpy(dep, p + 11u, len - 11u);
            dep[len - 11u] = '\0';
            if (!valid_dependency_expression(dep)) {
                set_errorf(error, error_size, "invalid dependency expression: ", dep);
                return 0;
            }
        }
        if (!line_end) break;
        p = line_end + 1;
    }
    return 1;
}

static int validate_common(const char *path, char *error, size_t error_size, char values[7][1024], size_t *entry_count) {
    int path_rc = ake_validate_package_path(path, error, error_size);
    if (path_rc != 0) return path_rc;
    byte_buffer archive = {0};
    if (!read_xz(path, &archive, error, error_size)) {
        buffer_free(&archive);
        return 10;
    }
    if (!archive.size) {
        buffer_free(&archive);
        set_error(error, error_size, "decompressed AKE archive is empty");
        return 10;
    }
    char metadata[AKE_MAX_METADATA + 1u];
    if (!validate_tar(&archive, metadata, sizeof(metadata), error, error_size, entry_count)) {
        buffer_free(&archive);
        return 10;
    }
    if (!metadata[0]) {
        buffer_free(&archive);
        set_error(error, error_size, "metadata/package.ake is missing");
        return 10;
    }
    if (!has_required_fields(metadata, values, error, error_size)) {
        buffer_free(&archive);
        return 10;
    }
    if (!validate_dependencies(metadata, error, error_size)) {
        buffer_free(&archive);
        return 10;
    }
    if (strncmp(values[6], "1.", 2) != 0) {
        buffer_free(&archive);
        set_error(error, error_size, "unsupported AKE specification version");
        return 10;
    }
    size_t entry_len = strlen(values[5]);
    if (entry_len < 8u || strncmp(values[5], "bin/", 4) != 0 || !ascii_ieq(values[5][entry_len - 4u], '.') ||
        !ascii_ieq(values[5][entry_len - 3u], 'e') || !ascii_ieq(values[5][entry_len - 2u], 'x') ||
        !ascii_ieq(values[5][entry_len - 1u], 'e')) {
        buffer_free(&archive);
        set_error(error, error_size, "entry must point to a .exe under bin/");
        return 10;
    }
    if (!ake_is_safe_relative_path(values[5])) {
        buffer_free(&archive);
        set_error(error, error_size, "metadata entry contains an unsafe path");
        return 10;
    }

    /* Re-check that the declared entry exists in the TAR. */
    const char *needle = values[5];
    size_t pos = 0;
    int found_entry = 0;
    while (pos + 512u <= archive.size) {
        const unsigned char *h = (const unsigned char *)(archive.data + pos);
        if (is_zero_block(h)) { pos += 512u; continue; }
        char name[512];
        if (!tar_path(h, name, sizeof(name))) break;
        size_t file_size = 0;
        if (!parse_octal(h + 124u, 12u, &file_size)) break;
        size_t data_pos = pos + 512u;
        size_t padded = (file_size + 511u) & ~(size_t)511u;
        if (data_pos > archive.size || padded > archive.size - data_pos) break;
        if (strcmp(name, needle) == 0 && (h[156] == 0 || h[156] == '0')) { found_entry = 1; break; }
        pos = data_pos + padded;
    }
    buffer_free(&archive);
    if (!found_entry) {
        set_error(error, error_size, "entry executable is missing");
        return 10;
    }
    return 0;
}

int ake_validate_package(const char *path, char *error, size_t error_size) {
    char values[7][1024];
    size_t entries = 0;
    return validate_common(path, error, error_size, values, &entries);
}

int ake_package_info(const char *path, char *out, size_t out_size) {
    if (out && out_size) out[0] = '\0';
    char error[512];
    char values[7][1024];
    size_t entries = 0;
    int rc = validate_common(path, error, sizeof(error), values, &entries);
    if (rc != 0) {
        if (out && out_size) snprintf(out, out_size, "%s", error);
        return rc;
    }
    if (!out || out_size == 0) return 0;
    byte_buffer dep_archive = {0};
    char dep_metadata[AKE_MAX_METADATA + 1u];
    dep_metadata[0] = '\0';
    if (!read_xz(path, &dep_archive, error, sizeof(error))) {
        buffer_free(&dep_archive);
        if (out && out_size) snprintf(out, out_size, "%s", error);
        return 10;
    }
    size_t dep_count = 0;
    if (!validate_tar(&dep_archive, dep_metadata, sizeof(dep_metadata), error, sizeof(error), &dep_count)) {
        buffer_free(&dep_archive);
        if (out && out_size) snprintf(out, out_size, "%s", error);
        return 10;
    }
    buffer_free(&dep_archive);
    int n = snprintf(out, out_size,
        "name=%s\nid=%s\nversion=%s\npublisher=%s\narchitecture=%s\nentry=%s\nake_version=%s\nentries=%zu\n",
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], entries);
    if (n < 0 || (size_t)n >= out_size) {
        out[out_size - 1] = '\0';
        return 11;
    }
    size_t used = (size_t)n;
    const char *p = dep_metadata;
    while (p && *p) {
        const char *line_end = strchr(p, '\n');
        size_t len = line_end ? (size_t)(line_end - p) : strlen(p);
        int keep = 0;
        if (len >= 11u && strncmp(p, "dependency=", 11u) == 0) keep = 1;
        if (len >= 11u && strncmp(p, "permission.", 11u) == 0) keep = 1;
        if (len >= 9u && strncmp(p, "resource.", 9u) == 0) keep = 1;
        if (len >= 7u && strncmp(p, "volume.", 7u) == 0) keep = 1;
        if (len >= 4u && strncmp(p, "env.", 4u) == 0) keep = 1;
        if (len >= 5u && strncmp(p, "port.", 5u) == 0) keep = 1;
        if (len >= 9u && strncmp(p, "registry.", 9u) == 0) keep = 1;
        if (len >= 12u && strncmp(p, "association.", 12u) == 0) keep = 1;
        if (len >= 9u && strncmp(p, "protocol.", 9u) == 0) keep = 1;
        if (len >= 9u && strncmp(p, "shortcut.", 9u) == 0) keep = 1;
        if (len >= 8u && strncmp(p, "service.", 8u) == 0) keep = 1;
        if (keep) {
            if (used + len + 1u >= out_size) {
                out[out_size - 1] = '\0';
                return 11;
            }
            memcpy(out + used, p, len);
            used += len;
            out[used++] = '\n';
            out[used] = '\0';
        }
        if (!line_end) break;
        p = line_end + 1;
    }
    return 0;
}

int ake_package_dependencies(const char *path, char *out, size_t out_size) {
    if (out && out_size) out[0] = '\0';
    char error[512];
    char info_buf[8192];
    int rc = ake_package_info(path, info_buf, sizeof(info_buf));
    if (rc != 0) {
        if (out && out_size) snprintf(out, out_size, "%s", info_buf);
        return rc;
    }
    size_t used = 0;
    for (const char *p = info_buf; p && *p;) {
        const char *line_end = strchr(p, '\n');
        size_t len = line_end ? (size_t)(line_end - p) : strlen(p);
        if (len >= 11u && strncmp(p, "dependency=", 11u) == 0) {
            if (used + len + 1u >= out_size) {
                if (out && out_size) out[out_size - 1] = '\0';
                return 11;
            }
            memcpy(out + used, p, len);
            used += len;
            out[used++] = '\n';
            out[used] = '\0';
        }
        if (!line_end) break;
        p = line_end + 1;
    }
    (void)error;
    return 0;
}

const char *ake_core_version(void) {
    return "1.0-core-stage3";
}

/* Stage 15 test ABI: stable numeric mapping for network policy names. */
int ake_network_policy_parse_for_test(const char *value, int *mode) {
    if (!value || !mode) return -1;
    if (strcmp(value, "host") == 0) *mode = 0;
    else if (strcmp(value, "deny") == 0 || strcmp(value, "none") == 0) *mode = 1;
    else if (strcmp(value, "internet") == 0) *mode = 2;
    else if (strcmp(value, "internet-server") == 0) *mode = 3;
    else if (strcmp(value, "private-network") == 0 || strcmp(value, "private") == 0) *mode = 4;
    else if (strcmp(value, "internet-and-private") == 0 || strcmp(value, "all") == 0) *mode = 5;
    else return -2;
    return 0;
}
