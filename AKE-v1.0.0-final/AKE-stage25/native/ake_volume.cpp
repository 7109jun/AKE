#include "ake_volume.h"
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <cstddef>

static int utf8_wide(const char *input, std::wstring &out) {
    if (!input) return ERROR_INVALID_PARAMETER;
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, nullptr, 0);
    if (needed <= 0) return static_cast<int>(GetLastError());
    out.resize(static_cast<size_t>(needed - 1));
    if (needed > 1 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, out.data(), needed) <= 0)
        return static_cast<int>(GetLastError());
    return 0;
}

#pragma pack(push, 1)
typedef struct _AKE_MOUNT_POINT_REPARSE_BUFFER {
    DWORD ReparseTag;
    WORD ReparseDataLength;
    WORD Reserved;
    WORD SubstituteNameOffset;
    WORD SubstituteNameLength;
    WORD PrintNameOffset;
    WORD PrintNameLength;
    WCHAR PathBuffer[1];
} AKE_MOUNT_POINT_REPARSE_BUFFER;
#pragma pack(pop)

static bool is_drive_absolute(const std::wstring &path) {
    return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

static int create_junction(const std::wstring &source, const std::wstring &target) {
    if (!is_drive_absolute(source) || target.empty()) return ERROR_INVALID_PARAMETER;
    if (GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES) return ERROR_ALREADY_EXISTS;
    if (!CreateDirectoryW(target.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return static_cast<int>(GetLastError());

    std::wstring substitute = L"\\??\\" + source;
    for (auto &c : substitute) if (c == L'/') c = L'\\';
    const size_t path_bytes = (substitute.size() + 1) * sizeof(WCHAR);
    if (path_bytes > 0xFFF0u) { RemoveDirectoryW(target.c_str()); return ERROR_BUFFER_OVERFLOW; }

    const size_t total = sizeof(AKE_MOUNT_POINT_REPARSE_BUFFER) + path_bytes + 2 * sizeof(WCHAR);
    std::vector<BYTE> buffer(total, 0);
    auto *data = reinterpret_cast<AKE_MOUNT_POINT_REPARSE_BUFFER *>(buffer.data());
    data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    data->SubstituteNameOffset = 0;
    data->SubstituteNameLength = static_cast<WORD>(substitute.size() * sizeof(WCHAR));
    data->PrintNameOffset = data->SubstituteNameLength + sizeof(WCHAR);
    data->PrintNameLength = 0;
    std::memcpy(data->PathBuffer, substitute.c_str(), path_bytes);
    data->ReparseDataLength = static_cast<WORD>(8 + path_bytes);

    HANDLE h = CreateFileW(target.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryW(target.c_str()); return static_cast<int>(GetLastError()); }
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, data, data->ReparseDataLength + 8, nullptr, 0, &bytes, nullptr);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!ok) RemoveDirectoryW(target.c_str());
    return static_cast<int>(err);
}

static int delete_junction(const std::wstring &target) {
    HANDLE h = CreateFileW(target.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());
    struct {
        DWORD ReparseTag;
        WORD ReparseDataLength;
        WORD Reserved;
    } header{IO_REPARSE_TAG_MOUNT_POINT, 0, 0};
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_DELETE_REPARSE_POINT, &header, sizeof(header), nullptr, 0, &bytes, nullptr);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (ok && !RemoveDirectoryW(target.c_str())) return static_cast<int>(GetLastError());
    return static_cast<int>(err);
}

int ake_mount_volume(const char *source, const char *target, int /*read_only*/) {
    std::wstring ws, wt;
    int rc = utf8_wide(source, ws); if (rc != 0) return rc;
    rc = utf8_wide(target, wt); if (rc != 0) return rc;
    DWORD attr = GetFileAttributesW(ws.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return ERROR_PATH_NOT_FOUND;
    return create_junction(ws, wt);
}

int ake_unmount_volume(const char *target) {
    std::wstring wt;
    int rc = utf8_wide(target, wt); if (rc != 0) return rc;
    DWORD attr = GetFileAttributesW(wt.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return ERROR_FILE_NOT_FOUND;
    return delete_junction(wt);
}

#else
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <errno.h>

int ake_mount_volume(const char *source, const char *target, int /*read_only*/) {
    if (!source || !target || source[0] != '/' || target[0] != '/') return 22;
    if (symlink(source, target) != 0) return errno;
    return 0;
}

int ake_unmount_volume(const char *target) {
    if (!target) return 22;
    if (unlink(target) != 0) return errno;
    return 0;
}
#endif
