#include "ake_ipc.h"

#include <cstring>
#include <string>
#include <vector>
#include <limits>
#include <climits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static bool valid_component(const char *value) {
    if (!value || !*value) return false;
    const size_t n = std::strlen(value);
    if (n > 64) return false;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (!(c == '.' || c == '_' || c == '-' ||
              (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

int ake_ipc_validate_component(const char *value) {
    return valid_component(value) ? 0 : 1;
}

int ake_ipc_build_pipe_name(const char *container_name, const char *channel,
                            char *out, size_t out_size) {
    if (!valid_component(container_name) || !valid_component(channel) || !out || out_size == 0) return 1;
#ifdef _WIN32
    const std::string value = std::string("\\\\.\\pipe\\AKE\\") + container_name + "\\" + channel;
#else
    const std::string value = std::string("ake-ipc/") + container_name + "/" + channel;
#endif
    if (value.size() + 1 > out_size) return 2;
    std::memcpy(out, value.c_str(), value.size() + 1);
    return 0;
}

#ifdef _WIN32
static int utf8_wide(const char *input, std::wstring &out) {
    if (!input) return ERROR_INVALID_PARAMETER;
    const size_t n = std::strlen(input);
    if (n > static_cast<size_t>(INT_MAX)) return ERROR_ARITHMETIC_OVERFLOW;
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           input, static_cast<int>(n), nullptr, 0);
    if (needed <= 0) return static_cast<int>(GetLastError());
    out.resize(static_cast<size_t>(needed));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            input, static_cast<int>(n), out.data(), needed) <= 0) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}

static bool write_exact(HANDLE h, const void *data, DWORD size) {
    const unsigned char *p = static_cast<const unsigned char *>(data);
    DWORD left = size;
    while (left) {
        DWORD done = 0;
        if (!WriteFile(h, p, left, &done, nullptr)) return false;
        if (done == 0) return false;
        p += done;
        left -= done;
    }
    return true;
}

static bool read_exact(HANDLE h, void *data, DWORD size) {
    unsigned char *p = static_cast<unsigned char *>(data);
    DWORD left = size;
    while (left) {
        DWORD got = 0;
        if (!ReadFile(h, p, left, &got, nullptr)) return false;
        if (got == 0) return false;
        p += got;
        left -= got;
    }
    return true;
}

static int wait_for_client(HANDLE pipe, uint32_t timeout_ms) {
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return static_cast<int>(GetLastError());
    BOOL connected = ConnectNamedPipe(pipe, &ov);
    if (connected) {
        CloseHandle(ov.hEvent);
        return 0;
    }
    DWORD err = GetLastError();
    if (err == ERROR_PIPE_CONNECTED) {
        SetEvent(ov.hEvent);
    } else if (err != ERROR_IO_PENDING) {
        CloseHandle(ov.hEvent);
        return static_cast<int>(err);
    }
    if (timeout_ms == 0) timeout_ms = 30000;
    const DWORD wait_rc = WaitForSingleObject(ov.hEvent, timeout_ms);
    if (wait_rc == WAIT_TIMEOUT) {
        CancelIoEx(pipe, &ov);
        CloseHandle(ov.hEvent);
        return static_cast<int>(ERROR_TIMEOUT);
    }
    if (wait_rc != WAIT_OBJECT_0) {
        CloseHandle(ov.hEvent);
        return static_cast<int>(GetLastError());
    }
    DWORD transferred = 0;
    if (!GetOverlappedResult(pipe, &ov, &transferred, FALSE) && GetLastError() != ERROR_PIPE_CONNECTED) {
        const int result = static_cast<int>(GetLastError());
        CloseHandle(ov.hEvent);
        return result;
    }
    CloseHandle(ov.hEvent);
    return 0;
}

int ake_ipc_server_once(const char *pipe_name,
                        const unsigned char *response, size_t response_size,
                        uint32_t timeout_ms) {
    if (!pipe_name || !*pipe_name || response_size > 1024u * 1024u) return ERROR_INVALID_PARAMETER;
    std::wstring wpipe;
    int rc = utf8_wide(pipe_name, wpipe);
    if (rc != 0) return rc;
    HANDLE pipe = CreateNamedPipeW(
        wpipe.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 1024 * 1024, 1024 * 1024, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());

    const int connect_rc = wait_for_client(pipe, timeout_ms);
    if (connect_rc != 0) {
        CloseHandle(pipe);
        return connect_rc;
    }
    uint32_t request_size = 0;
    if (!read_exact(pipe, &request_size, sizeof(request_size)) || request_size > 1024u * 1024u) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return ERROR_INVALID_DATA;
    }
    std::vector<unsigned char> request(request_size);
    if (request_size && !read_exact(pipe, request.data(), request_size)) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return static_cast<int>(GetLastError());
    }
    (void)request;
    const uint32_t out_size = static_cast<uint32_t>(response_size);
    bool ok = write_exact(pipe, &out_size, sizeof(out_size));
    if (ok && out_size) ok = write_exact(pipe, response, out_size);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return static_cast<int>(err);
}

int ake_ipc_client_call(const char *pipe_name,
                        const unsigned char *request, size_t request_size,
                        unsigned char *response, size_t response_capacity,
                        size_t *response_size, uint32_t timeout_ms) {
    if (!pipe_name || !*pipe_name || request_size > 1024u * 1024u ||
        (!response && response_capacity) || !response_size) return ERROR_INVALID_PARAMETER;
    *response_size = 0;
    std::wstring wpipe;
    int rc = utf8_wide(pipe_name, wpipe);
    if (rc != 0) return rc;
    if (timeout_ms == 0) timeout_ms = 5000;
    if (!WaitNamedPipeW(wpipe.c_str(), timeout_ms)) return static_cast<int>(GetLastError());
    HANDLE pipe = CreateFileW(wpipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());
    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
        const int err = static_cast<int>(GetLastError());
        CloseHandle(pipe);
        return err;
    }
    const uint32_t req = static_cast<uint32_t>(request_size);
    bool ok = write_exact(pipe, &req, sizeof(req));
    if (ok && req) ok = write_exact(pipe, request, req);
    uint32_t out_size = 0;
    if (ok) ok = read_exact(pipe, &out_size, sizeof(out_size));
    if (!ok || out_size > response_capacity || out_size > 1024u * 1024u) {
        const int err = ok ? static_cast<int>(ERROR_MORE_DATA) : static_cast<int>(GetLastError());
        CloseHandle(pipe);
        return err;
    }
    if (out_size) ok = read_exact(pipe, response, out_size);
    if (ok) *response_size = out_size;
    const int err = ok ? ERROR_SUCCESS : static_cast<int>(GetLastError());
    CloseHandle(pipe);
    return err;
}

#else
int ake_ipc_server_once(const char *, const unsigned char *, size_t, uint32_t) { return 120; }
int ake_ipc_client_call(const char *, const unsigned char *, size_t, unsigned char *, size_t, size_t *, uint32_t) { return 120; }
#endif

const char *ake_ipc_version(void) { return "1.0"; }
