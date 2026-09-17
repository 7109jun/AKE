#include "ake_windows.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdio>
#include <iterator>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

const char *ake_platform_name(void) {
#ifdef _WIN32
    return "windows";
#else
    return "non-windows-test";
#endif
}

#ifdef _WIN32
static int utf8_to_wide(const char *input, std::vector<wchar_t> &out) {
    if (!input) return 2;
    const size_t bytes = std::strlen(input);
    if (bytes > static_cast<size_t>(INT_MAX)) return 8;
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           input, static_cast<int>(bytes), nullptr, 0);
    if (needed < 0) return 8;
    if (needed == 0 && bytes != 0) return static_cast<int>(GetLastError());
    out.resize(static_cast<size_t>(needed) + 1u);
    if (needed != 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           input, static_cast<int>(bytes), out.data(), needed) <= 0) {
        return static_cast<int>(GetLastError());
    }
    out[static_cast<size_t>(needed)] = L'\0';
    return 0;
}

static int build_wide_environment(const unsigned char *utf8, size_t size,
                                  std::vector<wchar_t> &wide) {
    if (!utf8 || size < 2 || utf8[size - 1] != 0 || utf8[size - 2] != 0) return 9;
    if (size > 32768u * sizeof(char)) return 10;

    size_t i = 0;
    std::vector<std::string> records;
    while (i < size) {
        const size_t start = i;
        while (i < size && utf8[i] != 0) ++i;
        if (i == size) return 9;
        const size_t len = i - start;
        if (len == 0) {
            if (i + 1 != size) return 9;
            break;
        }
        records.emplace_back(reinterpret_cast<const char *>(utf8 + start), len);
        ++i;
    }

    std::sort(records.begin(), records.end(), [](const std::string &a, const std::string &b) {
        const auto split = [](const std::string &s) -> size_t {
            const size_t p = s.find('=');
            return p == std::string::npos ? s.size() : p;
        };
        const size_t ai = split(a), bi = split(b);
        size_t n = std::min(ai, bi);
        for (size_t j = 0; j < n; ++j) {
            unsigned char ac = static_cast<unsigned char>(a[j]);
            unsigned char bc = static_cast<unsigned char>(b[j]);
            ac = static_cast<unsigned char>(std::toupper(ac));
            bc = static_cast<unsigned char>(std::toupper(bc));
            if (ac != bc) return ac < bc;
        }
        return ai < bi;
    });

    wide.clear();
    for (const std::string &record : records) {
        std::vector<wchar_t> item;
        const int rc = utf8_to_wide(record.c_str(), item);
        if (rc != 0) return rc;
        wide.insert(wide.end(), item.begin(), item.end() - 1);
        wide.push_back(L'\0');
    }
    wide.push_back(L'\0');
    return 0;
}
#endif

static int spawn_impl(const char *program, const char *arguments,
                       const char *working_directory,
                       const unsigned char *environment_block_utf8,
                       size_t environment_size,
                       int *exit_code) {
    if (!program || !*program) return 2;
#ifdef _WIN32
    size_t n1 = std::strlen(program);
    size_t n2 = arguments ? std::strlen(arguments) : 0;
    if (n1 > static_cast<size_t>(INT_MAX) || n2 > static_cast<size_t>(INT_MAX)) return 8;

    std::string cmd;
    cmd.reserve(n1 + n2 + 4);
    cmd += '"';
    cmd += program;
    cmd += '"';
    if (n2) {
        cmd += ' ';
        cmd += arguments;
    }

    std::vector<wchar_t> wide_cmd;
    int rc = utf8_to_wide(cmd.c_str(), wide_cmd);
    if (rc != 0) return rc;

    std::vector<wchar_t> wide_cwd;
    const wchar_t *cwd_ptr = nullptr;
    if (working_directory && *working_directory) {
        rc = utf8_to_wide(working_directory, wide_cwd);
        if (rc != 0) return rc;
        cwd_ptr = wide_cwd.data();
    }

    std::vector<wchar_t> wide_env;
    LPVOID env_ptr = nullptr;
    if (environment_block_utf8 && environment_size != 0) {
        rc = build_wide_environment(environment_block_utf8, environment_size, wide_env);
        if (rc != 0) return rc;
        env_ptr = static_cast<LPVOID>(wide_env.data());
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    if (env_ptr) flags |= CREATE_NEW_PROCESS_GROUP;

    if (!CreateProcessW(nullptr, wide_cmd.data(), nullptr, nullptr, FALSE, flags,
                         env_ptr, cwd_ptr, &si, &pi)) {
        return static_cast<int>(GetLastError());
    }

    CloseHandle(pi.hThread);
    DWORD wait_rc = WaitForSingleObject(pi.hProcess, INFINITE);
    if (wait_rc != WAIT_OBJECT_0) {
        DWORD err = GetLastError();
        CloseHandle(pi.hProcess);
        return err ? static_cast<int>(err) : 5;
    }

    DWORD code = 1;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        DWORD err = GetLastError();
        CloseHandle(pi.hProcess);
        return err ? static_cast<int>(err) : 6;
    }
    CloseHandle(pi.hProcess);
    if (exit_code) *exit_code = (code > 0x7FFFFFFFu) ? static_cast<int>(0x7FFFFFFF) : static_cast<int>(code);
    return 0;
#else
    (void)arguments;
    (void)working_directory;
    (void)environment_block_utf8;
    (void)environment_size;
    (void)exit_code;
    return 3;
#endif
}

int ake_spawn_process(const char *program, const char *arguments) {
    int code = 0;
    int rc = spawn_impl(program, arguments, nullptr, nullptr, 0, &code);
    return rc ? rc : code;
}

int ake_spawn_process_in_directory(const char *program, const char *arguments,
                                   const char *working_directory, int *exit_code) {
    if (exit_code) *exit_code = 0;
    return spawn_impl(program, arguments, working_directory, nullptr, 0, exit_code);
}

int ake_spawn_process_in_directory_with_environment(
    const char *program, const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8,
    size_t environment_size,
    int *exit_code) {
    if (exit_code) *exit_code = 0;
    return spawn_impl(program, arguments, working_directory,
                      environment_block_utf8, environment_size, exit_code);
}

#ifdef _WIN32
#include <winhttp.h>

static void set_http_error(char *error, size_t error_size, const char *message) {
    if (!error || error_size == 0) return;
    std::strncpy(error, message ? message : "HTTP download failed", error_size - 1);
    error[error_size - 1] = '\0';
}

static int utf8_to_wide_string(const char *input, std::wstring &out) {
    std::vector<wchar_t> wide;
    int rc = utf8_to_wide(input, wide);
    if (rc != 0) return rc;
    out.assign(wide.data());
    return 0;
}

static bool parse_http_url(const std::wstring &url, std::wstring &host, INTERNET_PORT &port,
                           std::wstring &path, bool &secure) {
    URL_COMPONENTS c{};
    c.dwStructSize = sizeof(c);
    wchar_t host_buf[256]{};
    wchar_t path_buf[32768]{};
    wchar_t extra_buf[32768]{};
    c.lpszHostName = host_buf;
    c.dwHostNameLength = static_cast<DWORD>(sizeof(host_buf) / sizeof(host_buf[0]));
    c.lpszUrlPath = path_buf;
    c.dwUrlPathLength = static_cast<DWORD>(sizeof(path_buf) / sizeof(path_buf[0]));
    c.lpszExtraInfo = extra_buf;
    c.dwExtraInfoLength = static_cast<DWORD>(sizeof(extra_buf) / sizeof(extra_buf[0]));
    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &c)) return false;
    host.assign(c.lpszHostName, c.dwHostNameLength);
    path.assign(c.lpszUrlPath ? c.lpszUrlPath : L"", c.dwUrlPathLength);
    if (c.lpszExtraInfo && c.dwExtraInfoLength) path.append(c.lpszExtraInfo, c.dwExtraInfoLength);
    if (path.empty()) path = L"/";
    port = c.nPort;
    secure = (c.nScheme == INTERNET_SCHEME_HTTPS);
    return c.nScheme == INTERNET_SCHEME_HTTP || c.nScheme == INTERNET_SCHEME_HTTPS;
}

extern "C" int ake_http_download(const char *url, const char *destination, char *error, size_t error_size) {
    if (!url || !destination || !*url || !*destination) { set_http_error(error, error_size, "invalid HTTP download arguments"); return 2; }
    std::wstring wurl, whost, wpath, wdest;
    int rc = utf8_to_wide_string(url, wurl);
    if (rc != 0) { set_http_error(error, error_size, "invalid UTF-8 URL"); return rc; }
    rc = utf8_to_wide_string(destination, wdest);
    if (rc != 0) { set_http_error(error, error_size, "invalid UTF-8 destination"); return rc; }
    INTERNET_PORT port = 0;
    bool secure = false;
    if (!parse_http_url(wurl, whost, port, wpath, secure)) { set_http_error(error, error_size, "invalid HTTP(S) URL"); return 3; }

    HINTERNET session = WinHttpOpen(L"AKE/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { set_http_error(error, error_size, "WinHttpOpen failed"); return static_cast<int>(GetLastError()); }
    WinHttpSetTimeouts(session, 15000, 15000, 30000, 30000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    HINTERNET connect = WinHttpConnect(session, whost.c_str(), port, 0);
    if (!connect) { DWORD e = GetLastError(); WinHttpCloseHandle(session); set_http_error(error, error_size, "WinHttpConnect failed"); return static_cast<int>(e); }
    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", wpath.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) { DWORD e = GetLastError(); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "WinHttpOpenRequest failed"); return static_cast<int>(e); }

    const wchar_t *headers = L"Accept: application/octet-stream, text/plain\r\nUser-Agent: AKE/1.0\r\n";
    BOOL ok = WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(request, nullptr)) {
        DWORD e = GetLastError(); WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "HTTP request failed"); return static_cast<int>(e);
    }
    DWORD status = 0, status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "cannot query HTTP status"); return 7;
    }
    if (status < 200 || status >= 300) {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        set_http_error(error, error_size, "repository returned a non-success HTTP status");
        return status == 404 ? 70 : 7;
    }

    FILE *out = nullptr;
#if defined(_MSC_VER)
    if (_wfopen_s(&out, wdest.c_str(), L"wb") != 0) out = nullptr;
#else
    out = _wfopen(wdest.c_str(), L"wb");
#endif
    if (!out) { WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "cannot create destination file"); return 8; }

    unsigned char buffer[64 * 1024];
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) { fclose(out); DeleteFileW(wdest.c_str()); DWORD e = GetLastError(); WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "HTTP data query failed"); return static_cast<int>(e); }
        if (available == 0) break;
        while (available > 0) {
            DWORD want = (available > sizeof(buffer)) ? static_cast<DWORD>(sizeof(buffer)) : available;
            DWORD got = 0;
            if (!WinHttpReadData(request, buffer, want, &got) || got == 0) { fclose(out); DeleteFileW(wdest.c_str()); DWORD e = GetLastError(); WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "HTTP data read failed"); return static_cast<int>(e); }
            if (fwrite(buffer, 1, got, out) != got) { fclose(out); DeleteFileW(wdest.c_str()); WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); set_http_error(error, error_size, "cannot write downloaded file"); return 9; }
            available -= got;
        }
    }
    fclose(out);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return 0;
}
#else
extern "C" int ake_http_download(const char *url, const char *destination, char *error, size_t error_size) {
    (void)url; (void)destination;
    if (error && error_size) {
        const char *msg = "HTTP(S) repository downloads require a Windows build";
        std::strncpy(error, msg, error_size - 1);
        error[error_size - 1] = '\0';
    }
    return 3;
}
#endif

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <knownfolders.h>
#include <string>
#include <filesystem>

static void integration_error(char *error, size_t size, const char *msg) { if (!error || !size) return; std::strncpy(error, msg ? msg : "Windows integration failed", size - 1); error[size - 1] = '\0'; }
static bool valid_classes_key(const char *key) {
    if (!key || !*key) return false;
    std::string k(key);
    if (k.find("..") != std::string::npos || k.find('/') != std::string::npos || k.find(':') != std::string::npos) return false;
    return true;
}
static int classes_key(const char *key, HKEY *out) {
    if (!valid_classes_key(key) || !out) return ERROR_INVALID_PARAMETER;
    std::wstring w;
    std::vector<wchar_t> buf;
    int rc=utf8_to_wide(key,buf); if(rc) return rc; w.assign(buf.data());
    std::wstring full=L"Software\\Classes\\"+w;
    return RegCreateKeyExW(HKEY_CURRENT_USER,full.c_str(),0,nullptr,0,KEY_READ|KEY_WRITE,nullptr,out,nullptr);
}
static int classes_open(const char *key, HKEY *out) {
    if (!valid_classes_key(key) || !out) return ERROR_INVALID_PARAMETER;
    std::vector<wchar_t> buf; int rc=utf8_to_wide(key,buf); if(rc) return rc;
    std::wstring full=L"Software\\Classes\\"+std::wstring(buf.data());
    return RegOpenKeyExW(HKEY_CURRENT_USER,full.c_str(),0,KEY_READ|KEY_WRITE,out);
}
int ake_registry_set_classes(const char *key,const char *value_name,const char *value_data,char *error,size_t error_size){
    HKEY h=nullptr; int rc=classes_key(key,&h); if(rc){integration_error(error,error_size,"cannot open HKCU\\Software\\Classes key");return rc;}
    std::vector<wchar_t> vn,vd; rc=utf8_to_wide(value_name?value_name:"",vn); if(!rc)rc=utf8_to_wide(value_data?value_data:"",vd); if(!rc)rc=RegSetValueExW(h,vn.data(),0,REG_SZ,reinterpret_cast<const BYTE*>(vd.data()),static_cast<DWORD>(vd.size()*sizeof(wchar_t))); RegCloseKey(h); if(rc){integration_error(error,error_size,"cannot set registry value");} return rc;
}
int ake_registry_query_classes(const char *key,const char *value_name,char *out,size_t out_size){
    if(out&&out_size)out[0]='\0'; HKEY h=nullptr; int rc=classes_open(key,&h); if(rc==ERROR_FILE_NOT_FOUND||rc==ERROR_PATH_NOT_FOUND)return 2; if(rc)return rc;
    std::vector<wchar_t> vn; rc=utf8_to_wide(value_name?value_name:"",vn); if(rc){RegCloseKey(h);return rc;} DWORD type=0,size=0; rc=RegQueryValueExW(h,vn.data(),nullptr,&type,nullptr,&size); if(rc==ERROR_FILE_NOT_FOUND){RegCloseKey(h);return 2;} if(rc||type!=REG_SZ){RegCloseKey(h);return rc?rc:ERROR_DATATYPE_MISMATCH;} std::vector<BYTE> bytes(size+sizeof(wchar_t)); rc=RegQueryValueExW(h,vn.data(),nullptr,&type,bytes.data(),&size);RegCloseKey(h);if(rc)return rc;int needed=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,reinterpret_cast<wchar_t*>(bytes.data()),static_cast<int>(size/sizeof(wchar_t)),nullptr,0,nullptr,nullptr);if(needed<0||!out||out_size==0)return ERROR_INSUFFICIENT_BUFFER;std::vector<char> tmp(static_cast<size_t>(needed)+1);if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,reinterpret_cast<wchar_t*>(bytes.data()),static_cast<int>(size/sizeof(wchar_t)),tmp.data(),needed,nullptr,nullptr)<=0)return ERROR_NO_UNICODE_TRANSLATION;if(static_cast<size_t>(needed)+1>out_size)return ERROR_INSUFFICIENT_BUFFER;std::memcpy(out,tmp.data(),static_cast<size_t>(needed));out[needed]='\0';return 0;
}
int ake_registry_delete_classes(const char *key,const char *value_name,char *error,size_t error_size){HKEY h=nullptr;int rc=classes_open(key,&h);if(rc==ERROR_FILE_NOT_FOUND||rc==ERROR_PATH_NOT_FOUND)return 2;if(rc){integration_error(error,error_size,"cannot open registry key for deletion");return rc;}std::vector<wchar_t> vn;rc=utf8_to_wide(value_name?value_name:"",vn);if(!rc)rc=RegDeleteValueW(h,vn.data());RegCloseKey(h);if(rc==ERROR_FILE_NOT_FOUND)return 2;if(rc)integration_error(error,error_size,"cannot delete registry value");return rc;}
int ake_registry_delete_tree_classes(const char *key,char *error,size_t error_size){if(!valid_classes_key(key))return ERROR_INVALID_PARAMETER;std::vector<wchar_t> b;int rc=utf8_to_wide(key,b);if(rc)return rc;std::wstring full=L"Software\\Classes\\"+std::wstring(b.data());rc=RegDeleteTreeW(HKEY_CURRENT_USER,full.c_str());if(rc==ERROR_FILE_NOT_FOUND||rc==ERROR_PATH_NOT_FOUND)return 2;if(rc)integration_error(error,error_size,"cannot delete registry tree");return rc;}

static int shortcut_path(const char *kind,const char *name,std::wstring &path){if(!kind||!name||!*name)return ERROR_INVALID_PARAMETER;if(std::string(name).find_first_of("\\/")!=std::string::npos)return ERROR_INVALID_NAME;REFKNOWNFOLDERID folder=FOLDERID_Programs;if(std::strcmp(kind,"desktop")==0)folder=FOLDERID_Desktop;else if(std::strcmp(kind,"start-menu")!=0)return ERROR_INVALID_PARAMETER;PWSTR base=nullptr;HRESULT hr=SHGetKnownFolderPath(folder,0,nullptr,&base);if(FAILED(hr))return static_cast<int>(hr);std::filesystem::path dir(base);CoTaskMemFree(base);if(std::strcmp(kind,"start-menu")==0){dir/=L"AKE";std::error_code ec;std::filesystem::create_directories(dir,ec);if(ec)return static_cast<int>(ERROR_CANNOT_MAKE);}std::vector<wchar_t> wn;int rc=utf8_to_wide(name,wn);if(rc)return rc;dir/=std::wstring(wn.data())+L".lnk";path=dir.wstring();return 0;}
int ake_create_shortcut(const char *kind,const char *name,const char *target,const char *arguments,const char *working_directory,char *error,size_t error_size){std::wstring path;int rc=shortcut_path(kind,name,path);if(rc){integration_error(error,error_size,"invalid shortcut path");return rc;}std::vector<wchar_t> wt,wa,ww;rc=utf8_to_wide(target,wt);if(rc)return rc;if(arguments&&*arguments){rc=utf8_to_wide(arguments,wa);if(rc)return rc;}if(working_directory&&*working_directory){rc=utf8_to_wide(working_directory,ww);if(rc)return rc;}HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);bool uninit=SUCCEEDED(hr);if(FAILED(hr)&&hr!=RPC_E_CHANGED_MODE){integration_error(error,error_size,"COM initialization failed");return static_cast<int>(hr);}IShellLinkW *link=nullptr;hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&link));if(SUCCEEDED(hr))hr=link->SetPath(wt.data());if(SUCCEEDED(hr)&&!wa.empty())hr=link->SetArguments(wa.data());if(SUCCEEDED(hr)&&!ww.empty())hr=link->SetWorkingDirectory(ww.data());IPersistFile *pf=nullptr;if(SUCCEEDED(hr))hr=link->QueryInterface(IID_PPV_ARGS(&pf));if(SUCCEEDED(hr))hr=pf->Save(path.c_str(),TRUE);if(pf)pf->Release();if(link)link->Release();if(uninit)CoUninitialize();if(FAILED(hr)){integration_error(error,error_size,"cannot create Windows shortcut");return static_cast<int>(hr);}return 0;}
int ake_remove_shortcut(const char *kind,const char *name,char *error,size_t error_size){std::wstring path;int rc=shortcut_path(kind,name,path);if(rc)return rc;if(!DeleteFileW(path.c_str())){DWORD e=GetLastError();if(e==ERROR_FILE_NOT_FOUND)return 2;integration_error(error,error_size,"cannot remove Windows shortcut");return static_cast<int>(e);}return 0;}
#else
int ake_registry_set_classes(const char*,const char*,const char*,char*,size_t){return 3;}
int ake_registry_query_classes(const char*,const char*,char*,size_t){return 3;}
int ake_registry_delete_classes(const char*,const char*,char*,size_t){return 3;}
int ake_registry_delete_tree_classes(const char*,char*,size_t){return 3;}
int ake_create_shortcut(const char*,const char*,const char*,const char*,const char*,char*,size_t){return 3;}
int ake_remove_shortcut(const char*,const char*,char*,size_t){return 3;}
#endif
