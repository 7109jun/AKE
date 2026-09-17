#include "ake_isolation.h"
#include "ake_runtime.h"

#include <cstring>
#include <string>
#include <vector>
#include <climits>
#include <cstdint>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#endif

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

static int build_environment(const unsigned char *utf8, size_t size,
                             std::vector<wchar_t> &out) {
    if (!utf8 || size < 2 || utf8[size - 1] != 0 || utf8[size - 2] != 0) return ERROR_INVALID_DATA;
    if (size > 32768u * sizeof(char)) return ERROR_ENVVAR_NOT_FOUND;
    out.clear();
    size_t i = 0;
    while (i < size) {
        const size_t start = i;
        while (i < size && utf8[i] != 0) ++i;
        if (i == size) return ERROR_INVALID_DATA;
        const size_t len = i - start;
        if (len == 0) {
            if (i + 1 != size) return ERROR_INVALID_DATA;
            break;
        }
        std::string record(reinterpret_cast<const char *>(utf8 + start), len);
        std::wstring wr;
        int rc = utf8_wide(record.c_str(), wr);
        if (rc != 0) return rc;
        out.insert(out.end(), wr.begin(), wr.end());
        out.push_back(L'\0');
        ++i;
    }
    out.push_back(L'\0');
    return 0;
}

static int grant_runtime_access(const std::wstring &path, PSID app_sid) {
    if (!app_sid || !IsValidSid(app_sid)) return ERROR_INVALID_SID;
    PSID owner = nullptr;
    PSID group = nullptr;
    PACL old_acl = nullptr;
    PACL new_acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD rc = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION, &owner, &group,
                                     &old_acl, nullptr, &descriptor);
    if (rc != ERROR_SUCCESS) return static_cast<int>(rc);

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(app_sid);

    rc = SetEntriesInAclW(1, &ea, old_acl, &new_acl);
    if (rc == ERROR_SUCCESS) {
        rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                   new_acl, nullptr);
    }
    if (new_acl) LocalFree(new_acl);
    if (descriptor) LocalFree(descriptor);
    return static_cast<int>(rc);
}

static int get_appcontainer_sid(const std::wstring &name, PSID *out_sid) {
    if (!out_sid) return ERROR_INVALID_PARAMETER;
    *out_sid = nullptr;
    wchar_t display[256] = L"AKE Package";
    wchar_t description[256] = L"AKE application container";
    HRESULT hr = CreateAppContainerProfile(name.c_str(), display, description,
                                            nullptr, 0, out_sid);
    if (SUCCEEDED(hr)) return 0;
    if (hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) return static_cast<int>(HRESULT_CODE(hr));
    return static_cast<int>(HRESULT_CODE(DeriveAppContainerSidFromAppContainerName(name.c_str(), out_sid)));
}

typedef BOOL (WINAPI *ake_derive_capability_sids_fn)(
    LPCWSTR, PSID **, DWORD *, PSID **, DWORD *);

static ake_derive_capability_sids_fn resolve_derive_capability_sids() {
    HMODULE kernel_base = GetModuleHandleW(L"KernelBase.dll");
    if (!kernel_base) kernel_base = LoadLibraryW(L"KernelBase.dll");
    if (!kernel_base) return nullptr;
    return reinterpret_cast<ake_derive_capability_sids_fn>(
        GetProcAddress(kernel_base, "DeriveCapabilitySidsFromName"));
}

static int append_capability(const wchar_t *name,
                             std::vector<SID_AND_ATTRIBUTES> &attributes,
                             std::vector<PSID> &owned_sids) {
    if (!name) return ERROR_INVALID_PARAMETER;

    const auto derive_capability_sids = resolve_derive_capability_sids();
    if (!derive_capability_sids) return ERROR_CALL_NOT_IMPLEMENTED;

    PSID *group_sids = nullptr;
    DWORD group_count = 0;
    PSID *capability_sids = nullptr;
    DWORD capability_count = 0;

    if (!derive_capability_sids(name, &group_sids, &group_count,
                                &capability_sids, &capability_count)) {
        return static_cast<int>(GetLastError());
    }

    if (group_sids) {
        for (DWORD i = 0; i < group_count; ++i) {
            if (group_sids[i]) LocalFree(group_sids[i]);
        }
        LocalFree(group_sids);
    }

    if (!capability_sids || capability_count != 1 || !capability_sids[0]) {
        if (capability_sids) {
            for (DWORD i = 0; i < capability_count; ++i) {
                if (capability_sids[i]) LocalFree(capability_sids[i]);
            }
            LocalFree(capability_sids);
        }
        return ERROR_INVALID_DATA;
    }

    PSID sid = capability_sids[0];
    LocalFree(capability_sids);
    owned_sids.push_back(sid);

    SID_AND_ATTRIBUTES entry{};
    entry.Sid = sid;
    entry.Attributes = SE_GROUP_ENABLED;
    attributes.push_back(entry);
    return 0;
}

static int build_network_capabilities(
    int network_mode,
    std::vector<SID_AND_ATTRIBUTES> &attributes,
    std::vector<PSID> &owned_sids) {
    attributes.clear();
    owned_sids.clear();

    switch (network_mode) {
        case 1: // deny
            return 0;
        case 2: // internet client
            return append_capability(L"internetClient", attributes, owned_sids);
        case 3: // internet client + server
            return append_capability(L"internetClientServer", attributes, owned_sids);
        case 4: // private network client + server
            return append_capability(L"privateNetworkClientServer", attributes, owned_sids);
        case 5: { // internet + private network
            int rc = append_capability(L"internetClientServer", attributes, owned_sids);
            if (rc != 0) return rc;
            rc = append_capability(L"privateNetworkClientServer", attributes, owned_sids);
            if (rc != 0) return rc;
            return 0;
        }
        case 0: // host/inherit; an AppContainer cannot be given unrestricted host networking
            return 0;
        default:
            return ERROR_INVALID_PARAMETER;
    }
}

static void free_owned_sids(std::vector<PSID> &owned_sids) {
    for (PSID sid : owned_sids) {
        if (sid) LocalFree(sid);
    }
    owned_sids.clear();
}

static int create_restricted_primary_token(HANDLE *out_token) {
    if (!out_token) return ERROR_INVALID_PARAMETER;
    *out_token = nullptr;
    HANDLE current_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                          &current_token)) {
        return static_cast<int>(GetLastError());
    }
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID administrators_sid = nullptr;
    SID_AND_ATTRIBUTES disabled_sid{};
    DWORD disable_sid_count = 0;
    if (AllocateAndInitializeSid(&nt_authority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &administrators_sid)) {
        disabled_sid.Sid = administrators_sid;
        disabled_sid.Attributes = 0;
        disable_sid_count = 1;
    }

    HANDLE restricted = nullptr;
    if (!CreateRestrictedToken(current_token,
                               DISABLE_MAX_PRIVILEGE,
                               disable_sid_count, disable_sid_count ? &disabled_sid : nullptr,
                               0, nullptr,
                               0, nullptr,
                               &restricted)) {
        DWORD e = GetLastError();
        if (administrators_sid) FreeSid(administrators_sid);
        CloseHandle(current_token);
        return static_cast<int>(e);
    }
    if (administrators_sid) FreeSid(administrators_sid);
    CloseHandle(current_token);
    *out_token = restricted;
    return 0;
}

static int spawn_impl(const char *program, const char *arguments,
                      const char *working_directory,
                      const unsigned char *environment_block_utf8, size_t environment_size,
                      const char *container_name, int filesystem_mode, int process_mode,
                      int network_mode, int identity_mode,
                      uint64_t memory_limit_bytes, uint32_t cpu_rate_percent_x100,
                      uint32_t active_process_limit, uint64_t process_user_time_100ns,
                      int *exit_code) {
    if (!program || !*program || !working_directory || !*working_directory) return ERROR_INVALID_PARAMETER;

    std::wstring wprogram, wcwd, wname;
    int rc = utf8_wide(program, wprogram);
    if (rc != 0) return rc;
    rc = utf8_wide(working_directory, wcwd);
    if (rc != 0) return rc;
    if (container_name && *container_name) {
        rc = utf8_wide(container_name, wname);
        if (rc != 0) return rc;
    }

    std::vector<wchar_t> env;
    rc = build_environment(environment_block_utf8, environment_size, env);
    if (rc != 0) return rc;

    std::string command_utf8 = "\"";
    command_utf8 += program;
    command_utf8 += "\"";
    if (arguments && *arguments) {
        command_utf8 += ' ';
        command_utf8 += arguments;
    }
    std::wstring command;
    rc = utf8_wide(command_utf8.c_str(), command);
    if (rc != 0) return rc;

    PROCESS_INFORMATION pi{};
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);

    SIZE_T attr_size = 0;
    SECURITY_CAPABILITIES caps{};
    PSID app_sid = nullptr;
    PPROC_THREAD_ATTRIBUTE_LIST attrs = nullptr;
    HANDLE job = nullptr;
    HANDLE restricted_token = nullptr;
    std::vector<SID_AND_ATTRIBUTES> network_capabilities;
    std::vector<PSID> owned_capability_sids;

    if (identity_mode < 0 || identity_mode > 2) return ERROR_INVALID_PARAMETER;
    if (identity_mode == 2 && filesystem_mode != 1) return ERROR_INVALID_PARAMETER;
    if (identity_mode == 1 && filesystem_mode == 1) return ERROR_INVALID_PARAMETER;
    if (identity_mode != 2 && network_mode != 0) return ERROR_INVALID_PARAMETER;

    DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    if (filesystem_mode == 1) {
        if (!container_name || !*container_name) return ERROR_INVALID_PARAMETER;
        rc = get_appcontainer_sid(wname, &app_sid);
        if (rc != 0) return rc;
        rc = grant_runtime_access(wcwd, app_sid);
        if (rc != 0) {
            FreeSid(app_sid);
            return rc;
        }
        int capability_rc = build_network_capabilities(network_mode, network_capabilities, owned_capability_sids);
        if (capability_rc != 0) {
            FreeSid(app_sid);
            free_owned_sids(owned_capability_sids);
            return capability_rc;
        }

        caps.AppContainerSid = app_sid;
        caps.Capabilities = network_capabilities.empty() ? nullptr : network_capabilities.data();
        caps.CapabilityCount = static_cast<DWORD>(network_capabilities.size());
        caps.Reserved = 0;

        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        attrs = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attr_size));
        if (!attrs) { free_owned_sids(owned_capability_sids); FreeSid(app_sid); return ERROR_NOT_ENOUGH_MEMORY; }
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) {
            rc = static_cast<int>(GetLastError());
            HeapFree(GetProcessHeap(), 0, attrs);
            free_owned_sids(owned_capability_sids);
            FreeSid(app_sid);
            return rc;
        }
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &caps, sizeof(caps), nullptr, nullptr)) {
            rc = static_cast<int>(GetLastError());
            DeleteProcThreadAttributeList(attrs);
            HeapFree(GetProcessHeap(), 0, attrs);
            free_owned_sids(owned_capability_sids);
            FreeSid(app_sid);
            return rc;
        }
        si.lpAttributeList = attrs;
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if ((memory_limit_bytes != 0 || cpu_rate_percent_x100 != 0 || active_process_limit != 0 || process_user_time_100ns != 0) && process_mode != 0) {
        rc = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if (process_mode == 0) {
        job = CreateJobObjectW(nullptr, nullptr);
        if (!job) { rc = static_cast<int>(GetLastError()); goto cleanup; }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (memory_limit_bytes != 0) {
            if (memory_limit_bytes > static_cast<uint64_t>(std::numeric_limits<SIZE_T>::max())) {
                rc = ERROR_ARITHMETIC_OVERFLOW; goto cleanup;
            }
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = static_cast<SIZE_T>(memory_limit_bytes);
        }
        if (active_process_limit != 0) {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
        }
        if (process_user_time_100ns != 0) {
            if (process_user_time_100ns > static_cast<uint64_t>(std::numeric_limits<LONGLONG>::max())) {
                rc = ERROR_ARITHMETIC_OVERFLOW; goto cleanup;
            }
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(process_user_time_100ns);
        }
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits))) {
            rc = static_cast<int>(GetLastError()); goto cleanup;
        }
        if (cpu_rate_percent_x100 != 0) {
            if (cpu_rate_percent_x100 > 10000u) {
                rc = ERROR_INVALID_PARAMETER; goto cleanup;
            }
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
            cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpu.CpuRate = cpu_rate_percent_x100;
            if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation,
                                         &cpu, sizeof(cpu))) {
                rc = static_cast<int>(GetLastError()); goto cleanup;
            }
        }
    }

    if (identity_mode == 1) {
        rc = create_restricted_primary_token(&restricted_token);
        if (rc != 0) goto cleanup;
        if (!CreateProcessAsUserW(restricted_token, wprogram.c_str(), command.data(),
                                  nullptr, nullptr, FALSE, flags, env.data(),
                                  wcwd.c_str(), &si.StartupInfo, &pi)) {
            rc = static_cast<int>(GetLastError());
            goto cleanup;
        }
    } else {
        if (!CreateProcessW(wprogram.c_str(), command.data(), nullptr, nullptr, FALSE,
                            flags, env.data(), wcwd.c_str(), &si.StartupInfo, &pi)) {
            rc = static_cast<int>(GetLastError());
            goto cleanup;
        }
    }

    if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
        rc = static_cast<int>(GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        goto cleanup;
    }

    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        rc = static_cast<int>(GetLastError());
        CloseHandle(pi.hProcess);
        goto cleanup;
    }
    {
        DWORD code = 1;
        if (!GetExitCodeProcess(pi.hProcess, &code)) {
            rc = static_cast<int>(GetLastError());
            CloseHandle(pi.hProcess);
            goto cleanup;
        }
        CloseHandle(pi.hProcess);
        if (exit_code) *exit_code = static_cast<int>(code <= 0x7FFFFFFFu ? code : 0x7FFFFFFFu);
        rc = 0;
    }

cleanup:
    if (job) CloseHandle(job);
    if (restricted_token) CloseHandle(restricted_token);
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    free_owned_sids(owned_capability_sids);
    if (app_sid) FreeSid(app_sid);
    return rc;
}

static int spawn_detached_impl(
    const char *program, const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8, size_t environment_size,
    const char *container_name, int filesystem_mode, int process_mode,
    int network_mode,
    int identity_mode,
    uint64_t memory_limit_bytes, uint32_t cpu_rate_percent_x100,
    uint32_t active_process_limit, uint64_t process_user_time_100ns,
    const char *job_name, const char *log_path, uint32_t *pid_out) {
    if (!program || !*program || !working_directory || !*working_directory ||
        !log_path || !*log_path || !pid_out) return ERROR_INVALID_PARAMETER;

    std::wstring wprogram, wcwd, wname, wjob, wlog;
    int rc = utf8_wide(program, wprogram);
    if (rc != 0) return rc;
    rc = utf8_wide(working_directory, wcwd);
    if (rc != 0) return rc;
    rc = utf8_wide(log_path, wlog);
    if (rc != 0) return rc;
    if (filesystem_mode == 1) {
        if (!container_name || !*container_name) return ERROR_INVALID_PARAMETER;
        rc = utf8_wide(container_name, wname);
        if (rc != 0) return rc;
    }
    if (process_mode == 0) {
        if (!job_name || !*job_name) return ERROR_INVALID_PARAMETER;
        rc = utf8_wide(job_name, wjob);
        if (rc != 0) return rc;
    }

    std::vector<wchar_t> env;
    rc = build_environment(environment_block_utf8, environment_size, env);
    if (rc != 0) return rc;

    std::string command_utf8 = "\"";
    command_utf8 += program;
    command_utf8 += "\"";
    if (arguments && *arguments) {
        command_utf8 += ' ';
        command_utf8 += arguments;
    }
    std::wstring command;
    rc = utf8_wide(command_utf8.c_str(), command);
    if (rc != 0) return rc;

    SECURITY_ATTRIBUTES inherit_attributes{};
    inherit_attributes.nLength = sizeof(inherit_attributes);
    inherit_attributes.bInheritHandle = TRUE;

    HANDLE log = CreateFileW(wlog.c_str(), GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             &inherit_attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());

    HANDLE input = CreateFileW(L"NUL", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &inherit_attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        CloseHandle(log);
        return static_cast<int>(e);
    }

    PROCESS_INFORMATION pi{};
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = input;
    si.StartupInfo.hStdOutput = log;
    si.StartupInfo.hStdError = log;

    SIZE_T attr_size = 0;
    const SIZE_T attr_count = filesystem_mode == 1 ? 2u : 1u;
    InitializeProcThreadAttributeList(nullptr, static_cast<DWORD>(attr_count), 0, &attr_size);
    PPROC_THREAD_ATTRIBUTE_LIST attrs = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attr_size));
    if (!attrs) {
        CloseHandle(input); CloseHandle(log);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!InitializeProcThreadAttributeList(attrs, static_cast<DWORD>(attr_count), 0, &attr_size)) {
        rc = static_cast<int>(GetLastError());
        HeapFree(GetProcessHeap(), 0, attrs);
        CloseHandle(input); CloseHandle(log);
        return rc;
    }

    SECURITY_CAPABILITIES caps{};
    PSID app_sid = nullptr;
    std::vector<SID_AND_ATTRIBUTES> network_capabilities;
    std::vector<PSID> owned_capability_sids;
    HANDLE job = nullptr;
    HANDLE restricted_token = nullptr;

    if (identity_mode < 0 || identity_mode > 2) { rc = ERROR_INVALID_PARAMETER; goto detached_cleanup; }
    if (identity_mode == 2 && filesystem_mode != 1) { rc = ERROR_INVALID_PARAMETER; goto detached_cleanup; }
    if (identity_mode == 1 && filesystem_mode == 1) { rc = ERROR_INVALID_PARAMETER; goto detached_cleanup; }
    if (identity_mode != 2 && network_mode != 0) { rc = ERROR_INVALID_PARAMETER; goto detached_cleanup; }

    if (filesystem_mode == 1) {
        rc = get_appcontainer_sid(wname, &app_sid);
        if (rc != 0) goto detached_cleanup;
        rc = grant_runtime_access(wcwd, app_sid);
        if (rc != 0) goto detached_cleanup;
        rc = build_network_capabilities(network_mode, network_capabilities, owned_capability_sids);
        if (rc != 0) goto detached_cleanup;

        caps.AppContainerSid = app_sid;
        caps.Capabilities = network_capabilities.empty() ? nullptr : network_capabilities.data();
        caps.CapabilityCount = static_cast<DWORD>(network_capabilities.size());
        caps.Reserved = 0;
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &caps, sizeof(caps), nullptr, nullptr)) {
            rc = static_cast<int>(GetLastError());
            goto detached_cleanup;
        }
    }

    {
        HANDLE inherited[2] = { input, log };
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       inherited, sizeof(inherited), nullptr, nullptr)) {
            rc = static_cast<int>(GetLastError());
            goto detached_cleanup;
        }
    }

    if ((memory_limit_bytes != 0 || cpu_rate_percent_x100 != 0 ||
         active_process_limit != 0 || process_user_time_100ns != 0) && process_mode != 0) {
        rc = ERROR_INVALID_PARAMETER;
        goto detached_cleanup;
    }

    if (process_mode == 0) {
        job = CreateJobObjectW(nullptr, wjob.c_str());
        if (!job) {
            rc = static_cast<int>(GetLastError());
            goto detached_cleanup;
        }
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            rc = ERROR_ALREADY_EXISTS;
            goto detached_cleanup;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = 0;
        if (memory_limit_bytes != 0) {
            if (memory_limit_bytes > static_cast<uint64_t>(std::numeric_limits<SIZE_T>::max())) {
                rc = ERROR_ARITHMETIC_OVERFLOW; goto detached_cleanup;
            }
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = static_cast<SIZE_T>(memory_limit_bytes);
        }
        if (active_process_limit != 0) {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
        }
        if (process_user_time_100ns != 0) {
            if (process_user_time_100ns > static_cast<uint64_t>(std::numeric_limits<LONGLONG>::max())) {
                rc = ERROR_ARITHMETIC_OVERFLOW; goto detached_cleanup;
            }
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(process_user_time_100ns);
        }
        if (limits.BasicLimitInformation.LimitFlags != 0 &&
            !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits))) {
            rc = static_cast<int>(GetLastError()); goto detached_cleanup;
        }
        if (cpu_rate_percent_x100 != 0) {
            if (cpu_rate_percent_x100 > 10000u) {
                rc = ERROR_INVALID_PARAMETER; goto detached_cleanup;
            }
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
            cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpu.CpuRate = cpu_rate_percent_x100;
            if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation,
                                         &cpu, sizeof(cpu))) {
                rc = static_cast<int>(GetLastError()); goto detached_cleanup;
            }
        }
    }

    {
        std::vector<wchar_t> mutable_command = command;
        DWORD flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP;
        if (identity_mode == 1) {
            rc = create_restricted_primary_token(&restricted_token);
            if (rc != 0) goto detached_cleanup;
            if (!CreateProcessAsUserW(restricted_token, wprogram.c_str(), mutable_command.data(),
                                      nullptr, nullptr, TRUE, flags, env.data(),
                                      wcwd.c_str(), &si.StartupInfo, &pi)) {
                rc = static_cast<int>(GetLastError());
                goto detached_cleanup;
            }
        } else {
            if (!CreateProcessW(wprogram.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
                                flags, env.data(), wcwd.c_str(), &si.StartupInfo, &pi)) {
                rc = static_cast<int>(GetLastError());
                goto detached_cleanup;
            }
        }
    }

    CloseHandle(input);
    input = nullptr;
    CloseHandle(log);
    log = nullptr;

    if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
        rc = static_cast<int>(GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        pi.hThread = nullptr;
        pi.hProcess = nullptr;
        goto detached_cleanup;
    }

    *pid_out = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    pi.hThread = nullptr;
    pi.hProcess = nullptr;
    rc = 0;

detached_cleanup:
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (input) CloseHandle(input);
    if (log) CloseHandle(log);
    if (job) CloseHandle(job);
    if (restricted_token) CloseHandle(restricted_token);
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    free_owned_sids(owned_capability_sids);
    if (app_sid) FreeSid(app_sid);
    if (rc != 0 && log_path) DeleteFileW(wlog.c_str());
    return rc;
}
#endif

extern "C" int ake_query_process(uint32_t pid, int *running, int *exit_code) {
    if (!pid || !running) {
#ifdef _WIN32
        return ERROR_INVALID_PARAMETER;
#else
        return 2;
#endif
    }
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process) return static_cast<int>(GetLastError());
    DWORD code = STILL_ACTIVE;
    if (!GetExitCodeProcess(process, &code)) {
        DWORD e = GetLastError();
        CloseHandle(process);
        return static_cast<int>(e);
    }
    if (code == STILL_ACTIVE) {
        *running = 1;
        if (exit_code) *exit_code = 0;
    } else {
        *running = 0;
        if (exit_code) *exit_code = static_cast<int>(code <= 0x7FFFFFFFu ? code : 0x7FFFFFFF);
    }
    CloseHandle(process);
    return 0;
#else
    (void)pid; (void)exit_code;
    *running = 0;
    return 3;
#endif
}

extern "C" int ake_terminate_job_or_process(const char *job_name, uint32_t pid) {
#ifdef _WIN32
    if (job_name && *job_name) {
        std::wstring wjob;
        int rc = utf8_wide(job_name, wjob);
        if (rc != 0) return rc;
        HANDLE job = OpenJobObjectW(JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY, FALSE, wjob.c_str());
        if (job) {
            BOOL ok = TerminateJobObject(job, 0xC000013A);
            DWORD e = ok ? ERROR_SUCCESS : GetLastError();
            CloseHandle(job);
            if (ok) return 0;
            return static_cast<int>(e);
        }
    }
    if (!pid) return ERROR_INVALID_PARAMETER;
    HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return static_cast<int>(GetLastError());
    BOOL ok = TerminateProcess(process, 0xC000013A);
    DWORD e = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(process);
    return static_cast<int>(e);
#else
    (void)job_name; (void)pid;
    return 3;
#endif
}

extern "C" int ake_spawn_isolated_process(
    const char *program, const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8, size_t environment_size,
    const char *container_name, int filesystem_mode, int process_mode,
    int network_mode,
    int identity_mode,
    uint64_t memory_limit_bytes, uint32_t cpu_rate_percent_x100,
    uint32_t active_process_limit, uint64_t process_user_time_100ns,
    int *exit_code) {
    if (exit_code) *exit_code = 0;
#ifdef _WIN32
    return spawn_impl(program, arguments, working_directory,
                      environment_block_utf8, environment_size,
                      container_name, filesystem_mode, process_mode, network_mode, identity_mode,
                      memory_limit_bytes, cpu_rate_percent_x100, active_process_limit,
                      process_user_time_100ns, exit_code);
#else
    (void)program; (void)arguments; (void)working_directory;
    (void)environment_block_utf8; (void)environment_size;
    (void)container_name; (void)filesystem_mode; (void)process_mode; (void)network_mode; (void)identity_mode;
    (void)memory_limit_bytes; (void)cpu_rate_percent_x100;
    (void)active_process_limit; (void)process_user_time_100ns;
    return 3;
#endif
}

extern "C" int ake_spawn_isolated_process_detached(
    const char *program, const char *arguments,
    const char *working_directory,
    const unsigned char *environment_block_utf8, size_t environment_size,
    const char *container_name, int filesystem_mode, int process_mode,
    int network_mode, int identity_mode,
    uint64_t memory_limit_bytes, uint32_t cpu_rate_percent_x100,
    uint32_t active_process_limit, uint64_t process_user_time_100ns,
    const char *job_name, const char *log_path, uint32_t *pid_out) {
#ifdef _WIN32
    if (pid_out) *pid_out = 0;
    return spawn_detached_impl(program, arguments, working_directory,
                               environment_block_utf8, environment_size,
                               container_name, filesystem_mode, process_mode, network_mode, identity_mode,
                               memory_limit_bytes, cpu_rate_percent_x100,
                               active_process_limit, process_user_time_100ns,
                               job_name, log_path, pid_out);
#else
    (void)program; (void)arguments; (void)working_directory;
    (void)environment_block_utf8; (void)environment_size;
    (void)container_name; (void)filesystem_mode; (void)process_mode; (void)network_mode; (void)identity_mode;
    (void)memory_limit_bytes; (void)cpu_rate_percent_x100;
    (void)active_process_limit; (void)process_user_time_100ns;
    (void)job_name; (void)log_path; (void)pid_out;
    return 3;
#endif
}

