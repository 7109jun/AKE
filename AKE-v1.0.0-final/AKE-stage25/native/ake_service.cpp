#include "ake_service.h"
#include "ake_isolation.h"
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include <cctype>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>

static std::wstring wstr(const char *s){ if(!s)return L""; int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,nullptr,0); if(n<=0)return L""; std::vector<wchar_t> b((size_t)n); if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s,-1,b.data(),n)<=0)return L""; return std::wstring(b.data()); }
static void seterr(char *e,size_t n,const char *m){ if(e&&n){std::strncpy(e,m?m:"service error",n-1);e[n-1]='\0';} }
static const wchar_t* account_name(int mode){
    switch(mode){case 0:return L"NT AUTHORITY\\LocalService";case 1:return L"NT AUTHORITY\\NetworkService";case 2:return L"LocalSystem";default:return nullptr;}
}
static DWORD start_type(int mode){switch(mode){case 0:return SERVICE_AUTO_START;case 1:return SERVICE_DEMAND_START;case 2:return SERVICE_DISABLED;default:return 0;}}
static int validate_name(const char *n){if(!n||!*n)return ERROR_INVALID_NAME;std::string s(n);if(s.size()>80)return ERROR_INVALID_NAME;for(unsigned char c:s)if(!(std::isalnum(c)||c=='_'||c=='-'||c=='.'))return ERROR_INVALID_NAME;return 0;}

static DWORD clamp_failure_delay(uint64_t value){ return value>0xFFFFFFFFull?0xFFFFFFFFu:(DWORD)value; }
int ake_service_install(const char *name,const char *display_name,const char *description,const char *binary_path,int start_mode,int account_mode,int restart_mode,uint32_t restart_retries,uint32_t restart_delay_ms,uint32_t restart_backoff,uint32_t restart_reset_sec,char *error,size_t error_size){
    int vn=validate_name(name); if(vn){seterr(error,error_size,"invalid service name");return vn;}
    const wchar_t *acct=account_name(account_mode); if(!acct){seterr(error,error_size,"invalid service account");return ERROR_INVALID_PARAMETER;}
    DWORD st=start_type(start_mode); if(st==0){seterr(error,error_size,"invalid service start mode");return ERROR_INVALID_PARAMETER;}
    std::wstring wn=wstr(name),wd=wstr(display_name&&*display_name?display_name:name),wb=wstr(binary_path); if(wn.empty()||wd.empty()||wb.empty()){seterr(error,error_size,"invalid UTF-8 service value");return ERROR_NO_UNICODE_TRANSLATION;}
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE); if(!scm){DWORD e=GetLastError();seterr(error,error_size,"cannot open Service Control Manager");return (int)e;}
    SC_HANDLE svc=CreateServiceW(scm,wn.c_str(),wd.c_str(),SERVICE_CHANGE_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP|DELETE,SERVICE_WIN32_OWN_PROCESS,st,SERVICE_ERROR_NORMAL,wb.c_str(),nullptr,nullptr,nullptr,acct,nullptr);
    if(!svc){DWORD e=GetLastError(); if(e==ERROR_SERVICE_EXISTS){svc=OpenServiceW(scm,wn.c_str(),SERVICE_CHANGE_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP|DELETE); if(svc){ChangeServiceConfigW(svc,SERVICE_NO_CHANGE,st,SERVICE_NO_CHANGE,wb.c_str(),nullptr,nullptr,nullptr,acct,nullptr,wd.c_str());} } if(!svc){CloseServiceHandle(scm);seterr(error,error_size,"cannot create or open Windows service");return (int)e;}}
    if(description&&*description){std::wstring desc=wstr(description); SERVICE_DESCRIPTIONW sd{};sd.lpDescription=const_cast<LPWSTR>(desc.c_str());if(!ChangeServiceConfig2W(svc,SERVICE_CONFIG_DESCRIPTION,&sd)){DWORD e=GetLastError();seterr(error,error_size,"cannot set Windows service description");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}}
    if(restart_mode<0||restart_mode>2||restart_retries>32||restart_delay_ms<100||restart_backoff<1||restart_backoff>10){seterr(error,error_size,"invalid service restart policy");CloseServiceHandle(svc);CloseServiceHandle(scm);return ERROR_INVALID_PARAMETER;}
    if(restart_mode==0){
        SERVICE_FAILURE_ACTIONS reset{};
        if(!ChangeServiceConfig2W(svc,SERVICE_CONFIG_FAILURE_ACTIONS,&reset)){DWORD e=GetLastError();seterr(error,error_size,"cannot clear Windows service failure actions");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}
        SERVICE_FAILURE_ACTIONS_FLAG flag{};flag.fFailureActionsOnNonCrashFailures=FALSE;
        if(!ChangeServiceConfig2W(svc,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,&flag)){DWORD e=GetLastError();seterr(error,error_size,"cannot clear Windows service failure-action policy");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}
    }else{
        const uint32_t count=restart_retries;
        std::vector<SC_ACTION> actions; actions.reserve(count);
        uint64_t delay=restart_delay_ms;
        for(uint32_t i=0;i<count;i++){SC_ACTION a{};a.Type=SC_ACTION_RESTART;a.Delay=clamp_failure_delay(delay);actions.push_back(a);delay*=restart_backoff;if(delay>0xFFFFFFFFull)delay=0xFFFFFFFFull;}
        SERVICE_FAILURE_ACTIONSW fa{};fa.dwResetPeriod=restart_reset_sec;fa.cActions=count;fa.lpsa=actions.empty()?nullptr:actions.data();
        if(!ChangeServiceConfig2W(svc,SERVICE_CONFIG_FAILURE_ACTIONS,&fa)){DWORD e=GetLastError();seterr(error,error_size,"cannot set Windows service failure actions");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}
        SERVICE_FAILURE_ACTIONS_FLAG flag{};flag.fFailureActionsOnNonCrashFailures=(restart_mode==2)?TRUE:FALSE;
        if(!ChangeServiceConfig2W(svc,SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,&flag)){DWORD e=GetLastError();seterr(error,error_size,"cannot set Windows service failure-action policy");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}
    }
    CloseServiceHandle(svc);CloseServiceHandle(scm);return 0;
}
int ake_service_delete(const char *name,char *error,size_t error_size){
    std::wstring wn=wstr(name); if(wn.empty()){seterr(error,error_size,"invalid service name");return ERROR_INVALID_NAME;}
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm){seterr(error,error_size,"cannot open Service Control Manager");return (int)GetLastError();}
    SC_HANDLE svc=OpenServiceW(scm,wn.c_str(),SERVICE_STOP|SERVICE_QUERY_STATUS|DELETE);if(!svc){DWORD e=GetLastError();CloseServiceHandle(scm);if(e==ERROR_SERVICE_DOES_NOT_EXIST)return 0;seterr(error,error_size,"cannot open service");return (int)e;}
    SERVICE_STATUS st{}; ControlService(svc,SERVICE_CONTROL_STOP,&st); BOOL ok=DeleteService(svc);DWORD e=ok?ERROR_SUCCESS:GetLastError();CloseServiceHandle(svc);CloseServiceHandle(scm);if(e!=ERROR_SUCCESS&&e!=ERROR_SERVICE_MARKED_FOR_DELETE){seterr(error,error_size,"cannot delete service");return (int)e;}return 0;
}
int ake_service_start(const char *name,char *error,size_t error_size){std::wstring wn=wstr(name);if(wn.empty())return ERROR_INVALID_NAME;SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm)return (int)GetLastError();SC_HANDLE svc=OpenServiceW(scm,wn.c_str(),SERVICE_START|SERVICE_QUERY_STATUS);if(!svc){DWORD e=GetLastError();CloseServiceHandle(scm);seterr(error,error_size,"cannot open service");return (int)e;}if(!StartServiceW(svc,0,nullptr)){DWORD e=GetLastError();if(e!=ERROR_SERVICE_ALREADY_RUNNING){seterr(error,error_size,"cannot start service");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}}CloseServiceHandle(svc);CloseServiceHandle(scm);return 0;}
int ake_service_stop(const char *name,char *error,size_t error_size){std::wstring wn=wstr(name);if(wn.empty())return ERROR_INVALID_NAME;SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm)return (int)GetLastError();SC_HANDLE svc=OpenServiceW(scm,wn.c_str(),SERVICE_STOP|SERVICE_QUERY_STATUS);if(!svc){DWORD e=GetLastError();CloseServiceHandle(scm);seterr(error,error_size,"cannot open service");return (int)e;}SERVICE_STATUS st{};if(!ControlService(svc,SERVICE_CONTROL_STOP,&st)){DWORD e=GetLastError();if(e!=ERROR_SERVICE_NOT_ACTIVE){seterr(error,error_size,"cannot stop service");CloseServiceHandle(svc);CloseServiceHandle(scm);return (int)e;}}CloseServiceHandle(svc);CloseServiceHandle(scm);return 0;}
int ake_service_query(const char *name,char *state,size_t state_size,uint32_t *pid,char *error,size_t error_size){if(state&&state_size)state[0]='\0';if(pid)*pid=0;std::wstring wn=wstr(name);if(wn.empty())return ERROR_INVALID_NAME;SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm)return (int)GetLastError();SC_HANDLE svc=OpenServiceW(scm,wn.c_str(),SERVICE_QUERY_STATUS);if(!svc){DWORD e=GetLastError();CloseServiceHandle(scm);if(e==ERROR_SERVICE_DOES_NOT_EXIST)return 2;seterr(error,error_size,"cannot open service");return (int)e;}SERVICE_STATUS_PROCESS sp{};DWORD got=0;BOOL ok=QueryServiceStatusEx(svc,SC_STATUS_PROCESS_INFO,reinterpret_cast<LPBYTE>(&sp),sizeof(sp),&got);DWORD e=ok?0:GetLastError();CloseServiceHandle(svc);CloseServiceHandle(scm);if(!ok){seterr(error,error_size,"cannot query service status");return (int)e;}const char *s="unknown";switch(sp.dwCurrentState){case SERVICE_STOPPED:s="stopped";break;case SERVICE_START_PENDING:s="start-pending";break;case SERVICE_STOP_PENDING:s="stop-pending";break;case SERVICE_RUNNING:s="running";break;case SERVICE_CONTINUE_PENDING:s="continue-pending";break;case SERVICE_PAUSE_PENDING:s="pause-pending";break;case SERVICE_PAUSED:s="paused";break;}if(state&&state_size){std::strncpy(state,s,state_size-1);state[state_size-1]='\0';}if(pid)*pid=sp.dwProcessId;return 0;}

struct ServiceCtx{std::wstring service;std::string program,args,cwd,container,job;std::vector<unsigned char> env;int filesystem,process,network,identity,restart;uint64_t memory;uint32_t cpu,procs;uint64_t time;};
static ServiceCtx *g_ctx=nullptr;static SERVICE_STATUS_HANDLE g_handle=nullptr;static std::atomic<bool> g_stop(false);static std::atomic<DWORD> g_result_code(ERROR_SUCCESS);
static void report(DWORD state,DWORD win32=NO_ERROR,DWORD controls=0){SERVICE_STATUS s{};s.dwServiceType=SERVICE_WIN32_OWN_PROCESS;s.dwCurrentState=state;s.dwWin32ExitCode=win32;s.dwControlsAccepted=controls;s.dwWaitHint=5000;SetServiceStatus(g_handle,&s);}
static void WINAPI svc_ctrl(DWORD code){if(code==SERVICE_CONTROL_STOP||code==SERVICE_CONTROL_SHUTDOWN){g_stop.store(true);if(g_ctx){ake_terminate_job_or_process(g_ctx->job.c_str(),0);}report(SERVICE_STOP_PENDING,NO_ERROR,0);}}
static void WINAPI svc_main(DWORD argc,LPWSTR *argv){(void)argc;(void)argv;g_handle=RegisterServiceCtrlHandlerW(g_ctx?g_ctx->service.c_str():L"AKE",svc_ctrl);if(!g_handle){g_result_code.store(ERROR_FUNCTION_FAILED);return;}report(SERVICE_START_PENDING);uint32_t pid=0;int rc=ake_spawn_isolated_process_detached(g_ctx->program.c_str(),g_ctx->args.c_str(),g_ctx->cwd.c_str(),g_ctx->env.data(),g_ctx->env.size(),g_ctx->container.c_str(),g_ctx->filesystem,g_ctx->process,g_ctx->network,g_ctx->identity,g_ctx->memory,g_ctx->cpu,g_ctx->procs,g_ctx->time,g_ctx->job.c_str(),nullptr,&pid);if(rc!=0||pid==0){DWORD fail=rc?static_cast<DWORD>(rc):ERROR_GEN_FAILURE;g_result_code.store(fail);report(SERVICE_STOPPED,fail,0);return;}report(SERVICE_RUNNING,SUCCESS,SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN);for(;;){if(g_stop.load())break;int running=0,code=0;int q=ake_query_process(pid,&running,&code);if(q!=0){g_result_code.store(static_cast<DWORD>(q));return;}if(!running){DWORD child_code=code==0?ERROR_SUCCESS:static_cast<DWORD>(code);g_result_code.store(child_code);if(child_code!=ERROR_SUCCESS||g_ctx->restart==2){return;}report(SERVICE_STOPPED,ERROR_SUCCESS,0);return;}Sleep(500);}g_result_code.store(ERROR_SUCCESS);report(SERVICE_STOPPED,ERROR_SUCCESS,0);}
int ake_service_host(const char *service_name,const char *program,const char *arguments,const char *working_directory,const unsigned char *environment_block_utf8,size_t environment_size,const char *container_name,int filesystem_mode,int process_mode,int network_mode,int identity_mode,uint64_t memory_limit_bytes,uint32_t cpu_rate_percent_x100,uint32_t active_process_limit,uint64_t process_user_time_100ns,const char *job_name,int restart_mode){
    if(!service_name||!program||!working_directory||!container_name||!job_name||restart_mode<0||restart_mode>2)return ERROR_INVALID_PARAMETER;static ServiceCtx ctx;ctx.service=wstr(service_name);ctx.program=program;ctx.args=arguments?arguments:"";ctx.cwd=working_directory;ctx.container=container_name;ctx.job=job_name;ctx.filesystem=filesystem_mode;ctx.process=process_mode;ctx.network=network_mode;ctx.identity=identity_mode;ctx.restart=restart_mode;ctx.memory=memory_limit_bytes;ctx.cpu=cpu_rate_percent_x100;ctx.procs=active_process_limit;ctx.time=process_user_time_100ns;ctx.env.assign(environment_block_utf8,environment_block_utf8+(environment_size?environment_size:0));g_stop.store(false);g_result_code.store(ERROR_SUCCESS);g_ctx=&ctx;SERVICE_TABLE_ENTRYW table[2]={{const_cast<LPWSTR>(ctx.service.c_str()),svc_main},{nullptr,nullptr}};if(!StartServiceCtrlDispatcherW(table)){return (int)GetLastError();}return (int)g_result_code.load();}
#else
static void ign(char*,size_t){}
int ake_service_install(const char*,const char*,const char*,const char*,int,int,int,uint32_t,uint32_t,uint32_t,uint32_t,char*e,size_t n){ign(e,n);return 3;} int ake_service_delete(const char*,char*e,size_t n){ign(e,n);return 3;} int ake_service_start(const char*,char*e,size_t n){ign(e,n);return 3;} int ake_service_stop(const char*,char*e,size_t n){ign(e,n);return 3;} int ake_service_query(const char*,char*,size_t,uint32_t*,char*e,size_t n){ign(e,n);return 3;} int ake_service_host(const char*,const char*,const char*,const char*,const unsigned char*,size_t,const char*,int,int,int,int,uint64_t,uint32_t,uint32_t,uint64_t,const char*,int){return 3;}
#endif
