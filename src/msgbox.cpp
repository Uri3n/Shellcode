#include <Windows.h>
#include <stdint.h>
#include "vendor/native_defs.h"


/* Let's not bother with an MSVC ifdef...
 * we can't use that compiler regardless (no x64 inline asm support)
 */
#define ALWAYS_INLINE __attribute__((always_inline)) inline

/* Some hashes... */
#define HASH_K32            914211162U
#define HASH_LOADLIBRARYA   1066379828U
#define HASH_EXITPROCESS    785185407U
#define HASH_MESSAGEBOXA    3673453571U

/* Some type aliases... */
using HashType       = uint32_t;
using pMessageBoxA   = decltype(&::MessageBoxA);
using pLoadLibraryA  = decltype(&::LoadLibraryA);
using pExitProcess   = decltype(&::ExitProcess);

/* Some function prototypes... */
template<typename T>
auto hash_bytes(void* bytes, uint32_t len)         -> HashType;
auto my_strlen(const char* str)                    -> uint32_t;
auto get_module_base(HashType ht)                  -> uint8_t*;
auto get_func_addr(uint8_t *mod_base, HashType ht) -> void*;


asm(
  "__main:                        \n"
  " push rsi                      \n"
  " mov  rsi, rsp                 \n"
  " and  rsp, 0xFFFFFFFFFFFFFFF0  \n"
  " sub  rsp, 0x20                \n"
  " call msgbox_impl              \n"
  " mov  rsp, rsi                 \n"
  " pop  rsi                      \n"
  " ret                           \n"
);

extern "C" int msgbox_impl() {
    char user32_str [] = {'U','S','E','R','3','2','.','D','L','L','\0'};
    char msg_caption[] = {'S','h','e','l','l','c','o','d','e','\0'};
    char msg_text   [] = {'H','e','l','l','o',' ','W','o','r','l','d','\0'};

    pLoadLibraryA pload_lib  = nullptr;
    pExitProcess  pexit_proc = nullptr;
    pMessageBoxA  pmsgbox    = nullptr;
    uint8_t*      pk32       = nullptr;
    uint8_t*      puser32    = nullptr;

    /****************************************************************************************/

    if(pk32 = get_module_base(HASH_K32); pk32 == nullptr) {
        return 1;
    }

    pload_lib  = reinterpret_cast<pLoadLibraryA>(get_func_addr(pk32, HASH_LOADLIBRARYA));
    pexit_proc = reinterpret_cast<pExitProcess>(get_func_addr(pk32, HASH_EXITPROCESS));
    if(!pload_lib || !pexit_proc) {
        return 1;
    }

    if(puser32 = reinterpret_cast<uint8_t*>(pload_lib(user32_str)); puser32 == nullptr) {
        return 1;
    }

    if(pmsgbox = reinterpret_cast<pMessageBoxA>(get_func_addr(puser32, HASH_MESSAGEBOXA)); pmsgbox == nullptr) {
        return 1;
    }

    pmsgbox(nullptr, msg_text, msg_caption, MB_OK | MB_ICONWARNING);
    pexit_proc(0);
}


ALWAYS_INLINE uint32_t
my_strlen(const char* str) {
    const char* str2;
    for (str2 = str; *str2; ++str2) {}
    return str2 - str;
}

template<typename T>
ALWAYS_INLINE HashType hash_bytes(void* bytes, uint32_t len) {
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

ALWAYS_INLINE uint8_t*
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

ALWAYS_INLINE void*
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