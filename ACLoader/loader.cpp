#define AC_VERBOSE 0  //設1除錯

#include <Windows.h>
#include <stdio.h>
#include "lazy_importer.h"
#include <stdint.h>
#include <string.h>

#pragma comment(linker, "/merge:.rdata=.text")
// 建一個自訂唯讀段.acsec，最後再合併進.text
#pragma section(".acsec", read)
#pragma comment(linker, "/merge:.acsec=.text")
// bytes_cmp：手搓的memcmp
static inline int bytes_cmp(const void* a, const void* b, size_t n){
    const unsigned char* p = (const unsigned char*)a;
    const unsigned char* q = (const unsigned char*)b;
    for(size_t i=0;i<n;++i){
        unsigned char x=p[i], y=q[i];
        if(x!=y) return (x<y)?-1:1;
    }
    return 0;
}
static inline bool is_text_name(const char name[8]){
    return name[0]=='.' && name[1]=='t' && name[2]=='e' && name[3]=='x' && name[4]=='t';
}
const volatile DWORD oep = 0xdeadbabe;
const volatile DWORD k0  = 0xA1B2C3D4, k1 = 0x9A8B7C6D, k2 = 0x11223344, k3 = 0x55667788;
const volatile DWORD iv0 = 0xCAFEBABE, iv1= 0xFEEDFACE, iv2= 0x0D15EA5E, iv3= 0xC0DEC0DE;
// 32B SHA-256 佔位符(不與KEY_TAGS/IV_TAGS重複，避免被packer提前覆寫)
// 這8個DWORD會在打包最後被整檔雜湊值覆寫
__declspec(allocate(".acsec"))
const DWORD g_sha256_expected[8] = {
    0x714C8F21, 0xA39D52EE, 0x5BE0CD7A, 0xC4F1A893,
    0x2911D4BF, 0x8E7720CA, 0xF0B5C6D3, 0x63AA19E4
};
static inline void gather16_le(uint8_t out[16], DWORD a, DWORD b, DWORD c, DWORD d) {
    memcpy(out + 0,  &a, 4);
    memcpy(out + 4,  &b, 4);
    memcpy(out + 8,  &c, 4);
    memcpy(out + 12, &d, 4);
}

// bcrypt動態載入型別
typedef PVOID  BCRYPT_ALG_HANDLE;
typedef PVOID  BCRYPT_KEY_HANDLE;
typedef NTSTATUS (WINAPI *BCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *BCryptSetProperty_t)(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptGetProperty_t)(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *BCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptEncrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *BCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *BCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);

static const wchar_t AES_ALG[]     = L"AES";
static const wchar_t PROP_CHAIN[]  = L"ChainingMode";
static const wchar_t MODE_ECB[]    = L"ChainingModeECB";
static const wchar_t PROP_OBJLEN[] = L"ObjectLength";
static const wchar_t SHA256_ALG[]  = L"SHA256";
static const wchar_t PROP_HASHLEN[] = L"HashDigestLength";

// bcrypt 雜湊函式 typedef（動態解析）
typedef NTSTATUS (WINAPI *BCryptCreateHash_t)(BCRYPT_ALG_HANDLE, PVOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptHashData_t)(PVOID, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptFinishHash_t)(PVOID, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptDestroyHash_t)(PVOID);

static inline void incr_be_128(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; --i) { if (++ctr[i] != 0) break; }
}

// 用AES-ECB產生keystream的CTR
static bool aes128_ctr_crypt_inplace(uint8_t* buf, SIZE_T len,
                                     const uint8_t key[16], const uint8_t iv[16]) {
    HMODULE hb = LI_FN(LoadLibraryW)(L"bcrypt.dll");
    if (!hb) return false;

    auto pOpen   = (BCryptOpenAlgorithmProvider_t) LI_FN(GetProcAddress)(hb, "BCryptOpenAlgorithmProvider");
    auto pSet    = (BCryptSetProperty_t)          LI_FN(GetProcAddress)(hb, "BCryptSetProperty");
    auto pGet    = (BCryptGetProperty_t)          LI_FN(GetProcAddress)(hb, "BCryptGetProperty");
    auto pGenKey = (BCryptGenerateSymmetricKey_t) LI_FN(GetProcAddress)(hb, "BCryptGenerateSymmetricKey");
    auto pEnc    = (BCryptEncrypt_t)              LI_FN(GetProcAddress)(hb, "BCryptEncrypt");
    auto pDesKey = (BCryptDestroyKey_t)           LI_FN(GetProcAddress)(hb, "BCryptDestroyKey");
    auto pClose  = (BCryptCloseAlgorithmProvider_t)LI_FN(GetProcAddress)(hb, "BCryptCloseAlgorithmProvider");
    if (!pOpen || !pSet || !pGet || !pGenKey || !pEnc || !pDesKey || !pClose) return false;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR keyObj = NULL;
    DWORD objLen = 0, cb = 0;
    NTSTATUS st = 0;

    st = pOpen(&hAlg, AES_ALG, NULL, 0);
    if (st) goto cleanup;

    st = pSet(hAlg, PROP_CHAIN, (PUCHAR)MODE_ECB, (ULONG)sizeof(MODE_ECB), 0);
    if (st) goto cleanup;

    st = pGet(hAlg, PROP_OBJLEN, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (st || !objLen) goto cleanup;

    keyObj = (PUCHAR)LI_FN(VirtualAlloc)((LPVOID)nullptr, (SIZE_T)objLen, (DWORD)(MEM_COMMIT|MEM_RESERVE), (DWORD)PAGE_READWRITE);
    if (!keyObj) { st = (NTSTATUS)1; goto cleanup; }
    st = pGenKey(hAlg, &hKey, keyObj, objLen, (PUCHAR)key, 16, 0);
    if (st) goto cleanup;

    {
        uint8_t counter[16]; memcpy(counter, iv, 16);
        uint8_t ks[16]; ULONG produced = 0;
        SIZE_T off = 0;
        while (off < len) {
            st = pEnc(hKey, (PUCHAR)counter, 16, NULL, NULL, 0, ks, 16, &produced, 0);
            if (st || produced != 16) goto cleanup;
            SIZE_T chunk = (len - off) < 16 ? (len - off) : 16;
            for (SIZE_T i = 0; i < chunk; ++i) buf[off + i] ^= ks[i];
            off += chunk;
            incr_be_128(counter);
        }
    }

    st = 0;
cleanup:
    if (hKey)   pDesKey(hKey);
    if (keyObj) LI_FN(VirtualFree)((LPVOID)keyObj, (SIZE_T)0, (DWORD)MEM_RELEASE);
    if (hAlg)   pClose(hAlg, 0);
    return st == 0;
}
static bool rva_to_file_off(ULONG rva, BYTE* base, ULONGLONG* out_off) {
    auto dos = (PIMAGE_DOS_HEADER)base;
#if defined(_WIN64)
    auto nt  = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
#else
    auto nt  = (PIMAGE_NT_HEADERS32)(base + dos->e_lfanew);
#endif
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections;
    for (WORD i=0; i<n; ++i, ++sec) {
        ULONG va  = sec->VirtualAddress;
        ULONG raw = sec->PointerToRawData;
        ULONG sz  = sec->SizeOfRawData;
        if (rva >= va && rva < va + sz) {
            *out_off = (ULONGLONG)raw + (rva - va);
            return true;
        }
    }
    return false;
}

// 以CNG(SHA-256)對兩段資料做雜湊（用bcrypt.dll動態載入）
static bool sha256_hash_segments(PUCHAR seg1, ULONG seg1_len,
                                 PUCHAR seg2, ULONG seg2_len,
                                 PUCHAR out32) {
    HMODULE hb = LI_FN(LoadLibraryW)(L"bcrypt.dll");
    if (!hb) return false;
    auto pOpen   = (BCryptOpenAlgorithmProvider_t) LI_FN(GetProcAddress)(hb, "BCryptOpenAlgorithmProvider");
    auto pGet    = (BCryptGetProperty_t)          LI_FN(GetProcAddress)(hb, "BCryptGetProperty");
    auto pCreate = (BCryptCreateHash_t)           LI_FN(GetProcAddress)(hb, "BCryptCreateHash");
    auto pHash   = (BCryptHashData_t)             LI_FN(GetProcAddress)(hb, "BCryptHashData");
    auto pFinish = (BCryptFinishHash_t)           LI_FN(GetProcAddress)(hb, "BCryptFinishHash");
    auto pDesH   = (BCryptDestroyHash_t)          LI_FN(GetProcAddress)(hb, "BCryptDestroyHash");
    auto pClose  = (BCryptCloseAlgorithmProvider_t)LI_FN(GetProcAddress)(hb, "BCryptCloseAlgorithmProvider");
    if (!pOpen || !pGet || !pCreate || !pHash || !pFinish || !pDesH || !pClose) return false;

    PVOID hAlg = nullptr, hHash = nullptr;
    DWORD cb=0, objLen=0, hashLen=0;
    PUCHAR obj = nullptr;
    NTSTATUS st = 0;
    if ((st = pOpen((BCRYPT_ALG_HANDLE*)&hAlg, SHA256_ALG, nullptr, 0))) goto cleanup;
    if ((st = pGet(hAlg, PROP_OBJLEN,  (PUCHAR)&objLen,  sizeof(objLen),  &cb, 0)) || !objLen) goto cleanup;
    if ((st = pGet(hAlg, PROP_HASHLEN, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0)) || hashLen != 32) goto cleanup;
    obj = (PUCHAR)LI_FN(VirtualAlloc)(nullptr, objLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!obj) { st = 1; goto cleanup; }
    if ((st = pCreate(hAlg, &hHash, obj, objLen, nullptr, 0, 0))) goto cleanup;
    if (seg1 && seg1_len) if ((st = pHash(hHash, seg1, seg1_len, 0))) goto cleanup;
    if (seg2 && seg2_len) if ((st = pHash(hHash, seg2, seg2_len, 0))) goto cleanup;
    if ((st = pFinish(hHash, out32, hashLen, 0))) goto cleanup;
    st = 0;
cleanup:
    if (hHash) pDesH(hHash);
    if (obj)   LI_FN(VirtualFree)(obj, 0, MEM_RELEASE);
    if (hAlg)  pClose((BCRYPT_ALG_HANDLE)hAlg, 0);
    return st == 0;
}

// 啟動前驗證自身檔案完整性（整檔雜湊，略過 32B 佔位符）
static bool verify_self_integrity_before_unpack() {
    HMODULE hMod = LI_FN(GetModuleHandleW)((LPCWSTR)nullptr);
    BYTE*   base = (BYTE*)hMod;
    // 期望值位址->RVA->檔內位移
    const BYTE* expected = (const BYTE*)g_sha256_expected;
    ULONG rva = (ULONG)(expected - base);
    ULONGLONG file_off = 0;
    if (!rva_to_file_off(rva, base, &file_off)) return false;

    // 自身路徑
    wchar_t path[MAX_PATH];
    if (!LI_FN(GetModuleFileNameW)(hMod, path, MAX_PATH)) return false;

    // 映射檔案為唯讀，便於一次性雜湊
    HANDLE hFile = LI_FN(CreateFileW)(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER liSize;
    if (!LI_FN(GetFileSizeEx)(hFile, &liSize)) { LI_FN(CloseHandle)(hFile); return false; }
    HANDLE hMap = LI_FN(CreateFileMappingW)(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { LI_FN(CloseHandle)(hFile); return false; }
    BYTE* map = (BYTE*)LI_FN(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!map) { LI_FN(CloseHandle)(hMap); LI_FN(CloseHandle)(hFile); return false; }

    UCHAR digest[32];
    bool ok = sha256_hash_segments(
        map, (ULONG)file_off,
        map + file_off + 32, (ULONG)(liSize.QuadPart - (file_off + 32)),
        digest);
    LI_FN(UnmapViewOfFile)(map);
    LI_FN(CloseHandle)(hMap);
    LI_FN(CloseHandle)(hFile);
    if (!ok) return false;
    return bytes_cmp((const void*)g_sha256_expected, digest, 32) == 0;
}

extern "C" void ac_load() {
    auto msvcrtLib = LI_FN(LoadLibraryA)("msvcrt.dll");
    auto printf_f  = LI_FN(printf).in(msvcrtLib);
    #define LOG(...) do { printf_f(__VA_ARGS__); } while(0)

    // 可切換的除錯輸出
    #if AC_VERBOSE
      #define DBG(...) LOG(__VA_ARGS__)
    #else
      #define DBG(...) do {} while(0)
    #endif

    auto base = LI_FN(GetModuleHandleA)((LPCSTR)NULL);
    LOG("Loading! Base at '0x%llx'\n", (ULONGLONG)base);
    if (!verify_self_integrity_before_unpack()) {
        LOG("[L] integrity check FAILED, exiting.\n");
        LI_FN(ExitProcess)(0);
    }

    // 找出.text的RVA/SizeOfRawData
    auto dos = (PIMAGE_DOS_HEADER)base;
#if defined(_WIN64)
    auto nt  = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
#else
    auto nt  = (PIMAGE_NT_HEADERS32)((BYTE*)base + dos->e_lfanew);
#endif
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    DWORD text_rva = 0, text_raw_sz = 0;
    for (WORD i=0; i<nt->FileHeader.NumberOfSections; ++i) {
        if (is_text_name((const char*)sec[i].Name)) {            
            text_rva    = sec[i].VirtualAddress;
            text_raw_sz = sec[i].SizeOfRawData;
            break;
        }
    }

    DBG("[L] oep=0x%lx\n", (DWORD)oep);
    DBG("[L] .text rva=0x%lx size(raw)=0x%lx\n", text_rva, text_raw_sz);

    uint8_t KEY[16], IV[16];
    gather16_le(KEY, (DWORD)k0, (DWORD)k1, (DWORD)k2, (DWORD)k3);
    gather16_le(IV,  (DWORD)iv0,(DWORD)iv1,(DWORD)iv2,(DWORD)iv3);

    if (text_rva && text_raw_sz) {
        uint8_t* text = (uint8_t*)base + text_rva;

        DBG("[L] first8(before): %02X %02X %02X %02X %02X %02X %02X %02X\n",
            text[0],text[1],text[2],text[3],text[4],text[5],text[6],text[7]);

        DWORD oldProt = 0, tmp = 0;
        LI_FN(VirtualProtect)(text, text_raw_sz, PAGE_EXECUTE_READWRITE, &oldProt);

        bool ok = aes128_ctr_crypt_inplace(text, text_raw_sz, KEY, IV);
        DBG("[L] decrypt: %s\n", ok ? "ok" : "FAIL");

        LI_FN(FlushInstructionCache)(LI_FN(GetCurrentProcess)(), text, text_raw_sz);
        LI_FN(VirtualProtect)(text, text_raw_sz, oldProt, &tmp);

        DBG("[L] first8(after):  %02X %02X %02X %02X %02X %02X %02X %02X\n",
            text[0],text[1],text[2],text[3],text[4],text[5],text[6],text[7]);

        SecureZeroMemory(KEY, sizeof(KEY));
        SecureZeroMemory(IV,  sizeof(IV));
    } else {
        DBG("[L] ERROR: .text not found\n");
    }

    ULONG_PTR jmp = (ULONG_PTR)base + (ULONG_PTR)oep;
    DBG("[L] jmp -> 0x%llx\n", (unsigned long long)jmp);
    ((void (*)())jmp)();
}
