#define AC_VERBOSE 0  //設1除錯

#include <Windows.h>
#include <stdio.h>
#include "lazy_importer.h"
#include <stdint.h>
#include <string.h>

#pragma comment(linker, "/merge:.rdata=.text")

const volatile DWORD oep = 0xdeadbabe;
const volatile DWORD k0  = 0xA1B2C3D4, k1 = 0x9A8B7C6D, k2 = 0x11223344, k3 = 0x55667788;
const volatile DWORD iv0 = 0xCAFEBABE, iv1= 0xFEEDFACE, iv2= 0x0D15EA5E, iv3= 0xC0DEC0DE;

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

// big-endian 128-bit counter++
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
        if (!memcmp(sec[i].Name, ".text", 5)) {
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
