#include <stdio.h>
//#include "anti_cheat.h"
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "pe_parser.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <vector>
#include <string.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static bool sha256_hash_segments(const PUCHAR seg1, ULONG seg1_len,
                                 const PUCHAR seg2, ULONG seg2_len,
                                 PUCHAR out32 /*32 bytes*/) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cb = 0, objLen = 0, hashLen = 0;
    PUCHAR hashObj = NULL;
    bool ok = false;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) goto cleanup;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (!NT_SUCCESS(st) || !objLen) goto cleanup;
    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0);
    if (!NT_SUCCESS(st) || hashLen != 32) goto cleanup;

    hashObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objLen);
    if (!hashObj) goto cleanup;
    st = BCryptCreateHash(hAlg, &hHash, hashObj, objLen, NULL, 0, 0);
    if (!NT_SUCCESS(st)) goto cleanup;

    if (seg1 && seg1_len) {
        st = BCryptHashData(hHash, (PUCHAR)seg1, seg1_len, 0);
        if (!NT_SUCCESS(st)) goto cleanup;
    }
    if (seg2 && seg2_len) {
        st = BCryptHashData(hHash, (PUCHAR)seg2, seg2_len, 0);
        if (!NT_SUCCESS(st)) goto cleanup;
    }
    st = BCryptFinishHash(hHash, out32, hashLen, 0);
    if (!NT_SUCCESS(st)) goto cleanup;
    ok = true;
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hashObj) HeapFree(GetProcessHeap(), 0, hashObj);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

void* find_signature(void* data, DWORD size, DWORD signature){
    for (DWORD i = 0; i < size / sizeof(DWORD); i++) {
        if (memcmp((DWORD*)data + i, &signature, sizeof(DWORD)) == 0) {
            return (void*)((DWORD*)data + i);
        }
    }
    return nullptr;
}

static inline void incr_be_128(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; --i) { if (++ctr[i] != 0) break; }
}

// 用AES-ECB產生keystream的CTR
static bool aes128_ctr_encrypt_ecb(uint8_t* buf, DWORD len, const uint8_t key[16], const uint8_t iv[16]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD objLen = 0, cb = 0;
    NTSTATUS st = 0;
    bool ok = false;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st) goto cleanup;
    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_ECB, (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (st) goto cleanup;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (st || !objLen) goto cleanup;

    {
        std::vector<BYTE> keyObj(objLen);
        st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), (ULONG)keyObj.size(), (PUCHAR)key, 16, 0);
        if (st) goto cleanup;

        uint8_t counter[16]; memcpy(counter, iv, 16);
        uint8_t ks[16]; ULONG produced = 0;
        DWORD off = 0;
        while (off < len) {
            // 用ECB將counter加密作為keystream
            st = BCryptEncrypt(hKey, (PUCHAR)counter, 16, NULL, NULL, 0, ks, 16, &produced, 0);
            if (st || produced != 16) goto cleanup;
            DWORD remain = len - off;
            DWORD chunk  = (remain < 16) ? remain : 16;
            for (DWORD i = 0; i < chunk; ++i) buf[off + i] ^= ks[i];
            off += chunk;
            incr_be_128(counter);
        }
        ok = true;
    }
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

int main() {
	PeFile f("../a.exe");
	auto text_sec = f.get_section(".text");
	DWORD orignal_oep = f.get_nt_header()->OptionalHeader.AddressOfEntryPoint;
    // 產生隨機AES Key/IV(每次打包不同)
    uint8_t AES_KEY[16], AES_IV[16];
    BCryptGenRandom(NULL, AES_KEY, sizeof(AES_KEY), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, AES_IV,  sizeof(AES_IV),  BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // 加密.text(SizeOfRawData範圍)
    {
        auto& buf = f.get_buffer();
        uint8_t* textraw = (uint8_t*)&buf[text_sec->PointerToRawData];
        DWORD    textsz  = text_sec->SizeOfRawData;
        if (!aes128_ctr_encrypt_ecb(textraw, textsz, AES_KEY, AES_IV)) {
            printf("[!] AES-CTR(ECB) encrypt failed\n");
        } else {
            printf("[*] Encrypted .text: raw_off=0x%08X size=0x%08X\n",
                   text_sec->PointerToRawData, textsz);
        }
    }

    PeFile loader("../x64/Release/ACLoader.exe");
    auto loader_text_sec = loader.get_section(".text");
    f.add_section(".stub", loader.get_buffer().data() + loader_text_sec->PointerToRawData,
        loader_text_sec->SizeOfRawData,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);
	auto stub_sec = f.get_section(".stub");
    f.get_nt_header()->OptionalHeader.AddressOfEntryPoint = stub_sec->VirtualAddress +
        loader.get_nt_header()->OptionalHeader.AddressOfEntryPoint - loader.get_nt_header()->OptionalHeader.BaseOfCode;

    auto oep_sig = find_signature(&f.get_buffer()[stub_sec->PointerToRawData], stub_sec->SizeOfRawData, 0xdeadbabe);
    if (!oep_sig) {
        printf("Can't find oep signature\n");
    }
    else {
        printf("Patching oep\n");
        printf("Original oep: 0x%lx\n", orignal_oep);
        *(DWORD*)oep_sig = orignal_oep;
    }

    // Patch AES Key/IV佔位符
    {
        DWORD* stub = (DWORD*)(&f.get_buffer()[stub_sec->PointerToRawData]);
        DWORD  stub_sz = stub_sec->SizeOfRawData;

        const DWORD KEY_TAGS[4] = { 0xA1B2C3D4, 0x9A8B7C6D, 0x11223344, 0x55667788 };
        const DWORD IV_TAGS [4] = { 0xCAFEBABE, 0xFEEDFACE, 0x0D15EA5E, 0xC0DEC0DE };

        DWORD keyw[4], ivw[4];
        memcpy(&keyw[0], AES_KEY + 0, 4);
        memcpy(&keyw[1], AES_KEY + 4, 4);
        memcpy(&keyw[2], AES_KEY + 8, 4);
        memcpy(&keyw[3], AES_KEY + 12, 4);
        memcpy(&ivw [0], AES_IV  + 0, 4);
        memcpy(&ivw [1], AES_IV  + 4, 4);
        memcpy(&ivw [2], AES_IV  + 8, 4);
        memcpy(&ivw [3], AES_IV  + 12, 4);

        int patched = 0;
        for (int i = 0; i < 4; ++i) {
            void* p = find_signature(stub, stub_sz, KEY_TAGS[i]);
            if (p) { *(DWORD*)p = keyw[i]; ++patched; }
            else   printf("[!] key tag %d not found\n", i);
        }
        for (int i = 0; i < 4; ++i) {
            void* p = find_signature(stub, stub_sz, IV_TAGS[i]);
            if (p) { *(DWORD*)p = ivw[i]; ++patched; }
            else   printf("[!] iv tag %d not found\n", i);
        }
        printf("[*] Patched %d key/iv DWORDs into .stub\n", patched);
    }

    // 對最終輸出檔做SHA-256，略過32B佔位符
    static const uint32_t HASH_TAG[8] = {
        0x714C8F21, 0xA39D52EE, 0x5BE0CD7A, 0xC4F1A893,
        0x2911D4BF, 0x8E7720CA, 0xF0B5C6D3, 0x63AA19E4
    };
    {
        auto &buf = f.get_buffer();
        size_t hash_off = SIZE_MAX;
        // 在整個檔案緩衝區中尋找 32B 連續序列
        for (size_t i = 0; i + 32 <= buf.size(); ++i) {
            if (memcmp(buf.data() + i, HASH_TAG, 32) == 0) { hash_off = i; break; }
        }
        if (hash_off == SIZE_MAX) {
            printf("[!] hash placeholder not found in stub (did you add it in loader.cpp?)\n");
        } else {
            uint8_t digest[32];
            const PUCHAR seg1 = (PUCHAR)buf.data();
            ULONG seg1_len = (ULONG)hash_off;
            const PUCHAR seg2 = (PUCHAR)(buf.data() + hash_off + 32);
            ULONG seg2_len = (ULONG)(buf.size() - (hash_off + 32));
            if (!sha256_hash_segments(seg1, seg1_len, seg2, seg2_len, digest)) {
                printf("[!] sha256 failed\n");
            } else {
                memcpy(buf.data() + hash_off, digest, 32);
                printf("[*] Wrote SHA-256 at file_off=0x%llx\n", (unsigned long long)hash_off);
            }
        }
    }

	f.save("a.packed.exe");
	return 0;
}