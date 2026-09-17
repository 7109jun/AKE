#include "ake_crypto.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>
#include <algorithm>

static void set_error(char *error, size_t error_size, const char *msg) {
    if (!error || !error_size) return;
    std::strncpy(error, msg ? msg : "crypto error", error_size - 1);
    error[error_size - 1] = '\0';
}

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

static int read_file(const char *path, std::vector<unsigned char> &out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return 1;
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    if (n < 0 || n > 1024 * 1024) return 2;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(n));
    if (!out.empty() && !f.read(reinterpret_cast<char *>(out.data()), n)) return 3;
    return 0;
}

static int write_file(const char *path, const std::vector<unsigned char> &data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return 1;
    if (!data.empty()) f.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    return f ? 0 : 2;
}

extern "C" int ake_crypto_generate_keypair(const char *private_path, const char *public_path, char *error, size_t error_size) {
    if (!private_path || !*private_path || !public_path || !*public_path) { set_error(error, error_size, "invalid key output path"); return 2; }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (st < 0) { set_error(error, error_size, "BCryptOpenAlgorithmProvider failed"); return 3; }
    st = BCryptGenerateKeyPair(alg, &key, 256, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "BCryptGenerateKeyPair failed"); return 4; }
    st = BCryptFinalizeKeyPair(key, 0);
    if (st < 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "BCryptFinalizeKeyPair failed"); return 5; }

    ULONG private_size = 0, public_size = 0;
    st = BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &private_size, 0);
    if (st < 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "private key export size failed"); return 6; }
    st = BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &public_size, 0);
    if (st < 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "public key export size failed"); return 7; }
    std::vector<unsigned char> priv(private_size), pub(public_size);
    st = BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, priv.data(), private_size, &private_size, 0);
    if (st < 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "private key export failed"); return 8; }
    st = BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, pub.data(), public_size, &public_size, 0);
    if (st < 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "public key export failed"); return 9; }
    priv.resize(private_size);
    pub.resize(public_size);
    if (write_file(private_path, priv) != 0 || write_file(public_path, pub) != 0) {
        std::remove(private_path); std::remove(public_path);
        BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0);
        set_error(error, error_size, "cannot write generated key files"); return 10;
    }
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}

extern "C" int ake_crypto_sign_digest(const char *private_path, const unsigned char digest[32], unsigned char *signature, size_t signature_capacity, size_t *signature_size, char *error, size_t error_size) {
    if (signature_size) *signature_size = 0;
    if (!private_path || !*private_path || !digest || !signature || !signature_size) { set_error(error, error_size, "invalid signing arguments"); return 2; }
    std::vector<unsigned char> blob;
    if (read_file(private_path, blob) != 0) { set_error(error, error_size, "cannot read private key"); return 3; }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (st < 0) { set_error(error, error_size, "BCryptOpenAlgorithmProvider failed"); return 4; }
    st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &key, blob.data(), static_cast<ULONG>(blob.size()), 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "invalid ECDSA private key"); return 5; }
    ULONG needed = 0;
    st = BCryptSignHash(key, nullptr, const_cast<PUCHAR>(digest), 32, nullptr, 0, &needed, 0);
    if (st < 0 || needed == 0) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "signature size query failed"); return 6; }
    if (needed > signature_capacity) { BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "signature buffer too small"); return 7; }
    ULONG actual = 0;
    st = BCryptSignHash(key, nullptr, const_cast<PUCHAR>(digest), 32, signature, static_cast<ULONG>(signature_capacity), &actual, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0) { set_error(error, error_size, "BCryptSignHash failed"); return 8; }
    *signature_size = actual;
    return 0;
}

extern "C" int ake_crypto_verify_digest(const unsigned char *public_blob, size_t public_blob_size, const unsigned char digest[32], const unsigned char *signature, size_t signature_size, char *error, size_t error_size) {
    if (!public_blob || !public_blob_size || !digest || !signature || !signature_size) { set_error(error, error_size, "invalid verification arguments"); return 2; }
    if (public_blob_size > 1024 * 1024 || signature_size > 4096) { set_error(error, error_size, "key or signature is too large"); return 3; }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (st < 0) { set_error(error, error_size, "BCryptOpenAlgorithmProvider failed"); return 4; }
    st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, const_cast<PUCHAR>(public_blob), static_cast<ULONG>(public_blob_size), 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); set_error(error, error_size, "invalid ECDSA public key"); return 5; }
    st = BCryptVerifySignature(key, nullptr, const_cast<PUCHAR>(digest), 32, const_cast<PUCHAR>(signature), static_cast<ULONG>(signature_size), 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0) { set_error(error, error_size, "signature verification failed"); return 6; }
    return 0;
}

extern "C" const char *ake_crypto_version(void) { return "AKE-Crypto/1.0-Windows-CNG-ECDSA-P256-SHA256"; }

#else
extern "C" int ake_crypto_generate_keypair(const char *, const char *, char *error, size_t error_size) { set_error(error, error_size, "AKE cryptographic signing requires a Windows build"); return 100; }
extern "C" int ake_crypto_sign_digest(const char *, const unsigned char[32], unsigned char *, size_t, size_t *signature_size, char *error, size_t error_size) { if (signature_size) *signature_size = 0; set_error(error, error_size, "AKE cryptographic signing requires a Windows build"); return 100; }
extern "C" int ake_crypto_verify_digest(const unsigned char *, size_t, const unsigned char[32], const unsigned char *, size_t, char *error, size_t error_size) { set_error(error, error_size, "AKE cryptographic verification requires a Windows build"); return 100; }
extern "C" const char *ake_crypto_version(void) { return "AKE-Crypto/1.0-unavailable"; }
#endif
