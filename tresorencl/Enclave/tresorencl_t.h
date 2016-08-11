#ifndef TRESORENCL_T_H__
#define TRESORENCL_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void enclInitCrypto(char algorithm, unsigned char* key, size_t key_len);
uint32_t enclInitSealedCrypto(char algorithm, unsigned char* key, int key_len, unsigned char* buf, int buf_len, int* seal_len);
void enclEncrypt(unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);
void enclDecrypt(unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);

sgx_status_t SGX_CDECL enclavePrintf(const char* string);
sgx_status_t SGX_CDECL enclavePrintInt(const int* num);
sgx_status_t SGX_CDECL enclavePrintHex(const char* output, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
