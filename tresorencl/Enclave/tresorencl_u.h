#ifndef TRESORENCL_U_H__
#define TRESORENCL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, enclavePrintf, (const char* string));
void SGX_UBRIDGE(SGX_NOCONVENTION, enclavePrintInt, (const int* num));
void SGX_UBRIDGE(SGX_NOCONVENTION, enclavePrintHex, (const char* output, int len));

sgx_status_t enclInitCrypto(sgx_enclave_id_t eid, char algorithm, unsigned char* key, size_t key_len);
sgx_status_t enclInitSealedCrypto(sgx_enclave_id_t eid, uint32_t* retval, char algorithm, unsigned char* key, int key_len, unsigned char* buf, int buf_len, int* seal_len);
sgx_status_t enclEncrypt(sgx_enclave_id_t eid, unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);
sgx_status_t enclDecrypt(sgx_enclave_id_t eid, unsigned char* in, size_t in_len, unsigned char* out, size_t out_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
