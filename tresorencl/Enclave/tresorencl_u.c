#include "tresorencl_u.h"
#include <errno.h>

typedef struct ms_enclInitCrypto_t {
	char ms_algorithm;
	unsigned char* ms_key;
	size_t ms_key_len;
} ms_enclInitCrypto_t;

typedef struct ms_enclInitSealedCrypto_t {
	uint32_t ms_retval;
	char ms_algorithm;
	unsigned char* ms_key;
	int ms_key_len;
	unsigned char* ms_buf;
	int ms_buf_len;
	int* ms_seal_len;
} ms_enclInitSealedCrypto_t;

typedef struct ms_enclEncrypt_t {
	unsigned char* ms_in;
	size_t ms_in_len;
	unsigned char* ms_out;
	size_t ms_out_len;
} ms_enclEncrypt_t;

typedef struct ms_enclDecrypt_t {
	unsigned char* ms_in;
	size_t ms_in_len;
	unsigned char* ms_out;
	size_t ms_out_len;
} ms_enclDecrypt_t;

typedef struct ms_enclavePrintf_t {
	char* ms_string;
} ms_enclavePrintf_t;

typedef struct ms_enclavePrintInt_t {
	int* ms_num;
} ms_enclavePrintInt_t;

typedef struct ms_enclavePrintHex_t {
	char* ms_output;
	int ms_len;
} ms_enclavePrintHex_t;

static sgx_status_t SGX_CDECL tresorencl_enclavePrintf(void* pms)
{
	ms_enclavePrintf_t* ms = SGX_CAST(ms_enclavePrintf_t*, pms);
	enclavePrintf((const char*)ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tresorencl_enclavePrintInt(void* pms)
{
	ms_enclavePrintInt_t* ms = SGX_CAST(ms_enclavePrintInt_t*, pms);
	enclavePrintInt((const int*)ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tresorencl_enclavePrintHex(void* pms)
{
	ms_enclavePrintHex_t* ms = SGX_CAST(ms_enclavePrintHex_t*, pms);
	enclavePrintHex((const char*)ms->ms_output, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_tresorencl = {
	3,
	{
		(void*)tresorencl_enclavePrintf,
		(void*)tresorencl_enclavePrintInt,
		(void*)tresorencl_enclavePrintHex,
	}
};
sgx_status_t enclInitCrypto(sgx_enclave_id_t eid, char algorithm, unsigned char* key, size_t key_len)
{
	sgx_status_t status;
	ms_enclInitCrypto_t ms;
	ms.ms_algorithm = algorithm;
	ms.ms_key = key;
	ms.ms_key_len = key_len;
	status = sgx_ecall(eid, 0, &ocall_table_tresorencl, &ms);
	return status;
}

sgx_status_t enclInitSealedCrypto(sgx_enclave_id_t eid, uint32_t* retval, char algorithm, unsigned char* key, int key_len, unsigned char* buf, int buf_len, int* seal_len)
{
	sgx_status_t status;
	ms_enclInitSealedCrypto_t ms;
	ms.ms_algorithm = algorithm;
	ms.ms_key = key;
	ms.ms_key_len = key_len;
	ms.ms_buf = buf;
	ms.ms_buf_len = buf_len;
	ms.ms_seal_len = seal_len;
	status = sgx_ecall(eid, 1, &ocall_table_tresorencl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclEncrypt(sgx_enclave_id_t eid, unsigned char* in, size_t in_len, unsigned char* out, size_t out_len)
{
	sgx_status_t status;
	ms_enclEncrypt_t ms;
	ms.ms_in = in;
	ms.ms_in_len = in_len;
	ms.ms_out = out;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 2, &ocall_table_tresorencl, &ms);
	return status;
}

sgx_status_t enclDecrypt(sgx_enclave_id_t eid, unsigned char* in, size_t in_len, unsigned char* out, size_t out_len)
{
	sgx_status_t status;
	ms_enclDecrypt_t ms;
	ms.ms_in = in;
	ms.ms_in_len = in_len;
	ms.ms_out = out;
	ms.ms_out_len = out_len;
	status = sgx_ecall(eid, 3, &ocall_table_tresorencl, &ms);
	return status;
}

