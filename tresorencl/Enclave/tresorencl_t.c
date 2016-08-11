#include "tresorencl_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_enclInitCrypto(void* pms)
{
	ms_enclInitCrypto_t* ms = SGX_CAST(ms_enclInitCrypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	size_t _tmp_key_len = ms->ms_key_len;
	size_t _len_key = _tmp_key_len;
	unsigned char* _in_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclInitCrypto_t));
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_key != NULL) {
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	enclInitCrypto(ms->ms_algorithm, _in_key, _tmp_key_len);
err:
	if (_in_key) free(_in_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclInitSealedCrypto(void* pms)
{
	ms_enclInitSealedCrypto_t* ms = SGX_CAST(ms_enclInitSealedCrypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	int _tmp_key_len = ms->ms_key_len;
	size_t _len_key = _tmp_key_len;
	unsigned char* _in_key = NULL;
	unsigned char* _tmp_buf = ms->ms_buf;
	int _tmp_buf_len = ms->ms_buf_len;
	size_t _len_buf = _tmp_buf_len;
	unsigned char* _in_buf = NULL;
	int* _tmp_seal_len = ms->ms_seal_len;
	size_t _len_seal_len = sizeof(*_tmp_seal_len);
	int* _in_seal_len = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclInitSealedCrypto_t));
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);
	CHECK_UNIQUE_POINTER(_tmp_seal_len, _len_seal_len);

	if (_tmp_key != NULL) {
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	if (_tmp_buf != NULL) {
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	if (_tmp_seal_len != NULL) {
		if ((_in_seal_len = (int*)malloc(_len_seal_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_seal_len, 0, _len_seal_len);
	}
	ms->ms_retval = enclInitSealedCrypto(ms->ms_algorithm, _in_key, _tmp_key_len, _in_buf, _tmp_buf_len, _in_seal_len);
err:
	if (_in_key) free(_in_key);
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}
	if (_in_seal_len) {
		memcpy(_tmp_seal_len, _in_seal_len, _len_seal_len);
		free(_in_seal_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclEncrypt(void* pms)
{
	ms_enclEncrypt_t* ms = SGX_CAST(ms_enclEncrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_in = ms->ms_in;
	size_t _tmp_in_len = ms->ms_in_len;
	size_t _len_in = _tmp_in_len;
	unsigned char* _in_in = NULL;
	unsigned char* _tmp_out = ms->ms_out;
	size_t _tmp_out_len = ms->ms_out_len;
	size_t _len_out = _tmp_out_len;
	unsigned char* _in_out = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclEncrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	if (_tmp_in != NULL) {
		_in_in = (unsigned char*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_in, _tmp_in, _len_in);
	}
	if (_tmp_out != NULL) {
		if ((_in_out = (unsigned char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	enclEncrypt(_in_in, _tmp_in_len, _in_out, _tmp_out_len);
err:
	if (_in_in) free(_in_in);
	if (_in_out) {
		memcpy(_tmp_out, _in_out, _len_out);
		free(_in_out);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclDecrypt(void* pms)
{
	ms_enclDecrypt_t* ms = SGX_CAST(ms_enclDecrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_in = ms->ms_in;
	size_t _tmp_in_len = ms->ms_in_len;
	size_t _len_in = _tmp_in_len;
	unsigned char* _in_in = NULL;
	unsigned char* _tmp_out = ms->ms_out;
	size_t _tmp_out_len = ms->ms_out_len;
	size_t _len_out = _tmp_out_len;
	unsigned char* _in_out = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclDecrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	if (_tmp_in != NULL) {
		_in_in = (unsigned char*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_in, _tmp_in, _len_in);
	}
	if (_tmp_out != NULL) {
		if ((_in_out = (unsigned char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	enclDecrypt(_in_in, _tmp_in_len, _in_out, _tmp_out_len);
err:
	if (_in_in) free(_in_in);
	if (_in_out) {
		memcpy(_tmp_out, _in_out, _len_out);
		free(_in_out);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_enclInitCrypto, 0},
		{(void*)(uintptr_t)sgx_enclInitSealedCrypto, 0},
		{(void*)(uintptr_t)sgx_enclEncrypt, 0},
		{(void*)(uintptr_t)sgx_enclDecrypt, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL enclavePrintf(const char* string)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_string = string ? strlen(string) + 1 : 0;

	ms_enclavePrintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintf_t);
	void *__tmp = NULL;

	ocalloc_size += (string != NULL && sgx_is_within_enclave(string, _len_string)) ? _len_string : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintf_t));

	if (string != NULL && sgx_is_within_enclave(string, _len_string)) {
		ms->ms_string = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_string);
		memcpy((void*)ms->ms_string, string, _len_string);
	} else if (string == NULL) {
		ms->ms_string = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL enclavePrintInt(const int* num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_num = sizeof(*num);

	ms_enclavePrintInt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintInt_t);
	void *__tmp = NULL;

	ocalloc_size += (num != NULL && sgx_is_within_enclave(num, _len_num)) ? _len_num : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintInt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintInt_t));

	if (num != NULL && sgx_is_within_enclave(num, _len_num)) {
		ms->ms_num = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_num);
		memcpy((void*)ms->ms_num, num, _len_num);
	} else if (num == NULL) {
		ms->ms_num = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL enclavePrintHex(const char* output, int len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_output = len;

	ms_enclavePrintHex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintHex_t);
	void *__tmp = NULL;

	ocalloc_size += (output != NULL && sgx_is_within_enclave(output, _len_output)) ? _len_output : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintHex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintHex_t));

	if (output != NULL && sgx_is_within_enclave(output, _len_output)) {
		ms->ms_output = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_output);
		memcpy((void*)ms->ms_output, output, _len_output);
	} else if (output == NULL) {
		ms->ms_output = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

