#include <stdio.h>
#include <../include/sgx_urts.h>
#include "Enclave/tresorencl_u.h"
#include <limits.h>

#include <inttypes.h> //uchar

#include "tresorcommon.h"


#define BLOCK_SIZE (16) //in bytes

/*unsigned char test_plain_text[64] =   {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
										0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
										0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
										0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

unsigned char test_key_128[16] =      {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
*/

unsigned char test_key_128[16] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
unsigned char test_plain_text[16]	= "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";


/*
	 Ocall functions
*/
void enclavePrintf(const char *str)
{
    printf("\nEnclave print: %s", str);
}

void enclavePrintInt(const int *num)
{
    printf(": %d ", *num);
}

void enclavePrintHex(const char *mem, int count) {
	int i, k = 0;
	char hexbyte[8];
	char hexline[200] = ""; // 16byte per line a 5 byte text = 80
	for (i=0; i<count; i++) { // traverse through mem
		sprintf(hexbyte, "0x%02X|", (unsigned char) mem[i]); // add current byte to hexbyte
		strcat(hexline, hexbyte); // add hexbyte to hexline
		// print line every 16 bytes or if this is the last for loop
		if (((i)%16 == 0) && (i != 0) || (i+1==count)) { 
			k++;
			printf("%d: %s\n",k , hexline); // print line to console
			//syslog(LOG_INFO, "l%d: %s",k , hexline); // print line to syslog
			//printk(KERN_INFO, "%d: %s",k , hexline); // print line to kernellog
			memset(&hexline[0], 0, sizeof(hexline)); // clear array
		}
	}
}

int test128(sgx_enclave_id_t eid, unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks * BLOCK_SIZE;
	unsigned int i;
	unsigned char testVector[buffer_size];
	unsigned char testResult[buffer_size];
	unsigned char local_test_iv[BLOCK_SIZE];

	int ret;

	printf("buffer_size: %d numBlocks: %d BLOCK_SIZE: %d\n", buffer_size, numBlocks, BLOCK_SIZE);
	// Init the test vector and the test result
	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	enclavePrintHex(testVector, 16);
	enclavePrintHex(testResult, 16);

	ret = enclEncrypt (eid, testVector, buffer_size, testResult, buffer_size);
	if ( SGX_SUCCESS != ret )
		printf( "Error calling enclave\n (error 0x%x)\n", ret );

	printf("Post Encrypt plain -> cipher:\n");
	enclavePrintHex(testVector, 16);
	enclavePrintHex(testResult, 16);
	
	ret = enclDecrypt(eid, testResult, buffer_size, testVector, buffer_size);
		if ( SGX_SUCCESS != ret )
			printf( "Error calling enclave\n (error 0x%x)\n", ret );


	printf("Post Decrypt cipher -> plain:\n");
	enclavePrintHex(testResult, 16);
	enclavePrintHex(testVector, 16);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			printf("%d",i);
			return TRESOR_FAIL;
		}
	}

	return TRESOR_OK;
}


int load_file(char const* path, unsigned char *buf, long *buf_length)
{
    long length;
    FILE * f = fopen (path, "rb"); //was "rb"
    if (!f)
    {
      return TRESOR_SEALFILE_NOTAVAILABLE;
    }
	fseek (f, 0, SEEK_END);
	length = ftell (f);
	fseek (f, 0, SEEK_SET);
	unsigned char buffer[length];
	fread (buffer, sizeof(unsigned char), length, f);
	fclose (f);

    memcpy(buf_length, &length, sizeof(length));
    memcpy(buf, buffer, length);
    return TRESOR_OK;
}


int write_file(char const* path, unsigned char *data, int length) {
	FILE *file = fopen(path, "w");
	int ret = fwrite(data, sizeof(unsigned char), length, file);
	if (ret != length) {
	    printf("write_file: Error %d\n", ret);
	}
	fclose(file);
	return TRESOR_OK;
}


int initCrypto(sgx_enclave_id_t eid, char *key, int key_len) {
	printf("initCrypto: run..");
	sgx_status_t ret = SGX_SUCCESS;
	/* Use crypto without sealed salt */
	ret = enclInitCrypto(eid, 0, key, key_len);
	if ( SGX_SUCCESS != ret )
		printf( "Error calling enclInitCrypto\n (error 0x%x)\n", ret );
}

int initSealedCrypto(sgx_enclave_id_t eid, char *key, int key_len, char const* path) {
	printf("initSealedCrypto: run..");
	sgx_status_t ret = SGX_SUCCESS;

	/* Use crypto with sealed salt */
	unsigned char blob[SEAL_MAX_BLOB_SIZE] = { 0 };
	unsigned char sealedBlob[SEAL_MAX_BLOB_SIZE] = { 0 };
	int blob_len, seal_len;
	blob_len = SEAL_MAX_BLOB_SIZE;
	uint32_t i, pwerr;
	seal_len = 0;

	// try loading sealed blob
	long *buf_length_long = 0; 
	ret = load_file(path, sealedBlob, &buf_length_long);


	if (ret == TRESOR_SEALFILE_NOTAVAILABLE) {
		printf("initSealedCrypto: no seal available: load_fil returned %d", ret);
		ret = enclInitSealedCrypto(eid, &pwerr, 0, key, key_len, blob, blob_len, &seal_len);
		if ( SGX_SUCCESS != ret ) {			
			printf( "enclInitSealedCryptoealedCrypto: SGX error: (error 0x%x)\n", ret );
			return ret;
		}
		if (pwerr != TRESOR_OK) {
		    printf("initSealedCrypto: Crypto error: %#x\n", pwerr);
		    return ret;
		}
		memcpy(sealedBlob, blob, seal_len);
		write_file(path,sealedBlob,seal_len);
	} else {
		printf("initSealedCrypto: seal is available: load_fil returned %d", ret);
		seal_len = buf_length_long; // TODO: long to int parsing with error cases
		ret = enclInitSealedCrypto(eid, &pwerr, 0, key, key_len, sealedBlob, seal_len, &seal_len);
		if ( SGX_SUCCESS != ret ) {
			printf( "initSealedCrypto: SGX error: (error 0x%x)\n", ret );
			return ret;
		}
		if (pwerr != TRESOR_OK) {
		    printf("initSealedCrypto: Crypto error: %#x\n", pwerr);
		    return ret;
		}	
	}
}

int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
	printf("TOKEN: %x\n", token);
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	sgx_status_t ret = SGX_SUCCESS;
	unsigned int input, output;
	
	ret = sgx_create_enclave( enclavefilepath, DEBUG_ENCLAVE, &token, &updated, &eid, NULL );

	if ( SGX_SUCCESS != ret) {
		printf("Error creating enclave (error 0x%x)\n", ret); // check sgx_error.h of Intel SGX SDK
		printf("Check sgx_error.h of Intel SGX SDK! Check if the paths are correctly set in tresorcommon.h!");
		return -1;
	}

  	int key_len = 16;

  	if (SEALED_CRYPTO == 1) {
	  	// set crypto key
	  	initSealedCrypto(eid, test_key_128, key_len, sealfilepath);
  	} else {
		initCrypto(eid, test_key_128, key_len);
  	}
	// crypto test
  	printf("1 block(s):  AES-128: %s",(test128(eid, 1) != TRESOR_OK) ? "FAIL" : "PASS");


	if ( SGX_SUCCESS != (ret = sgx_destroy_enclave( eid ) ) )
	{
		printf( "Error destroying enclave (error 0x%x)\n", ret );
		return -3;
	}
	
	return 1;
}

