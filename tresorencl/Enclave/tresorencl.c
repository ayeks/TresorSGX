
#include "tresorencl.h"
#include "tresorencl_t.h"

#include "tresorcommon.h"

#include <inttypes.h> //uint8_t

#include "iaesni.h" // intel aesni

/* sealing */
#include "sgx_trts.h"
#include "sgx_tseal.h"

/* pbkdf2 */
#include "pbkdf2.h"
#include "sha2.h"
#include "bitops.h"
#include "handy.h"

#include <string.h>
#include <stdio.h>

char aes_alg_type;
unsigned char aes_key_128[16];
unsigned char aes_key_192[24];
unsigned char aes_key_256[32];

/* This structure is all the data needed for password verification. */
typedef struct
{
#define PWRECORD_VERSION 1
  uint32_t version; // versioning of sealed data
#define PWRECORD_PBKDF2_ITERS 50000
  uint32_t iters;	// number of iterations of PBKDF2
  uint8_t salt[16]; // random salt, generated in enclave
  uint8_t hash[32];	// TODO delete the hash, now its just for debugging purposes
} pwrecord;	// will be saved on hard disc

#define PWRECORD_ENCODING_LEN (4 + 4 + 16 + 32)

/* Zeroes a password record */
static void pwrecord_clean(pwrecord *pwr)
{
  mem_clean(pwr, sizeof *pwr);
}

/* Generates a password record, with a random salt. */
static uint32_t pwrecord_fresh(pwrecord *pwr)
{
  pwr->version = PWRECORD_VERSION;
  pwr->iters = PWRECORD_PBKDF2_ITERS;
  if (sgx_read_rand(pwr->salt, sizeof pwr->salt))
    return TRESOR_SGX_RAND_FAILURE;
  memset(pwr->hash, 0, sizeof pwr->hash);
  return TRESOR_OK;
}

/* Computes a password hash using the parameters in pwr and the given password.
 * Places the result in out. */
static void pwrecord_compute_hash(const pwrecord *pwr, const uint8_t *password, uint32_t pwlen, uint8_t out[32])
{
  cf_pbkdf2_hmac(password, pwlen,	// user password, pw len
                 pwr->salt, sizeof pwr->salt,	// unsealed salt, salt len
                 pwr->iters,	//	 number of iterations
                 out, 32,	// out buffer, out len
                 &cf_sha256); // hash type
}

/* Fills in the hash field of pwr using the given password */
static void pwrecord_init_hash(pwrecord *pwr, const uint8_t *password, uint32_t pwlen)
{
  pwrecord_compute_hash(pwr, password, pwlen, pwr->hash);
}

/* Encodes the contents of pwr into out.
 * 
 * A pwrecord encoding looks like:
 *   version (big endian 32-bit word) currently 1
 *   iters   (big endian 32-bit word) PKBDF2 iterations used
 *   salt    (16 bytes)
 *   hash    (32 bytes)
 */
static void pwrecord_encode(pwrecord *pwr, uint8_t out[PWRECORD_ENCODING_LEN])
{
  write32_be(pwr->version, out);
  out += 4;
  write32_be(pwr->iters, out);
  out += 4;
  memcpy(out, pwr->salt, sizeof pwr->salt);
  out += sizeof pwr->salt;
  memcpy(out, pwr->hash, sizeof pwr->hash);
}

/* Decodes a password record encoding in buf, writing the results into
 * pwr. */
static uint32_t pwrecord_decode(pwrecord *pwr, const uint8_t buf[PWRECORD_ENCODING_LEN])
{
  pwr->version = read32_be(buf + 0);
  pwr->iters = read32_be(buf + 4);
  memcpy(pwr->salt, buf + 8, sizeof pwr->salt);
  memcpy(pwr->hash, buf + 8 + sizeof pwr->salt, sizeof pwr->hash);

  if (pwr->version != PWRECORD_VERSION ||
      pwr->iters == 0)
    return TRESOR_BLOB_INVALID;

  return TRESOR_OK;
}

/* 
 * public init function
 * 	inititalises encryption mode, key, and keylen
 */
void enclInitCrypto(char algorithm, unsigned char *key, size_t key_len) {
	//enclavePrintf("enclInitCrypto: run..");
	//void enclInitCrypto(int algorithm, unsigned char *key, int key_len) {

	aes_alg_type = (enum aes_algorithm) algorithm;
	//TODO: check if keylen matches algorithm type
	if (aes_alg_type == AES_128_BLK) {
		memcpy(aes_key_128, key, key_len);
	} else if (aes_alg_type == AES_192_BLK) {
		memcpy(aes_key_192, key, key_len);
	} else if (aes_alg_type == AES_256_BLK) {
		memcpy(aes_key_256, key, key_len);
	}
}

/* checks if data is complete zero */
int checkzero (unsigned char *data, size_t length) {
    if (length == 0) return 1;
    return memcmp(data, data+1, length-1);
}

/* 
 * public init function with sealed salt
 * 	inititalises encryption mode, key, and keylen
 *	if blob is complete zero:
 *		1. generate new salt
 *		2. seal new pwrecord
 *		3. PBKDF2 
 *		4. Copy hash to aes_key_256
 *		5. save pwrecord in blob, daemon must save the blob
 *	if blob is not complete zero
 *		1. unseal pwrecord
 *		2. PBKDF2
 *		3. Copy hash to aes_key_256
 *		5. blob is not altered
 */
uint32_t  enclInitSealedCrypto(char algorithm, unsigned char* user_key, int user_key_len, unsigned char *blob, int blob_len, int *seal_len) {
	//enclavePrintf("enclInitSealedCrypto: run..");
	pwrecord pwr = { 0 };
  	uint32_t err = TRESOR_OK;
  	int need_len = 0, plain_len = 0, ret = 0;
  	char buf[616]; // TODO blob_len
  	char plain[PWRECORD_ENCODING_LEN] = { 0 };
  	int pwRecordValid = 0;
  	pwRecordValid = 0;

	//enclavePrintInt(blob_len);

	// check if blob is complete zero
	pwRecordValid = checkzero(blob, blob_len);
	//enclavePrintHex(blob, blob_len);

	if (pwRecordValid == 0) {
		// enclavePrintf("enclInitSealedCrypto: 1. generate new pw record");
		// 1. generate new pw record
		err = pwrecord_fresh(&pwr);
  		if (err) return err;
  		// enclavePrintf("enclInitSealedCrypto: 2. seal pwrecord");
  		// 2. seal pwrecord
  		pwrecord_encode(&pwr, plain);
  		need_len = sgx_calc_sealed_data_size(0, PWRECORD_ENCODING_LEN);
  		
  		if (sizeof buf < need_len) {
  			// enclavePrintf("enclInitSealedCrypto: 2. seal pwrecord: Error: buf < need_len)");
    		return TRESOR_SEALBUF_TOO_SMALL;
  		}
		if (sgx_seal_data(0, NULL, PWRECORD_ENCODING_LEN, plain, need_len, (sgx_sealed_data_t *) buf))
			return TRESOR_SGX_SEAL_FAILURE;
		// enclavePrintHex(plain, PWRECORD_ENCODING_LEN);
		// enclavePrintHex(buf, need_len);
	} else {
		// enclavePrintf("enclInitSealedCrypto: 1. unseal pw record");
		// unseal data blob
		plain_len = sizeof plain;
		ret = sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, plain, &plain_len);
		if (ret != 0) {
			enclavePrintf("enclInitSealedCrypto: sgx_unseal_data: error");
			enclavePrintInt(&ret);
			return ret;
		}
		//enclavePrintf("enclInitSealedCrypto: 2.2 decode pwrecord");
		ret = pwrecord_decode(&pwr, plain); ;
		if (ret != 0) {
			//enclavePrintf("enclInitSealedCrypto: 2.2 unseal pwrecord error");
			return ret;
		}
	}

	// enclavePrintf("enclInitSealedCrypto: 3. generate hash aka encryption password");
	// 3. generate hash aka encryption password
	pwrecord_init_hash(&pwr, user_key, user_key_len);

	// enclavePrintf("enclInitSealedCrypto: 4. Copy hash to aes_key_256");
	// 4. Copy hash to aes_key_256
	aes_alg_type = AES_256_BLK;
	memcpy(aes_key_256, pwr.hash, 32);

	//enclavePrintHex(aes_key_256,32);

	// enclavePrintf("enclInitSealedCrypto: 5. save pwrecord in blob");
	// 5. save pwrecord in blob, daemon must save the blob
	memcpy(blob, buf, need_len);
	memcpy(seal_len, &need_len, sizeof(&need_len));

	pwrecord_clean(&pwr);

	return err;
}


/* 
 * public encrypt function
 * 	encrypts only with given plaintext, retreives rest from enclave vars
 */
void enclEncrypt(unsigned char *in, size_t in_len, unsigned char *out, size_t out_len) {
	//enclavePrintf("enclEncrypt: run..");

	// dont encrypt if out is to small to handle data
	// otherwise crypto will trap
	if (out_len < (in_len)) {
		enclavePrintf("enclEncrypt: out_len to small!");
	} else {
	  	// blk crypto
		unsigned long numBlocks = 1; // 16 bit blocks

		if (aes_alg_type == AES_128_BLK) {
			intel_AES_enc128(in, out, aes_key_128, numBlocks);
		} else if (aes_alg_type == AES_192_BLK) {
			intel_AES_enc192(in, out, aes_key_192, numBlocks);
		} else if (aes_alg_type == AES_256_BLK) {
			intel_AES_enc256(in, out, aes_key_256, numBlocks);
		}

	}
	//enclavePrintf("enclEncrypt: return.");
}


/* 
 * public decrypt function
 * 	de only with given ciphertext, retreives IV from the beginning
 */
void enclDecrypt(unsigned char *in, size_t in_len, unsigned char *out, size_t out_len) {
	//enclavePrintf("enclDecrypt: run");

	// dont encrypt if out is to small to handle data
	// otherwise crypto will trap
	if (out_len < (in_len)) {
		enclavePrintf("enclDecrypt: out_len to small!");
		enclavePrintInt((int *)in_len);
		enclavePrintInt((int *)out_len);
	} else {
		// blk crypto
		unsigned long numBlocks = 1; // 16 bit blocks

		if (aes_alg_type == AES_128_BLK) {
			intel_AES_dec128(in, out, aes_key_128, numBlocks);
		} else if (aes_alg_type == AES_192_BLK) {
			intel_AES_dec192(in, out, aes_key_192, numBlocks);
		} else if (aes_alg_type == AES_256_BLK) {
			intel_AES_dec256(in, out, aes_key_256, numBlocks);
		}
	}
	//enclavePrintf("enclDecrypt: return.");
}
