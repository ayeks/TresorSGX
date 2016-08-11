#include <linux/module.h>
//#include <linux/init.h>	
//#include <linux/kmod.h>	
#include <linux/kernel.h>	
#include <linux/string.h>	

/* Crypto API */
#include <linux/crypto.h>

#define BLOCK_SIZE (16) //in bytes

unsigned char test_plain_text[64] =   {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
										0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
										0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
										0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

unsigned char test_key_128[16] =      {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

void printCharAsHex(const unsigned char mem[], int count) {
   int i, k = 0;
    char hexbyte[11] = "";
    char hexline[126] = "";
    for (i=0; i<count; i++) { // traverse through mem
    	sprintf(hexbyte, "0x%02X|", mem[i]); // add current byte to hexbyte
        strcat(hexline, hexbyte); // add hexbyte to hexline
        // print line every 16 bytes or if this is the last for loop
        if ((((i)%15 == 0) && (i != 0)) || (i+1==count)) { 
            k++;
            //printf("%d: %s",k , hexline); // print line to console
            //syslog(LOG_INFO, "%d: %s",k , hexline); // print line to syslog
            printk(KERN_INFO "test_tresor_lkm: l%d: %s",k , hexline); // print line to kernellog
            memset(&hexline[0], 0, sizeof(hexline)); // clear array
        }
    }
}

int test128(struct crypto_cipher *tfm, unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks * BLOCK_SIZE;
	unsigned int i;
	unsigned char testVector[buffer_size];
	unsigned char testResult[buffer_size];

	printk(KERN_INFO "test_tresor_lkm: buffer_size: %d numBlocks: %d BLOCK_SIZE: %d\n", buffer_size, numBlocks, BLOCK_SIZE);

	// Init the test vector and the test result
	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	printCharAsHex(testVector, 16);
	
	printk(KERN_INFO "test_tresor_lkm: Call crypto_cipher_encrypt_one ...\n");
	crypto_cipher_encrypt_one(tfm, testResult, testVector);

	printCharAsHex(testResult, 16);

	// decrypt


	printk(KERN_INFO "test_tresor_lkm: Call crypto_cipher_decrypt_one ...\n");
	crypto_cipher_decrypt_one(tfm, testVector, testResult);


	printCharAsHex(testVector, 16);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			return 1;
		}
	}
	printk(KERN_INFO "test_tresor_lkm: Call crypto_cipher_decrypt_one ...\n");
	return 0;
}

static int __init tresor_test_init( void )
{
	int key_len;
	int ret;
	struct crypto_cipher *tfm;

	char *cipherName = "tresorsgx";
	//char *cipherName = "aes";

	printk(KERN_INFO "test_tresor_lkm: Entering: %s\n", __FUNCTION__);

	ret = -EFAULT;

	// run algorithm tests of the crypto API testmgr:
	// only works if kernel is patched with tresorsgx vectors (which are copied from aes..)
	ret = alg_test("ecb(tresorsgx)","ecb(tresorsgx)",0,0);
	printk(KERN_INFO "test_tresor_lkm: ecb(tresorsgx): %d\n", ret);

	ret = alg_test("cbc(tresorsgx)","cbc(tresorsgx)",0,0);
	printk(KERN_INFO "test_tresor_lkm: cbc(tresorsgx): %d\n", ret);


	// run own test vectors
	printk(KERN_INFO "test_tresor_lkm: test tresorsgx tfm");

	tfm = NULL;
	tfm = crypto_alloc_cipher(cipherName, 0, BLOCK_SIZE);
	if (tfm == NULL || IS_ERR(tfm)) {
		printk(KERN_ERR "test_tresor_lkm: could not allocate cipher handle for %s\n", cipherName);
		return 0;
	}

  	key_len = BLOCK_SIZE;

  	// set key
	if (crypto_cipher_setkey(tfm, test_key_128, key_len)) {
		printk(KERN_ERR "test_tresor_lkm: could not set key");
		return 0;
	}
	printk(KERN_INFO "test_tresor_lkm: run 1 block(s):  AES-128..\n");

	// test crypto
	ret = test128(tfm, 1);
	if (ret == 0) {
		printk(KERN_INFO "test_tresor_lkm: 1 block(s):  AES-128: PASS\n");
	} else {
		printk(KERN_INFO "test_tresor_lkm: 1 block(s):  AES-128: FAIL: %d\n", ret);
	}

	// free cipher handle
	crypto_free_cipher(tfm);
	
	
	printk(KERN_INFO "test_tresor_lkm: ended successfully\n");
	return 0;
}
 
static void __exit tresor_test_exit( void )
{
	printk(KERN_INFO "test_tresor_lkm: Entering: %s\n", __FUNCTION__);
}


module_init( tresor_test_init );
module_exit( tresor_test_exit );


MODULE_LICENSE("GPL");
