/* ******************************
 *      DIRECTORIES
 * ****************************** */

char *enclavefilepath = "/PATH_TO_/TresorSGX/tresorencl/Enclave/tresorencl.so"; // TODO modify me
char *sealfilepath = "/PATH_TO_/seals/sealedBlob.txt";  // TODO modify me
char *setkey_pipename = "/tmp/tresorsgxsetkey";

#define usermodehelper_daemon "/opt/tresorsgx/tresord"
#define usermodehelper_home "HOME=/usr/bin"


/* ******************************
 *      Tresor COMMON
 * ****************************** */

#define DEBUG_ENCLAVE       (1) // starts SGX enclave in debugmode if set
#define SEALED_CRYPTO       (1) // enables usage of sealed salt
#define SETKEY_BYPIPE       (0) // daemon opens a pipe for key setting
#define STARTDAEMON_BY_LKM  (0) // the daemon is started using the usermode on lkm launch

#define SEAL_MAX_BLOB_SIZE  1024 // sealed blob maximum size

/* Tresor Error codes */
/* Dont use 0x[0-5]00[0-F] because they are used by SGX*/ 
enum {
    TRESOR_OK =                     0x0000,
    TRESOR_FAIL =                   0x0001, // generic error
    TRESOR_SEALBUF_TOO_SMALL =      0x0010, // in enclave seal buffer to small for sealed object
    TRESOR_BLOB_INVALID =           0x0020, // in enclave blob did not decrypt or was truncated
    TRESOR_SGX_RAND_FAILURE =       0x0030, // in enclave sgx_read_rand failed
    TRESOR_SGX_SEAL_FAILURE =       0x0040, // in enclave sgx_seal_data failed
    TRESOR_SEALFILE_NOTAVAILABLE =  0x0050, // sealfile cant be loaded
    TRESOR_SEALFILE_WRITEFAIL =     0x0060, // error during sealfile write
    TRESOR_DAEMON_EXIT =            0x0070, // exit daemon netlink receive loop
    TRESOR_NL_NODAEMON_REGISTERED = 0x0080, // no daemon registered at lkm, dont now whom to send msg
    TRESOR_NL_FAILED_MSG_CREATION = 0x0090, // genlmsg creation failed
    TRESOR_NL_FAILED_UNICAST =      0x00A0, // unicast went wrong
    TRESOR_NL_IS_NULL =             0x00B0, // Netlink info is null
};


enum aes_algorithm {
    AES_128_BLK,
    AES_192_BLK,   
    AES_256_BLK,   
    AES_128_CTR,   // not used but supported by sgx crypto
    AES_192_CTR,   // not used but supported by sgx crypto
    AES_256_CTR,   // not used but supported by sgx crypto
    AES_128_CBC,   // not used but supported by sgx crypto
    AES_192_CBC,   // not used but supported by sgx crypto
    AES_256_CBC    // not used but supported by sgx crypto
};


/* ******************************
 *      NETLINK COMMON
 * ****************************** */

#define TRESOR_NL_FAMILY_NAME "TRESOR_NETLINK"

struct tresor_nl_msg {
    unsigned int operation;
    unsigned int text_len;
    char text[32];
};

enum {
    DEMO_ATTR1_STRING = 1,
    TRESOR_NL_ATTR1_MSG,
    __TRESOR_NL_ATTR_MAX,
};

#define TRESOR_NL_ATTR_MAX (__TRESOR_NL_ATTR_MAX)


enum {
    TRESOR_NL_CMD = 1,
};

#define TRESOR_NL_VERSION 1 // Tresor Netlink Interface Version Number

// Netlink Message operation types
enum {
    TRESOR_MSG_EXITDAEMON,
    TRESOR_MSG_REGISTER,
    TRESOR_MSG_SAVEKEY,
    TRESOR_MSG_ENCRYPT,
    TRESOR_MSG_DECRYPT
};