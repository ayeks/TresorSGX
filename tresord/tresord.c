#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
/* netlink */
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
/* common tresor */
#include "tresorcommon.h"
/* sgx */
#include <sgx_urts.h>
#include <tresorencl_u.h>
/* signal */
#include <signal.h>
/* synchronation */
#include <pthread.h>



/* netlink */
static struct nla_policy tresor_nl_gnl_policy[TRESOR_NL_ATTR_MAX + 1] =
{
  [DEMO_ATTR1_STRING] = {.type = NLA_STRING,.maxlen = 256}, // TODO: wont work when without
  [TRESOR_NL_ATTR1_MSG] = { .type = NLA_UNSPEC,.maxlen = sizeof(struct tresor_nl_msg)},
};

// netlink socket - must be global because of usage in signal handler
struct nl_sock * sk;

/* Daemon */ 
pid_t pid, sid;

/* SGX enclave ID */
sgx_enclave_id_t eid;

/* semaphore for all encryption / decryption operations */
pthread_mutex_t mutex_nl;

/* Monitoring variables for debugging purposes */
int mon_nl_cb = 0;			// nl callback calls
int mon_nl_send = 0;		// nl send calls
int mon_nl_cb_fails = 0; 	// nl callback didnt reached end
int mon_nl_send_fails = 0; 	// nl send didnt reached end
int mon_encrypt = 0;		// encrypt calls
int mon_encrypt_fails = 0; 	// encrypt call didnt reached end
int mon_decrypt = 0;		// decrypt calls
int mon_decrypt_fails = 0; 	// decrypt didnt reached end
int mon_setkey = 0;			// setkey calls
int mon_setkey_fails = 0; 	// setkey didnt reached end


/* Enclave Ocall functions */
void enclavePrintf(const char *str)
{
	syslog(LOG_NOTICE, "%d enclavePrintf: %s\n", sid, str);
}


void enclavePrintInt(const int *num)
{
	syslog(LOG_NOTICE, "%d enclavePrintInt: %d\n", sid, *num);
}


void printCharAsHex(const char *mem, int count) {
	int i, k = 0;
	char hexbyte[6];
	char hexline[80] = ""; // 16byte per line a 5 byte text = 80
	for (i=0; i<count; i++) { // traverse through mem
		sprintf(hexbyte, "0x%02X|", (unsigned char) mem[i]); // add current byte to hexbyte
		strcat(hexline, hexbyte); // add hexbyte to hexline
		// print line every 16 bytes or if this is the last for loop
		if ((((i)%15 == 0) && (i != 0)) || (i+1==count)) { 
			k++;
			//printf("%d: %s",k , hexline); // print line to console
			syslog(LOG_INFO, "l%d: %s",k , hexline); // print line to syslog
			//printk(KERN_INFO, "%d: %s",k , hexline); // print line to kernellog
			memset(&hexline[0], 0, sizeof(hexline)); // clear array
		}
	}
}


void enclavePrintHex(const char *mem, int count) {
	printCharAsHex(mem, count);
}


/* send Netlink message to kernel */
void tresor_nl_sendmsg(struct nl_sock *sk, struct tresor_nl_msg tresormsg) {
	mon_nl_send++;
	mon_nl_send_fails++;

	struct nl_msg * msg;
	int id = genl_ctrl_resolve(sk, TRESOR_NL_FAMILY_NAME);
	
	// create a messgae
	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0,  // hdrlen
	                    0,  // flags
	                    TRESOR_NL_CMD, // numeric command identifier
	                    TRESOR_NL_VERSION  // interface version
	                   );

	nla_put(msg, TRESOR_NL_ATTR1_MSG, sizeof(struct tresor_nl_msg), &tresormsg);
	//syslog(LOG_NOTICE, "%d sendNetlinkMsg: to Kernel: %d: Operation: %d, Text: %s, nlh->nlmsg_len: %d, sizeof(msg): %d, strlen(msg.text): %d, sizeof(msg.text): %d\n", sid, nlh->nlmsg_pid, msg.operation, msg.text, nlh->nlmsg_len, sizeof(msg), strlen(msg.text), sizeof(msg.text));

  	nl_send_auto(sk, msg);

  	// cleanup 	
  	nlmsg_free(msg);

  	mon_nl_send_fails--;
}


/* loads file and filelen into buf and buf_length */
int load_file(char const* path, unsigned char *buf, long *buf_length)
{
    long length;
    FILE * f = fopen (path, "rb");
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


/* writes length of data into file */
int write_file(char const* path, unsigned char *data, int length) {
	int ret = TRESOR_OK;
	FILE *file = fopen(path, "w");
	int writeLen = fwrite(data, sizeof(unsigned char), length, file);
	if (writeLen != length) {
	    syslog(LOG_ERR, "%d write_file: Error fwrite: %d\n", sid, writeLen); 
	    ret = TRESOR_SEALFILE_NOTAVAILABLE;
	}
	fclose(file);
	return ret;
}


/* initiates crypto without seal at enclave */
int initCrypto(sgx_enclave_id_t eid, char *key, int key_len) {
	sgx_status_t ret = SGX_SUCCESS;
	char aes_type;
	if (key_len == 16) {
		aes_type = AES_128_BLK;
	} else if (key_len == 24) {
		aes_type = AES_192_BLK;
	} else if (key_len == 32) {
		aes_type = AES_256_BLK;
	}
	ret = enclInitCrypto(eid, aes_type, key, key_len);
	if ( SGX_SUCCESS != ret )
		syslog(LOG_ERR, "%d Error calling enclInitCrypto\n (error 0x%x)\n", sid, ret );

	return ret;
}


/* initiates crypto with seal at enclave */
int initSealedCrypto(sgx_enclave_id_t eid, char *key, int key_len, char const* path) {
	sgx_status_t ret = SGX_SUCCESS;

	/* Use crypto with sealed salt */
	unsigned char blob[SEAL_MAX_BLOB_SIZE] = { 0 };
	unsigned char sealedBlob[SEAL_MAX_BLOB_SIZE] = { 0 };
	int blob_len, seal_len;
	uint32_t i, pwerr;
	seal_len = 0;
	blob_len = SEAL_MAX_BLOB_SIZE;

	// try loading sealed blob
	long *buf_length_long = 0; 
	ret = load_file(path, sealedBlob, &buf_length_long);

	// if seal not available - generate new one
	if (ret == TRESOR_SEALFILE_NOTAVAILABLE) {
		syslog(LOG_NOTICE, "%d initSealedCrypto: no seal available: load_file returned 0x%x", sid, ret);
		ret = enclInitSealedCrypto(eid, &pwerr, 0, key, key_len, blob, blob_len, &seal_len);
		if ( SGX_SUCCESS != ret ) {			
			syslog(LOG_ERR, "%d initSealedCrypto: SGX error: (error 0x%x)\n", sid, ret );
			return ret;
		}
		if (pwerr != TRESOR_OK) {
		    syslog(LOG_ERR, "%d initSealedCrypto: Crypto error: %#x\n", sid, pwerr);
		    return ret;
		}
		memcpy(sealedBlob, blob, seal_len);
		if(TRESOR_OK != write_file(path,sealedBlob,seal_len)) {
			syslog(LOG_ERR, "%d initSealedCrypto: Error during save of new seal - try again or check permissions to dir: %s\n", sid, path);
		}
	} else { // if seal available - use it
		syslog(LOG_NOTICE, "%d initSealedCrypto: seal is available", sid);
		seal_len = buf_length_long; // TODO: long to int parsing with error cases
		ret = enclInitSealedCrypto(eid, &pwerr, 0, key, key_len, sealedBlob, seal_len, &seal_len);
		if ( SGX_SUCCESS != ret ) {
			syslog(LOG_ERR, "%d initSealedCrypto: SGX error: (error 0x%x)\n", sid, ret );
			return ret;
		}
		if (pwerr != TRESOR_OK) {
		    syslog(LOG_ERR, "%d initSealedCrypto: Crypto error: %#x\n", sid, pwerr);
		    return ret;
		}	
	}
}


/* parses incoming messages */
int parseNetlinkMsg(struct tresor_nl_msg msg) {
	int ret;
	ret = TRESOR_OK;
	struct tresor_nl_msg msg_return;

	switch (msg.operation) {
		case TRESOR_MSG_REGISTER:
			// Register ACK from kernel to Daemon, just for information
			syslog(LOG_NOTICE, "%d parseNetlinkMsg: TRESOR_MSG_REGISTER..", sid);
			syslog(LOG_NOTICE, "%d parseNetlinkMsg: Register ACK from Kernel op: %d text: %s", sid, msg.operation, msg.text);
			break;
		case TRESOR_MSG_EXITDAEMON:
			// Exit on this message, currently not implemented
    		syslog(LOG_NOTICE, "%d parseNetlinkMsg: TRESOR_MSG_EXITDAEMON..", sid);
    		ret = TRESOR_DAEMON_EXIT;
			break;
		case TRESOR_MSG_SAVEKEY:
			mon_setkey++;
			mon_setkey_fails++;
			syslog(LOG_NOTICE, "%d parseNetlinkMsg: TRESOR_MSG_SAVEKEY..", sid);
			printCharAsHex(msg.text,msg.text_len); 	// for finding the key in memory

			if (SETKEY_BYPIPE == 0) {
			  	if (SEALED_CRYPTO == 1) {
				  	initSealedCrypto(eid, msg.text, msg.text_len, sealfilepath);
			  	} else {
					initCrypto(eid, msg.text, msg.text_len);
			  	}
			  	syslog(LOG_NOTICE, "%d parseNetlinkMsg: TRESOR_MSG_SAVEKEY clear msg.text", sid);
		  		memset(msg.text, 0, msg.text_len); // clear msg text
			}
		  	
		  	syslog(LOG_NOTICE, "%d parseNetlinkMsg: TRESOR_MSG_SAVEKEY end.", sid);
		  	mon_setkey_fails--;
			break;
		case TRESOR_MSG_ENCRYPT:
			mon_encrypt++;
			mon_encrypt_fails++;

			msg_return.operation = msg.operation;
			msg_return.text_len = msg.text_len;
			ret = enclEncrypt (eid, msg.text, msg.text_len, msg_return.text, msg_return.text_len); 
			if ( TRESOR_OK != ret )
				syslog(LOG_ERR, "Error calling enclave\n (error 0x%x)\n", ret );
			tresor_nl_sendmsg(sk, msg_return);

			mon_encrypt_fails--;
			break;
		case TRESOR_MSG_DECRYPT:
			mon_decrypt++;
			mon_decrypt_fails++;

    		msg_return.operation = msg.operation;
			msg_return.text_len = msg.text_len; // because simple block crypto
			ret = enclDecrypt (eid, msg.text, msg.text_len, msg_return.text, msg_return.text_len);			
			if ( SGX_SUCCESS != ret )
				syslog(LOG_ERR, "Error calling enclave\n (error 0x%x)\n", ret );	
			tresor_nl_sendmsg(sk, msg_return);

			mon_decrypt_fails--;
			break;
		default:
    		syslog(LOG_NOTICE, "%d parseNetlinkMsg: ignore operation: %d text: %s", sid, msg.operation, msg.text);
			break;
	}
    return ret;
}


/* Netlink initialisation */
struct nl_sock* tresor_nl_init() {
	// setup mutex for strictly singularity in netlink message parsing
	if (pthread_mutex_init(&mutex_nl, NULL) != 0)
	{
	    syslog(LOG_ERR, "%d tresor_nl_init: mutex init failed\n", sid);
	}
	struct nl_sock * sk;
	sk = nl_socket_alloc();
	nl_socket_disable_seq_check(sk);  // disable sequence number check
	nl_socket_disable_auto_ack(sk); // disable ack's after each message
	genl_connect(sk);
	return sk;
}


/* Netlink callback function for incoming messages */
static int tresor_nl_callback_handler(struct nl_msg * msg, void * arg)
{	
    pthread_mutex_lock(&mutex_nl); // lock until nl callback is finished
    mon_nl_cb++;
    mon_nl_cb_fails++;

  	* (int*) arg = 0; // cbarg
	struct nlmsghdr * hdr = nlmsg_hdr(msg);
	struct genlmsghdr * gnlh = nlmsg_data(hdr);
 
  	// print complete message for debugging
  	// char *buf[2000];
 	// nl_msg_dump(msg, buf);
  	// syslog("MSG %s", buf);
  	//syslog(LOG_NOTICE, "%d tresor_nl_callback_handler: hdr->nlmsg_type: %x\n", sid, hdr->nlmsg_type);

	// check if message is error message and skip parsing in that case
	if (hdr->nlmsg_type == 2) {
		// parse error message
		struct nlmsgerr *err = nlmsg_data(hdr);
		if (0 != err->error) {
			syslog(LOG_ERR, "%d tresor_nl_callback_handler: Netlink Error: %d Exiting nl listen loop!\n", sid, err->error);
			* (int *) arg = TRESOR_DAEMON_EXIT;
		}	
	} else {
		int valid = genlmsg_validate(hdr, 0, TRESOR_NL_ATTR_MAX, tresor_nl_gnl_policy);
		//syslog(LOG_NOTICE, "tresor_nl_callback_handler: valid %d %s\n", valid, valid ? "ERROR" : "OK");
		struct nlattr * attrs[TRESOR_NL_ATTR_MAX + 1];
		if (genlmsg_parse(hdr, 0, attrs, TRESOR_NL_ATTR_MAX, tresor_nl_gnl_policy) < 0)
		{
			syslog(LOG_NOTICE, "%d tresor_nl_callback_handler: genlsmg_parse ERROR\n", sid);
		}
		else
		{
			//syslog(LOG_NOTICE, "%d tresor_nl_callback_handler: genlsmg_parse OK\n", sid);
			struct tresor_nl_msg * tresormsg = (struct tresor_nl_msg *) nla_data(attrs[TRESOR_NL_ATTR1_MSG]);
			//syslog(LOG_NOTICE, "%d tresor_nl_callback_handler: tresormsg: operation: %d text_len: %s\n", sid, tresormsg->operation, tresormsg->text_len);
			// parse incoming message
			* (int *) arg = parseNetlinkMsg(*tresormsg);
		}
  	}
  	mon_nl_cb_fails--;
	pthread_mutex_unlock(&mutex_nl);
	return NL_STOP;
}


/* Netlink initialize callback function */
struct nl_cb *  tresor_nl_initcallback(void * cbarg) {
	struct nl_cb * cb = NULL;
	cb = nl_cb_alloc(NL_CB_CUSTOM);
	nl_cb_set_all(cb, NL_CB_CUSTOM, tresor_nl_callback_handler, cbarg);
	nl_cb_err(cb, NL_CB_DEBUG, NULL, NULL);
	return cb;
}


/* free netlink ressources */
void tresor_nl_free(struct nl_sock *sk){
  pthread_mutex_destroy(&mutex_nl);
  nl_close(sk);
  nl_socket_free(sk);
}


/* SGX Function for enclave creation */
int sgxCreateEnclave() {
	sgx_launch_token_t token = {0};
	int updated = 0;
	sgx_status_t ret;
	ret = sgx_create_enclave(enclavefilepath, DEBUG_ENCLAVE, &token, &updated, &eid, NULL );
	if ( SGX_SUCCESS != ret)
	{
		syslog(LOG_ERR, "%d sgxCreateEnclave: cant create tresorencl (error 0x%x)\n", sid, ret );
	} else {
		syslog(LOG_NOTICE, "%d sgxCreateEnclave: tresorencl created. eid: %d status: %d\n", sid, (int) eid, ret);
	}
	return ret;
}


/* destroy SGX enclave */
int sgxDestroyEnclave() {
	sgx_status_t ret;
	ret = sgx_destroy_enclave( eid );
	if ( SGX_SUCCESS != ret ) {
		syslog(LOG_ERR, "%d sgxDestroyEnclave: cant destroy tresorencl (error 0x%x)\n", sid, ret );
	}
 	else {
		syslog(LOG_NOTICE, "%d sgxDestroyEnclave: tresorencl destroyed..", sid);
 	}
	return ret;
}


/* user defined signal 1 callback handler
   Prints monitoring information */
void signal_callback_handler_usr(int signum) {
	syslog(LOG_NOTICE, "%d Caught signal: %d", sid, signum);
	if (signum == 10) { // print monitoring vars on sigint
		syslog(LOG_INFO, "mon_nl_cb: %d, mon_nl_cb_fails:%d, mon_nl_send:%d, mon_nl_send_fails:%d, mon_encrypt:%d, mon_encrypt_fails:%d, mon_decrypt:%d, mon_decrypt_fails:%d, mon_setkey:%d, mon_setkey_fails:%d",
					 	mon_nl_cb, mon_nl_cb_fails, mon_nl_send, mon_nl_send_fails, mon_encrypt, mon_encrypt_fails, mon_decrypt, mon_decrypt_fails, mon_setkey, mon_setkey_fails);
	}
}


/* term signal callback handler
   prints monitoring info and shuts daemon and enclave down */
void signal_callback_handler(int signum) {
	syslog(LOG_NOTICE, "%d Caught signal: %d", sid, signum);
	syslog(LOG_INFO, "mon_nl_cb: %d, mon_nl_cb_fails:%d, mon_nl_send:%d, mon_nl_send_fails:%d, mon_encrypt:%d, mon_encrypt_fails:%d, mon_decrypt:%d, mon_decrypt_fails:%d, mon_setkey:%d, mon_setkey_fails:%d",
					 mon_nl_cb, mon_nl_cb_fails, mon_nl_send, mon_nl_send_fails, mon_encrypt, mon_encrypt_fails, mon_decrypt, mon_decrypt_fails, mon_setkey, mon_setkey_fails);
	sgxDestroyEnclave(eid);
	tresor_nl_free(sk);
	exit(signum);
}

int main(void) {
	syslog(LOG_NOTICE, "started..");

	// register signal handler
	signal(SIGUSR1, signal_callback_handler_usr);
	signal(SIGTERM, signal_callback_handler);

	/* SGX vars */
	eid = 0;
	unsigned int input, output;

	// fork the parent process
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "Cant fork parent process");
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}	
	syslog(LOG_NOTICE, "PID: %d", pid);

	//change the file mode mask
	umask(0);

	// create new sid for child process
	sid = setsid();
	if (sid < 0) {
		syslog(LOG_ERR, "Cant fork child process");
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "SID: %d", sid);

	// change current working directory
	if (chdir("/") < 0) {
		exit(EXIT_FAILURE);		
	}

	// close standard file descriptors
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	// netlink callback function
  	struct nl_cb * cb = NULL;

  	sk = tresor_nl_init();
  	if (sk == NULL) {
  		syslog(LOG_ERR, "%d Cant bind NetlinkSocket", sid);
		exit(EXIT_FAILURE);
  	}

	syslog(LOG_NOTICE, "%d main: Create sgx enclave..", sid);
	
	if (TRESOR_OK != sgxCreateEnclave()) {
		syslog(LOG_ERR, "%d Cant create Enclave. Exiting!", sid);
		exit(EXIT_FAILURE);
	}

	/* if key set by pipe is activated, open a pipe first before registering at kernel module */
	if (SETKEY_BYPIPE == 1) { // opens a pipe and wait for key
		syslog(LOG_NOTICE, "%d main: SETKEY_BYPIPE start..", sid);

	    setlinebuf(stdout);
	    unlink(setkey_pipename);
	    mkfifo(setkey_pipename, 0600);

	    int fd;
	    char buf[32];
	 	memset(buf, 0, 32); // set buf to 0

	    fd = open(setkey_pipename, O_RDONLY);
	    read(fd, buf, sizeof(buf));
	    //syslog(LOG_NOTICE, "%d main: SETKEY_BYPIPE: recv: %s", sid, buf);
	    close(fd);

	    if (SEALED_CRYPTO == 1) {
		  	initSealedCrypto(eid, buf, 32, sealfilepath);
	  	} else {
			initCrypto(eid, buf, 32);
	  	}

	    memset(buf, 0, 32); // set buf to 0
	    syslog(LOG_NOTICE, "%d main: SETKEY_BYPIPE end.", sid);
	}

	syslog(LOG_NOTICE, "%d main: call tresor_nl_initcallback", sid);
  	int exitDaemon = 0; // callback arg - can be retreived after receive
  	cb = tresor_nl_initcallback(&exitDaemon);

	/* 	Register daemon at kernel netlink interface
	no text is needed because PID is contained in netlink header */
	syslog(LOG_NOTICE, "%d main: Register tresord via netlink at tresorlkm", sid);
  	struct tresor_nl_msg tresor_register_msg;
  	tresor_register_msg.operation = TRESOR_MSG_REGISTER;
  	strncpy(tresor_register_msg.text,"Hello Tresord here!",sizeof("Hello Tresord here!"));
  	// send to kernel
  	tresor_nl_sendmsg(sk, tresor_register_msg);

	// daemon loop blocks until it receives a message, exitDaemon is set in nl callback function
	while (exitDaemon == TRESOR_OK) {
	    int nrecv = nl_recvmsgs(sk, cb); //needs sk from init
	}

	syslog(LOG_NOTICE, "%d main: destroy enclave..", sid);
	sgxDestroyEnclave(eid);
	syslog(LOG_NOTICE, "%d main: free netlink..", sid);
	tresor_nl_free(sk);
	syslog(LOG_NOTICE, "%d main: exit.", sid);
	exit(EXIT_SUCCESS);
}
