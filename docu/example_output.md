## Terminal:

lars@lars-tresor-7559:~/Documents/gitlab/TresorSGX$ ./run_tresortest.sh 
running test tresorsgx
Step 1: make components
SUCCESS creating RSA key pair for enclave
SUCCESS making TRESORD
SUCCESS making tresorlkm
SUCCESS making test_tresor_lkm
Step 2: insmod tresorlkm
Step 3: run tresord
Step 4: check if set key by pipe is activated..
SETKEY_BYPIPE == 0
Step 5: insmod test_tresor_lkm
Step 6: Print syslog:
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698345] test_tresor_lkm: l1: 0x6B|0xC1|0xBE|0xE2|0x2E|0x40|0x9F|0x96|0xE9|0x3D|0x7E|0x11|0x73|0x93|0x17|0x2A|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698345] test_tresor_lkm: Call crypto_cipher_encrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_SAVEKEY clear msg.text
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.896973] test_tresor_lkm: l1: 0xC1|0x76|0x31|0x98|0x87|0x43|0x32|0xF0|0x40|0xCB|0x03|0x4C|0x82|0xA7|0xA3|0x9E|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.896975] test_tresor_lkm: Call crypto_cipher_decrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897071] test_tresor_lkm: l1: 0x6B|0xC1|0xBE|0xE2|0x2E|0x40|0x9F|0x96|0xE9|0x3D|0x7E|0x11|0x73|0x93|0x17|0x2A|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897072] test_tresor_lkm: Call crypto_cipher_decrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897072] test_tresor_lkm: 1 block(s):  AES-128: PASS
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897074] test_tresor_lkm: ended successfully
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_SAVEKEY end.
lars@lars-tresor-7559:~/Documents/gitlab/TresorSGX$ ./shutdown_tresortest.sh 
shutdown test tresorsgx
rmmod test_tresor_lkm
kill tresord
rmmod tresorlkm

## SYSLOG:

Aug 11 17:15:02 lars-tresor-7559 kernel: [ 9506.676955] tresorlkm: Entering: tresor_init
Aug 11 17:15:02 lars-tresor-7559 kernel: [ 9506.677004] tresorlkm: tresor_init: Crypto Alg registered: 0
Aug 11 17:15:04 lars-tresor-7559 tresord: started..
Aug 11 17:15:04 lars-tresor-7559 tresord: PID: 0
Aug 11 17:15:04 lars-tresor-7559 tresord: SID: 10920
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 main: Create sgx enclave..
Aug 11 17:15:04 lars-tresor-7559 kernel: [ 9508.686969] isgx: [10920:0x00007fd982800000] ECREATE backing=0x7fd981fff000, size=0x800000
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 sgxCreateEnclave: tresorencl created. eid: 2 status: 0
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 main: call tresor_nl_initcallback
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 main: Register tresord via netlink at tresorlkm
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_REGISTER..
Aug 11 17:15:04 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: Register ACK from Kernel op: 1 text: Hello Kernel here!
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_SAVEKEY..
Aug 11 17:15:06 lars-tresor-7559 tresord: l1: 0x2B|0x7E|0x15|0x16|0x28|0xAE|0xD2|0xA6|0xAB|0xF7|0x15|0x88|0x09|0xCF|0x4F|0x3C|
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 initSealedCrypto: seal is available
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698323] test_tresor_lkm: Entering: tresor_test_init
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698327] alg: No test for ecb(tresorsgx) (ecb(tresorsgx))
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698327] test_tresor_lkm: ecb(tresorsgx): 0
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698329] alg: No test for cbc(tresorsgx) (cbc(tresorsgx))
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698330] test_tresor_lkm: cbc(tresorsgx): 0
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698330] test_tresor_lkm: test tresorsgx tfm
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698340] test_tresor_lkm: run 1 block(s):  AES-128..
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698341] test_tresor_lkm: buffer_size: 16 numBlocks: 1 BLOCK_SIZE: 16
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698345] test_tresor_lkm: l1: 0x6B|0xC1|0xBE|0xE2|0x2E|0x40|0x9F|0x96|0xE9|0x3D|0x7E|0x11|0x73|0x93|0x17|0x2A|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.698345] test_tresor_lkm: Call crypto_cipher_encrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_SAVEKEY clear msg.text
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.896973] test_tresor_lkm: l1: 0xC1|0x76|0x31|0x98|0x87|0x43|0x32|0xF0|0x40|0xCB|0x03|0x4C|0x82|0xA7|0xA3|0x9E|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.896975] test_tresor_lkm: Call crypto_cipher_decrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897071] test_tresor_lkm: l1: 0x6B|0xC1|0xBE|0xE2|0x2E|0x40|0x9F|0x96|0xE9|0x3D|0x7E|0x11|0x73|0x93|0x17|0x2A|
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897072] test_tresor_lkm: Call crypto_cipher_decrypt_one ...
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897072] test_tresor_lkm: 1 block(s):  AES-128: PASS
Aug 11 17:15:06 lars-tresor-7559 kernel: [ 9510.897074] test_tresor_lkm: ended successfully
Aug 11 17:15:06 lars-tresor-7559 tresord: 10920 parseNetlinkMsg: TRESOR_MSG_SAVEKEY end.
Aug 11 17:15:16 lars-tresor-7559 kernel: [ 9521.654990] test_tresor_lkm: Entering: tresor_test_exit

Aug 11 17:15:19 lars-tresor-7559 tresord: 10920 Caught signal: 15
Aug 11 17:15:19 lars-tresor-7559 tresord: mon_nl_cb: 4, mon_nl_cb_fails:0, mon_nl_send:3, mon_nl_send_fails:0, mon_encrypt:1, mon_encrypt_fails:0, mon_decrypt:1, mon_decrypt_fails:0, mon_setkey:1, mon_setkey_fails:0
Aug 11 17:15:19 lars-tresor-7559 tresord: 10920 sgxDestroyEnclave: tresorencl destroyed..
Aug 11 17:15:21 lars-tresor-7559 kernel: [ 9525.731692] tresorlkm: tresor_exit exiting module

