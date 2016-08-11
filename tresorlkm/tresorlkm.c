#include <linux/module.h>
#include <linux/kernel.h>

/* netlink communication */
#include <net/genetlink.h>
/* common tresor */
#include "../tresorcommon/tresorcommon.h"

/* crypto api */
#include <crypto/algapi.h>
#include <linux/module.h>
#include <crypto/aes.h>
#include <linux/smp.h>

/* syncronizing crypto api - netlink communication */
#include <linux/completion.h> 
#include <linux/mutex.h>


int pid;

static struct nla_policy tresor_nl_gnl_policy[TRESOR_NL_ATTR_MAX + 1] =
{
    [DEMO_ATTR1_STRING] = { .type = NLA_NUL_STRING, .len = 256 },   /* variable length NULL terminated string */
    [TRESOR_NL_ATTR1_MSG] = { .len = sizeof(struct tresor_nl_msg)},
};


static struct genl_family tresor_nl_gnl_family = {
    .id = GENL_ID_GENERATE, // genetlink should generate an id
    .hdrsize = 0,
    .name = TRESOR_NL_FAMILY_NAME,
    .version = TRESOR_NL_VERSION,
    .maxattr = TRESOR_NL_ATTR_MAX,
};

struct genl_info *tresord_nl_info;
int tresord_nl_portid;
int tresord_avail;

/* syncronization, fixed completion */
DECLARE_COMPLETION(completion_enc);
//u8 *encryption_text;
unsigned char encryption_text[16];
DECLARE_COMPLETION(completion_dec);
//u8 *decryption_text;
unsigned char decryption_text[16];

/* semaphore for all encryption / decryption operations */
static DEFINE_MUTEX(mutex_nl);


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
            printk(KERN_INFO "tresorlkm: l%d: %s",k , hexline); // print line to kernellog
            memset(&hexline[0], 0, sizeof(hexline)); // clear array
        }
    }
}

int tresor_nl_sendmsg(struct genl_info *info, struct tresor_nl_msg tresormsg) {
    struct sk_buff *skb;
    void *msg_head;
    int rc = 0;

    // check if info is null and abort if it is unset
    if (info == NULL || tresord_nl_portid == -1) {
            printk(KERN_ERR "tresorlkm: tresor_nl_sendmsg: ERROR no daemon registered netlink socket\n");
            return TRESOR_NL_NODAEMON_REGISTERED;
        }

    /* send message back */
    /* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE */
    //printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: allocate mem for new message\n");
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL) {
        printk(KERN_ERR "tresorlkm: tresor_nl_sendmsg: Failed to allocate new skb\n");
        return TRESOR_NL_FAILED_MSG_CREATION;
    }

    //printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: create the message\n");
    /* create the message */
    msg_head = genlmsg_put(skb, 0, info->snd_seq + 1, &tresor_nl_gnl_family, 0, TRESOR_NL_CMD);

    if (msg_head == NULL) {
        rc = -ENOMEM;
        printk(KERN_ERR "tresorlkm: tresor_nl_sendmsg: ERROR msg_head == NULL\n");
        return TRESOR_NL_FAILED_MSG_CREATION;
    }

    //printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: add content\n");

    rc |= nla_put(skb, TRESOR_NL_ATTR1_MSG, sizeof(struct tresor_nl_msg), &tresormsg);

    if (rc != 0) {
        printk(KERN_ERR "tresorlkm: tresor_nl_sendmsg: ERROR nla_put went wrong\n");
        return TRESOR_NL_FAILED_MSG_CREATION;
    }

    //printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: finalize the message\n");
    /* finalize the message */
    genlmsg_end(skb, msg_head);

    /* send the message back */
    // TODO: port ID differs here, why is that and which port id is the right one?
    rc = genlmsg_unicast(&init_net, skb, tresord_nl_portid);
    if (rc != 0) {
        printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: ERROR first genlmsg_unicast went wrong rc: %x tresord_nl_portid: %x\n", rc, tresord_nl_portid);
        rc = genlmsg_unicast(&init_net, skb, info->snd_portid);
        if (rc != 0) {
            printk(KERN_INFO "tresorlkm: tresor_nl_sendmsg: ERROR second genlmsg_unicast went wrong rc: %x info->snd_portid: %x\n", rc, info->snd_portid);
            tresord_avail = 0; // daemon is not reachable any longer. must be registered again.
            return TRESOR_NL_FAILED_UNICAST;
        }
    }

    return TRESOR_OK;
}




int tresor_nl_cmd(struct sk_buff *skb_2, struct genl_info *info)
{
    struct nlattr *na;
    //struct sk_buff *skb;
    struct tresor_nl_msg *attr_tresormsg;
    struct tresor_nl_msg tresormsg;
    int res;
    res = 0;

    if (info == NULL) {
        printk(KERN_INFO "tresorlkm:  tresor_nl_cmd: netlink info is null\n");
        return TRESOR_NL_IS_NULL;
    }
    //printk(KERN_INFO "tresor_nl_cmd: info is not null\n");
    //printk(KERN_INFO "tresor_nl_cmd: info->snd_portid %x\n", info->snd_portid);

    na = info->attrs[TRESOR_NL_ATTR1_MSG];
    if (na) {
        //printk(KERN_INFO "tresor_nl_cmd: na not null\n");
        attr_tresormsg = (struct tresor_nl_msg *)nla_data(na);
        if (attr_tresormsg == NULL) {
            printk(KERN_INFO "tresorlkm: tresor_nl_cmd: error while receiving data\n");
        } else {
            //printk(KERN_INFO "tresor_nl_cmd: tresormsg operation: %d text_len: %s\n", attr_tresormsg->operation, attr_tresormsg->text_len);

            //msg_counter--;
            //printk(KERN_INFO "tresorlkm: %s msg_counter--: %d\n", __FUNCTION__, msg_counter);;

            switch (attr_tresormsg->operation) {
                case TRESOR_MSG_REGISTER:
                    //printk(KERN_INFO, "tresorlkm: %s: TRESOR_MSG_REGISTER..", __FUNCTION__);
                    // set global nl info to daemon
                    tresord_nl_info = info; //TODO: check if that works
                    tresord_nl_portid = info->snd_portid;
                    // echo same operation back to daemon, ack for register
                    tresormsg.operation = TRESOR_MSG_REGISTER;
                    memcpy(tresormsg.text,"Hello Kernel here!",sizeof("Hello Kernel here!"));
                    tresormsg.text_len = sizeof("Hello Kernel here!");
                    res = tresor_nl_sendmsg(tresord_nl_info, tresormsg);
                    if(res != TRESOR_OK) {
                        printk(KERN_INFO, "tresorlkm: %s: ERROR cannot send register ack back because: 0x%x", __FUNCTION__, res);
                        break;
                    }
                    tresord_avail = 1; // daemon is now ready for use
                    break;
                case TRESOR_MSG_SAVEKEY:
                    //printk(KERN_INFO, "tresorlkm: %s: TRESOR_MSG_SAVEKEY..", __FUNCTION__);
                    break;
                case TRESOR_MSG_ENCRYPT:
                    //printk(KERN_INFO, "tresorlkm: %s: TRESOR_MSG_ENCRYPT.. text_len: %d", __FUNCTION__, attr_tresormsg->text_len);
                    //printCharAsHex(attr_tresormsg->text, 16);
                    memcpy(encryption_text, attr_tresormsg->text, attr_tresormsg->text_len);
                    complete(&completion_enc);
                    break;
                case TRESOR_MSG_DECRYPT:
                    //printk(KERN_INFO, "tresorlkm: %s: TRESOR_MSG_DECRYPT.. text_len: %d", __FUNCTION__, attr_tresormsg->text_len);
                    //printCharAsHex(attr_tresormsg->text, 16);
                    memcpy(decryption_text, attr_tresormsg->text, attr_tresormsg->text_len);
                    complete(&completion_dec);
                    break;
                default:
                    printk(KERN_INFO, "tresorlkm: %s: ignore operation: %d", __FUNCTION__, attr_tresormsg->operation);
                    break;
            }

        }
    } else {
        printk(KERN_INFO "tresorlkm: tresor_nl_cmd: info->attrs[TRESOR_NL_ATTR1_MSG] is null\n");
    }
    return TRESOR_OK;
}


/*
 * Set-key crypto api function
 */
static int tresor_crypto_setkey(struct crypto_tfm *tfm, const u8 *in_key,
                            unsigned int key_len)
{   
    int res;
    struct tresor_nl_msg tresormsg;
    res = 0;

    if(tresord_avail == 0) {
        printk(KERN_INFO "tresorlkm: ERROR tresor_crypto_setkey: No daemon available!");
        return -1;
    }

    mutex_lock(&mutex_nl); // lock mutex until encryption is finished

    //printk(KERN_INFO "tresorlkm: tresor_crypto_setkey: key_len: %d\n", key_len);

    struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
    ctx->key_length = key_len;

    /* send key to daemon */
    tresormsg.operation = TRESOR_MSG_SAVEKEY;

    memcpy(tresormsg.text, in_key, key_len);
    tresormsg.text_len = key_len;

    res = tresor_nl_sendmsg(tresord_nl_info, tresormsg);

    if(TRESOR_OK != res) {
        printk(KERN_INFO "tresorlkm: ERROR tresor_crypto_setkey: error during tresor_nl_sendmsg ret: 0x%x\n", res);
        mutex_unlock(&mutex_nl);
        return 1;
    }
    mutex_unlock(&mutex_nl);
    return 0;
}




/*
 * Encrypt one block crypto api function
 */
void tresor_crypto_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{   
    int res, i;
    struct tresor_nl_msg tresormsg;
    //printk(KERN_INFO "tresorlkm: %s starting src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst);

    if(tresord_avail == 0) {
        printk(KERN_INFO "tresorlkm: ERROR tresor_crypto_setkey: No daemon available!");
        return -1;
    }

    mutex_lock(&mutex_nl); // lock mutex until encryption is finished

    // clear buffer
    for (i=0;i<AES_BLOCK_SIZE;i++) {
        encryption_text[i] = 0xee;
    }

    /* send src data to daemon */
    tresormsg.operation = TRESOR_MSG_ENCRYPT;
    tresormsg.text_len = AES_BLOCK_SIZE;    // encrypt 1 block, 16 bytes
    memcpy(tresormsg.text, src, AES_BLOCK_SIZE);

    res = tresor_nl_sendmsg(tresord_nl_info, tresormsg);

    if(TRESOR_OK != res) {
        printk(KERN_INFO "tresorlkm: %s ERROR during tresor_nl_sendmsg: ret: 0x%x src_addr: %x dst_addr: %x...\n", __FUNCTION__, res, &src, &dst);
        mutex_unlock(&mutex_nl);
        return;
    }

    /* block while waiting for completion of encryption */
    /* used static completion, dynamic completion is also possible if completion information is propagated */
    // printk(KERN_INFO "tresorlkm: %s entering wait_for_completion..\n", __FUNCTION__);
    if(0 == wait_for_completion_timeout(&completion_enc, 100))
        printk(KERN_ERR "tresorlkm: %s wait for completion timed out! src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst); // uninteruruptile wait, handle with care
    // printk(KERN_INFO "tresorlkm: %s leaving wait_for_completion..\n", __FUNCTION__);

    /* return encrypted data through *dst */
    memcpy(dst, encryption_text, AES_BLOCK_SIZE); // copy 1 block to destination

    mutex_unlock(&mutex_nl);
    //printk(KERN_INFO "tresorlkm: %s end. src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst);
}


/*
 * Decrypt one block crypto api function
 */
void tresor_crypto_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
    int i, res;
    struct tresor_nl_msg tresormsg;
    //printk(KERN_INFO "tresorlkm: %s starting src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst);

    if(tresord_avail == 0) {
        printk(KERN_INFO "tresorlkm: ERROR tresor_crypto_setkey: No daemon available!");
        return -1;
    }

    mutex_lock(&mutex_nl); // lock mutex until encryption is finished

    // clear buffer
    for (i=0;i<AES_BLOCK_SIZE;i++) {
        decryption_text[i] = 0xee;
    }

    /* send src data to daemon */
    tresormsg.operation = TRESOR_MSG_DECRYPT;
    tresormsg.text_len = AES_BLOCK_SIZE;    // decrypt 1 block, 16 bytes
    memcpy(tresormsg.text, src, AES_BLOCK_SIZE);

    res = tresor_nl_sendmsg(tresord_nl_info, tresormsg);

    if(TRESOR_OK != res) {
        printk(KERN_INFO "tresorlkm: %s ERROR during tresor_nl_sendmsg: ret: 0x%x  src_addr: %x dst_addr: %x...\n", __FUNCTION__, res, &src, &dst);
        mutex_unlock(&mutex_nl);
        return;
    }

    /* block while waiting for completion of encryption */
    /* used static completion, dynamic completion is also possible if completion information is propagated */
    //printk(KERN_INFO "tresorlkm: %s entering wait_for_completion..\n", __FUNCTION__);
    if(0 == wait_for_completion_timeout(&completion_dec, 100))
        printk(KERN_ERR "tresorlkm: %s wait for completion timed out! src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst); // uninteruruptile wait, handle with care
    //printk(KERN_INFO "tresorlkm: %s leaving wait_for_completion..\n", __FUNCTION__);

    /* return encrypted data through *dst */
    memcpy(dst, decryption_text, AES_BLOCK_SIZE); // copy 1 block to destination

    mutex_unlock(&mutex_nl);
    //printk(KERN_INFO "tresorlkm: %s end. src_addr: %x dst_addr: %x...\n", __FUNCTION__, &src, &dst);
}


/*
 * Crypto API algorithm
 */
static struct crypto_alg tresor_alg = {
    .cra_name       = "tresorsgx",
    .cra_driver_name    = "tresorsgx-driver",
    .cra_priority       = 100,
    .cra_flags      = CRYPTO_ALG_TYPE_CIPHER,
    .cra_blocksize      = AES_BLOCK_SIZE,
    .cra_ctxsize        = sizeof(struct crypto_aes_ctx),
    .cra_alignmask      = 3,
    .cra_module     = THIS_MODULE,
    .cra_list       = LIST_HEAD_INIT(tresor_alg.cra_list),
    .cra_u  = {
        .cipher = {
            .cia_min_keysize    = AES_MIN_KEY_SIZE,
            .cia_max_keysize    = AES_MAX_KEY_SIZE,
            .cia_setkey     = tresor_crypto_setkey,
            .cia_encrypt        = tresor_crypto_encrypt,
            .cia_decrypt        = tresor_crypto_decrypt
        }
    }
};


/* Netlink genl ops */
static struct genl_ops doc_exmpl_gnl_ops_echo[] = {
    {
    .cmd = TRESOR_NL_CMD,
    .flags = 0,
    .policy = tresor_nl_gnl_policy,
    .doit = tresor_nl_cmd,
    .dumpit = NULL,
    },
};


/*
 * User mode helper to start daemon
 */
static int startDaemon( void )
{
    printk(KERN_INFO "tresorlkm: Entering: %s", __FUNCTION__); 

    int callRet = 0;
    struct subprocess_info *sub_info;
    char *argv[] = { usermodehelper_daemon, NULL };
    static char *envp[] = {
        usermodehelper_home,
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin:", NULL };
    
    sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL, NULL, NULL );
    if (sub_info == NULL) return -1;
    
    callRet = call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );
    
    printk(KERN_INFO "tresorlkm: TresorSGX daemon call returned: %d\n", callRet);

    return 0;
}

static int __init tresor_init(void)
{   
    int rc, retval;
    printk(KERN_INFO "tresorlkm: Entering: %s\n", __FUNCTION__); 
    tresord_nl_info = NULL;
    tresord_nl_portid = -1;
    tresord_avail = 0;

    mutex_init(&mutex_nl); // initialize mutex

    //msg_counter = 100;
    //printk(KERN_INFO "tresorlkm: %s msg_counter: %d\n", __FUNCTION__, msg_counter);

    rc = genl_register_family_with_ops(&tresor_nl_gnl_family, doc_exmpl_gnl_ops_echo);

    if (rc != 0) {
        printk(KERN_ALERT "tresorlkm: %s: Error creating socket.\n", __FUNCTION__);
        genl_unregister_family(&tresor_nl_gnl_family);
        return -1;
    }

    /* register crypto alg */
    retval = crypto_register_alg(&tresor_alg);
    printk(KERN_INFO "tresorlkm: %s: Crypto Alg registered: %d\n", __FUNCTION__, retval);

    if (STARTDAEMON_BY_LKM == 1) {
        startDaemon();
    }

    return retval;
}


static void __exit tresor_exit(void)
{
    int ret;
    complete_all(&completion_enc); //deblock all waiting threads for completion when exiting
    mutex_unlock(&mutex_nl);
    
    printk(KERN_INFO "tresorlkm: %s exiting module\n", __FUNCTION__);
    
    ret = genl_unregister_family(&tresor_nl_gnl_family);

    if (ret != 0) {
        printk(KERN_ERR "tresorlkm: %s unregister family %i\n", __FUNCTION__, ret);
    }

    /* unregister crypto alg */
    crypto_unregister_alg(&tresor_alg);
}

module_init(tresor_init);
module_exit(tresor_exit);

MODULE_LICENSE("GPL");
