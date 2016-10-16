# Tresor Loadable Kernel Module

## Usage

```
make
sudo insmod ./tresorlkm/tresorlkm.ko
```

## Role

The TresorLKM communicates with the Linux Crypto API and the User Space Daemon via Netlink. When loading the LKM `tresor_init` is executed. During `tresor_init` the required mutex and Netlink family is registers. Also the module registers its cipher at the Crypto API by calling `crypto_register_alg`. The LKM is able to start the daemon with help of the [usermodehelper API](https://www.ibm.com/developerworks/library/l-user-space-apps/index.html).

### Crypto API Communication
`tresor_crypto_setkey` key setting function which is executed if a key is set at the Crypto API.

`tresor_crypto_encrypt` Crypto API encryption function. The block will be send to the daemon for encryption. The function will wait until the encrypted block is returned.

`tresor_crypto_decrypt` Analog to encryption.

### Netlink Communication
`tresor_nl_cmd` callback function if a message is send to the Netlink family from the daemon.

`tresor_nl_sendmsg` sends a message to the daemon which must be registered at the Netlink socket.

## Control and message flow

At the Crypto API wants to encrypt one block and calls the registered encrypt routine in the TresorLKM.
The TresorLKM waits until it is able to lock a mutex. When the mutex is locked it sends an *encrypt* message with the block to the Daemon via Netlink.
The LKM must wait until the daemon encrypts the block and sends it back - triggering a Netlink callback function in the LKM. 
Completions are used to perform this task. If the message is returned, the completion is completed and the encrypted block is copied to the destination, defined by the Crypto API, the encrypt function unlocks the mutex and returns.

```
           +                                           +
Crypto API |                 Tresor LKM                |  Tresor Daemon
     +     |                                           |
     v     |                                           |
  encrypt+----->_crypto_encrypt                        |
           |     +                                     |
           |     |           mutex[U]                  |
           |     v                                     |
           |    lock mutex                             |
           |     +                                     |
           |     +---------->mutex[L]                  |
           |     v                                     |
           |    send nl msg+------------------------------>encrypt block
           |     +                                     |     +
           |     v                                     |     v
           |    wait for completion           _nl_cmd<----+send nl msg
           |     +                                 +   |
           |     |                                 v   |
           |     +---------->compl[L]     msg parsing  |
           |                                       +   |
           |                                       v   |
           |     +----------+msg txt<--------+cpy msg  |
           |     |                                 +   |
           |     |                                 v   |
           |     +----------+compl[U]<------+complete  |
           |     |                                     |
           |     v                                     |
           |   cpy msg                                 |
           |     +                                     |
           |     v                                     |
           |   unlock mutex                            |
           |     +                                     |
           |     |                                     |
 return<---------+---------->mutex[U]                  |
           +                                           +


```
