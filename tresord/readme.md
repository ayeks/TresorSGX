# TresorSGX Daemon

The daemon communicates via Netlink with the TresorSGX kernel module and hosts the enclave.
For testing the enclave please use the [tresorencl_tester](https://github.com/ayeks/TresorSGX/tree/master/tresorencl) because it reduces the complexity of the system a lot.. 

## Usage

Cleaning:

```
# To clear all objects files:
make clean
# To also clear the private/public key pair, execute:
make scrub
```

Building:

```
# If there is no public/private key pair, execute:
make configure
# To build the enclave and enclave:
make
```

Running the daemon:
	
```
./tresord
```

Debugging:
```
# In case of problems, don't forget to check the kernel logs for output from the SGX driver:
> tail -f /var/log/syslog
```

## Role

The daemon is started by the kernel module with the help of the user mode helper API or manually by the user.
During the initialisation phase the daemon creates the enclave with the help of the Intel SGX SDK.

If key setting by pipe is configured the daemon will open a pipe and waits until a user password is written to that pipe.
If sealing is enabled the daemon will try to load the sealed blob. Afterwards it calls the `setKeyWithSeal` function at the enclave - passing password and sealed salt.
If no sealing is enabled it just calls the setKey function with the user password.

When the enclave creation and the key setting by pipe has succeeded the daemon sends a register message of type *TRESOR_NETLINK* to the Netlink bus.
That initiates the register routine at the kernel module, which saves the daemons port id for later communication.

The daemon waits in a loop for new Netlink messages which will be parsed and analysed.

By default the Crypto API will call the `setKey` function at the TresorSGX kernel module. If key setting by pipe is disabled this key will be send to the enclave.

The daemon exits the loop if an exit message is send by the kernel module or a signal interrupt is send. 

