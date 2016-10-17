# TresorSGX
## Introduction

With release of the first CPUs with [Intel Software Guard Extensions](https://software.intel.com/en-us/sgx) in October 2015 and the [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk) in the first half of 2016, a new technology was made available to execute code in a secured *enclave*. These protected enclaves are shielded against access and modification of any outside application - privileged or not.

*TresorSGX* is a attempt to isolate and secure a operating system component of the Linux kernel. It outsources a functionality of a kernel module into a SGX container / enclave. TresorSGX provides a cryptographic algorithm for the Linux Crypto API which is executed in the secured container. **The cryptographic key material is guarded from unauthorised access of unprivileged and privileged components at any time.** This protects the disk-encryption system from cold-boot and DMA attacks on the key material.

TresorSGX was built during my master thesis at the [IT-Security chair](https://www1.cs.fau.de/) of the Department of Computer Science at the Friedrich-Alexander University (FAU) Erlangen Nuremberg. Have a look at [https://www1.cs.fau.de/sgx-kernel](https://www1.cs.fau.de/sgx-kernel) for more information about the thesis. 

## Background: Intel SGX

If you are familiar with the Intel SGX Architecture and its security characteristics, you can skip this section. Otherwise it is highly recommended to read through to develop an understanding of the design decisions we made. If you want a more in-depth understanding of Intel SGX - besided the official documentation - I recommend the paper [Intel SGX explained by Costan and Devadas](https://eprint.iacr.org/2016/086).

### Background: Intel SGX Security Characteristics

Intel also proposed [methods to use SGX to deploy trustworthy software solutions](https://software.intel.com/sites/default/files/article/413938/hasp-2013-innovative-instructions-for-trusted-solutions.pdf). This is achieved by using [attestation, provisioning and sealing techniques](https://software.intel.com/en-us/articles/innovative-technology-for-cpu-based-attestation-and-sealing).

![Intel SGX Enclave](/docu/img/sgx_secured_enclave.png "Intel SGX Enclave")

The enclave memory is secured against observation and modification of any non-enclave party. That excludes virtual machine monitors, ring-0 applications or other enclaves. This is achieved by encrypting the memory with a [in-CPU Memory Encryption Engine (MME)](https://software.intel.com/en-us/blogs/2016/02/26/memory-encryption-an-intel-sgx-underpinning-technology).

Via a hard-coded private key the CPU is able to perform an attestation of itself against a challenger and to sign via public-key cryptography a measurement of an enclave. That can be used to guarantee the integrity of an enclave and for enclave attestation.

Function calls into the enclave are provided via special instruction which perform checks on the callee and the function arguments. The same applies for function calls from the enclave to the outside. Interrupts and unplanned exits will not reveal secure information because an enclave can only be stopped in a secured area.

SGX allows the usage of multiple enclave instances which are isolated against each other and from the system software.

### Background: Intel SGX Architecture

The Intel Software Guard Extensions consist of multiple parts. The basis builds the Intel Skylake CPU with its extended instruction set and memory access mechanisms. These instructions are used to create, launch, enter and exit an enclave. The protected memory, the Enclave Page Cache (EPC), for the enclave is allocated in the Processor Reserved Memory (PRM) and secured with a Memory Encryption Engine.

![Intel SGX Archicture](/docu/img/sgx_arch_highlevel.png "Intel SGX Archicture")

The untrusted host application can call trusted functions inside the enclave. Neither the input to the enclave, nor the output of the enclave can be fully trusted because a malicious OS can modify these channels. The enclave author has to take this into consideration developing security critical applications. To initiate the enclave a launch token is needed which can be retrieved with the help of the Intel Launch Enclave. The access to the Launch Enclave and other architectural enclaves (Quoting, Provisioning, etc) is provided by the AESM service in user space. SGX libraries provide the necessary methods to communicate with the AESM Service. **Enclaves can only be entered in user space.** However, creating and initiating an enclave is only possible in kernel space. Therefore, a privileged SGX module or driver must be installed in kernel space to manage the enclave page cache and calling the specific SGX instructions. The launched enclave can only be entered from an unprivileged user-mode application via special SGX instructions.

## TresorSGX Design

As previously described it is not possible to enter an enclave from kernel space. An enclave’s code has always to be executed in ring three with a reduced set of allowed instructions and a limited amount of available memory. To overcome these major limitations of SGX, it was decided to build an architecture which moves part of the kernel functionality to user space such that the core functionality can then be wrapped by an enclave. This enclave is implemented by a user space service or daemon which calls the Intel Launch enclave for initialisation. Once the enclave is running, functionality within the enclave can be used by the daemon. Consequently, the kernel first has to communicate with the daemon which then passes the request to the enclave.

![TresorSGX Archicture](/docu/img/tresorsgx_arch.png "TresorSGX Archicture")

TresorSGX is an exemplary implementation in the scope of full disk encryption. The TresorSGX LKM registers a new cipher within the crypto API of the Linux kernel which can then be used by dm-crypt. The encryption algorithm used for full disk encryption is implemented within an enclave, and thus it is guaranteed that the implementation cannot be tampered with. The key used for disk encryption is securely derived within the enclave from a password chosen by the user and a device specific salt. The user password can be entered with the help of a tool which communicates with the daemon directly in user mode and the salt is stored sealed to the enclave identity. Consequently, it cannot be unsealed on a different device

### TresorSGX Workflow

The overall functionality of the implementation is spread between the LKM and the user space daemon.

**Initialising LKM and daemon:**
When the kernel module is initialized, it first registers a Netlink family for the communication with the daemon. Once the Netlink socket is created, it starts the daemon via the user mode helper API. The daemon then creates and starts the enclave. Using the key setting functionality of the crypto API would leak the key or password to main memory, therefor a possibility is provided to directly set the password using only the daemon.

**Deriving disk encryption key:**
After the password has been read from the user, the daemon loads a predefined file from disk which contains the sealed salt. The enclave checks if the sealed salt is valid and unseals it. If the sealed data is not valid, it will generate a new salt and seal it. The Password-Based Key Derivation Function 2 (PBKDF2) is used to finally derive the disk encryption key from the user password and the salt.

**Establish Netlink communication:**
The daemon creates the same Netlink interface as the kernel module and sends an initialisation succeeded message to the kernel. The kernel receives the message and registers the new cipher at the crypto API.

**Data encryption and decryption:**
After initialization, the encryption or decryption process is straight forward. The encrypt and decrypt callback functions of our LKM are called by the user of the crypto API. The LKM then sends a Netlink message to the daemon, which calls the encrypt and decrypt functions of the enclave. The enclave performs the requested cryptographic operation and returns the encrypted or decrypted block which is passed back to the kernel via Netlink. Finally, the kernel module copies the block to the destination given by the caller of the crypto API and returns.

## Usage

### TresorSGX requirements

Because the new CPU instructions of the Intel Software Guard Extensions only current Intel CPU are able to execute the TresorSGX enclave. Have a look at the [SGX-hardware list](https://github.com/ayeks/SGX-hardware) for more information about SGX support.
The requirements are: 

1. a SGX capable CPU
2. SGX must be enabled in BIOS (is default off)
3. [Intel SGX Linux SDK](https://software.intel.com/en-us/sgx-sdk/download) must be installed
4. Intel SGX AESM Daemon must be running (it is running by default if you installed the SDK)


### Test TresorSGX

TresorSGX can be tested by executing a single file. Just configure the paths in the [/tresorcommon/tresorcommon.h](/tresorcommon/tresorcommon.h) and execute the [run_tresortest.sh executable](/run_tresortest.sh). Analyse the results with: `tail -f /var/log/syslog` and compare them to [docu/example_output.md](/docu/example_output.md). Execute [shutdown_tresortest.sh executable](/shutdown_tresortest.sh) to shutdown TresorSGX.

### Installation of TresorSGX

If you want to install in a fixed position follow these steps:

1. (optional) modify the paths in [/tresorcommon/tresorcommon.h](/tresorcommon/tresorcommon.h)
2. (mandatory) build the TresorSGX LKM, Daemon, Enclave
3. (optional) copy files to the location defined in the configuration
4. (optional) add the TresorSGX LKM to \code{/etc/modules} to load the module on system boot
5. (mandatory) load the TresorSGX LKM into the kernel
6. (mandatory) execute the TresorSGX daemon if not configured to launch automatically
7. (optional) build and load the [/test_tresor_lkm/](https://github.com/ayeks/TresorSGX/tree/master/test_tresor_lkm) kernel module to test the TresorSGX cryptographic system


### Setup TresorSGX container

Follow these steps to create a single container-file which is encrypted with TresorSGX and can be mounted using cryptsetup:

1. `dd if=/dev/zero bs=1M count=1024 of=container`
2. `sudo losetup /dev/loop0 container` 
3. `modprobe dm_mod`
4. `sudo cryptsetup create tresor /dev/loop0 --cipher tresor --key-size 128`
5. `mkfs.ext2 /dev/loop0`
6. `mount /dev/loop0 /media/tresor/`

Follow these steps to remove the container:

1. `umount /media/tresor/`
2. `cryptsetup remove tresor`
3. `losetup -d /dev/loop0`


### Setup TresorSGX partition on an USB stick

Follow these steps to create a partition which is encrypted with TresorSGX and can be mounted using cryptsetup:

0. start tresorlkm and tresord
1. locate usb stick partition. e.g. `/dev/sdd1`
2. `modprobe dm_mod`
3. `sudo cryptsetup create tresor /dev/sdd --cipher tresor --key-size 128`
4. `mkfs.ext2 /dev/mapper/tresor`
5. `mount /dev/mapper/tresor /media/tresor/`

Follow these steps to remove the partition:

1. `umount /media/tresor/`
2. `cryptsetup remove tresor`

### Harden TresorSGX key setting

If you want to harden the system by using the [tresor_setkey tool](/tresor_setkey/) modify the [/tresorcommon/tresorcommon.h](/tresorcommon/tresorcommon.h) as follows.

1. modify line 57 of `tresorcommon.h` to:
	`#define SETKEY_BYPIPE 	(1) // daemon opens a pipe for key setting`

With that configuration the key inserted in the cryptsetup is just a dummy key. The daemon will open a pipe and will wait for the input of the real user password by the setkey tool.

## Contributing

The main drawback of TresorSGX in its disk encryption use case is the low performance. It operates at 1% of the standard AES implementation due the big overhead of the Netlink communication. The [performance analysis](/docu/performance_analysis.md) provides more information regarding that topic. If someone is able to replace or to improve the Netlink communication I am happy to support him on his way. 


