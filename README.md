# TresorSGX
## Introduction

With release of the first CPUs with [Intel Software Guard Extensions](https://software.intel.com/en-us/sgx) in October 2015 and the [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk) in the first half of 2016, a new technology was made available to execute code in a secured *enclave*. These protected enclaves are shielded against access and modification of any outside application - privileged or not.

## TresorSGX

*TresorSGX* is a attempt to isolate and secure a operating system component of the Linux kernel. It outsources a functionality of a kernel module into a SGX container / enclave. TresorSGX provides a cryptographic algorithm for the Linux Crypto API which is executed in the secured container. The cryptographic key material is guarded from unauthorised access of unprivileged and privileged components at any time. This protects the disk-encryption system from cold-boot and DMA attacks on the key material.

### Architecture

`TODO: Describe components and upload graphical overview.`

## Usage
### TresorSGX requirements

1. SGX capable CPU
2. SGX must be enabled in BIOS
3. Intel SGX Linux SDK must be installed
4. Intel SGX AESM Daemon must be running


### Installation of TresorSGX

1. (optional) modify the configuration of TresorSGX
2. (mandatory) build the TresorSGX LKM, Daemon, Enclave
3. (optional) copy files to the location defined in the configuration
4. (optional) add the TresorSGX LKM to \code{/etc/modules} to load the module on system boot
5. (mandatory) load the TresorSGX LKM into the kernel
6. (mandatory) execute the TresorSGX daemon if not configured to launch automatically
7. (optional) build and load the Test TresorSGX LKM to test the cryptographic system


### Test TresorSGX
1. `./run_tresortest.sh`
2. analyse results with: `tail -f /var/log/syslog`
3. `./shutdown_tresortest.sh`


### Setup TresorSGX container

1. `dd if=/dev/zero bs=1M count=1024 of=container`
2. `sudo losetup /dev/loop0 container` 
3. `modprobe dm_mod`
4. `sudo cryptsetup create tresor /dev/loop0 --cipher tresor --key-size 128`
5. `mkfs.ext2 /dev/loop0`
6. `mount /dev/loop0 /media/tresor/`

### Remove TresorSGX container 

1. `umount /media/tresor/`
2. `cryptsetup remove tresor`
3. `losetup -d /dev/loop0`


### Setup TresorSGX partition on an USB stick

0. start tresorlkm and tresord
1. locate usb stick partition. e.g. `/dev/sdd1`
2. `modprobe dm_mod`
3. `sudo cryptsetup create tresor /dev/sdd --cipher tresor --key-size 128`
4. `mkfs.ext2 /dev/mapper/tresor`
5. `mount /dev/mapper/tresor /media/tresor/`

### Remove TresorSGX partition

1. `umount /media/tresor/`
2. `cryptsetup remove tresor`

### Harden TresorSGX key setting

1. modify line 57 of `tresorcommon.h` to:
	`#define SETKEY_BYPIPE 	(1) // daemon opens a pipe for key setting`


