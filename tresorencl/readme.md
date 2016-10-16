# Tresor Enclave and Enclave Tester

The Enclave is located in `./Enclave/`. No SGX enclave can exist on its own. It must be executed in a host application which initialises the enclave. The host application for the TresorSGX enclave is the TresorSGX daemon `../tresord/`. However for debugging and testing purposes the minimalistic `tresorencl_tester.c` can be used. It creates the enclave and calls its trusted functions the same way as the daemon.
When building the enclave the first time `make configure` must be executed to create the SGX key pair.

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
# To build the enclave tester and the enclave:
make
```

Running the tester:
	
```
./tresorencl_tester
```

Debugging:
```
# In case of problems, don't forget to check the kernel logs for output from the SGX driver:
> tail -f /var/log/syslog
```

## Role

The available trusted enclave functions are described in the [EDL file](./Enclave/tresorencl.edl). The untrusted functions are for debugging purposes and are called by the enclave and are executed in the host application. The enclave functions are implemented in [./Enclave/tresorencl.c](./Enclave/tresorencl.c). The other files are either additional libs or SGX specific files (e.g. *_t.c, *_u.c, ..).

The PBKDF2 functions are copied from the awesome [sgx-pwenclave](https://github.com/ctz/sgx-pwenclave) repository and are used to create the encryption key. The salt is saved in a sealed container for later use. The sealed container can only be unsealed with the same enclave on the same CPU because it is sealed with the enclave identity.

```
                       +------------------------------------------------------------------------------------+
                       | TresorSGX Enclave                                                                  |
                       |                                                                                    |
                       |                                                                                    |
                       |                                                                                    |
                       | +-------------------+                                                              |
+----------------+  +---->User Key (Password)+------------------------------+                               |
|TresorSGX Daemon+--+  | +-------------------+                              |                               |
+----------------+  |  |                                                    |                               |
                    |  | +-----------+                         +----+       | +------+    +--------------+  |
                    +---->sealed Salt+---------+             +->Salt+-------+->PBKDF2+---->Encryption Key|  |
                       | +-----------+         |             | +----+       | +------+    +--------------+  |
                       |                       |             |              |                               |
+-----------------+    | +--------+            | +---------+ | +----------+ |                               |
|Intel Skylake CPU+-+---->Seal Key+------------+->unsealing+-+->Iterations+-+                               |
+-----------------+ |  | +--------+            | +---------+   +----------+                                 |
                    |  |                       |                                                            |
                    |  | +-------------------+ |                                                            |
                    +---->Enclave Measurement+-+                                                            |
                       | +-------------------+                                                              |
                       |                                                                                    |
                       +------------------------------------------------------------------------------------+


```
