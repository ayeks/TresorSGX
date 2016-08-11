#SGX_SDK ?= /home/ubuntu/Documents/sgx_linux/linux_sdk
SGX_SDK ?= /opt/intel/sgxsdk
SGX_INCLUDE = $(SGX_SDK)/include
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

INTEL_AESNI = ../../lib/iaesni
INTEL_AESNIC = $(INTEL_AESNI)/intel_aes
INTEL_AESNIASM = $(INTEL_AESNI)/iaesx64

COMMON = ../../tresorcommon

CC		  = gcc
AR		  = ar
LD		  = gcc
EDGER		  = /opt/intel/sgxsdk/bin/x64/sgx_edger8r
SIGNER		  = /opt/intel/sgxsdk/bin/x64/sgx_sign
INCLUDE		  = -IInclude -IApp -I$(SGX_INCLUDE) -I$(SGX_INCLUDE)/tlibc -I$(INTEL_AESNI) -I$(COMMON)
T_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -g
U_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -g
AR_FLAGS	  = rcs
OBJECTS		  = tresorencl.o sha256.o pbkdf2.o hmac.o chash.o blockwise.o 
LIB_SGX_TRTS      = -lsgx_trts
LIB_SGX_TSERVICE  = -lsgx_tservice

ENCLAVE_LIBS      = $(LIB_SGX_TRTS)
ENCLAVE_LIB_PARTS = -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice $(LIB_SGX_TSERVICE)
ENCLAVE	          = tresorencl
PRIVATE_KEY       = private_key.pem
PUBLIC_KEY        = public_key.pem
KEY_SIZE          = 3072
ENCLAVE_EDL       = $(ENCLAVE).edl
ENCLAVE_CONFIG    = $(ENCLAVE).config.xml
OUTPUT_T          = $(ENCLAVE).so
OUTPUT_T_UNSIG    = $(ENCLAVE).unsigned.so
OUTPUT_U          = lib$(ENCLAVE)_proxy.a
LIB_DIRS          = -L$(SGX_LIBRARY_PATH)
LD_FLAGS	  = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
                    -Wl,--whole-archive -Wl,--start-group $(ENCLAVE_LIBS) -Wl,--end-group \
                    -Wl,--no-whole-archive -Wl,--start-group $(ENCLAVE_LIB_PARTS) -Wl,--end-group \
                    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                    -Wl,--defsym,__ImageBase=0 
TRUSTED_OBJECTS   = $(ENCLAVE)_t.o
UNTRUSTED_OBJECTS = $(ENCLAVE)_u.o 
TRUSTED_CODE      = $(ENCLAVE)_t.h $(ENCLAVE)_t.c
UNTRUSTED_CODE    = $(ENCLAVE)_u.h $(ENCLAVE)_u.c

#.SILENT:
all: $(OUTPUT_T) $(OUTPUT_U)

$(OUTPUT_T) : $(TRUSTED_OBJECTS) $(OBJECTS)
	yasm -D__linux__ -g dwarf2 -f elf64 $(INTEL_AESNIASM).s -o $(INTEL_AESNIASM).o
	gcc -O3 -g -m64 -I./ -c $(INTEL_AESNIC).c -o $(INTEL_AESNIC).o -fPIC

	$(LD) $(OBJECTS) $(TRUSTED_OBJECTS) $(LD_FLAGS) $(LIB_DIRS)  -o $(OUTPUT_T_UNSIG) $(INTEL_AESNIC).o $(INTEL_AESNIASM).o -fPIC
	$(SIGNER) sign -key $(PRIVATE_KEY) -enclave $(OUTPUT_T_UNSIG) -out $(OUTPUT_T) -config $(ENCLAVE_CONFIG)

$(OUTPUT_U) : $(UNTRUSTED_OBJECTS) 
	$(AR) $(AR_FLAGS) $(OUTPUT_U) $(UNTRUSTED_OBJECTS) 
	
%_t.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(trusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(T_CFLAGS) $(subst .o,.c,$@)	
	

%_u.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(untrusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(U_CFLAGS) $(subst .o,.c,$@)

%.o : %.c edger
	echo "$(INDENT)[CC] " $< "(core)"
	$(CC) $(INCLUDE) $(T_CFLAGS) -c $<

edger: $(ENCLAVE).edl
	echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL)
	
.PHONY: force_check
force_check:
	true

.PHONY: scrub
scrub: 
	echo "$(INDENT)[RM]  " $(PRIVATE_KEY) $(PUBLIC_KEY)
	$(RM) $(PRIVATE_KEY) $(PUBLIC_KEY)

.PHONY: configure
configure: 
	echo "$(INDENT)[GEN] $(PRIVATE_KEY) ($(KEY_SIZE) bits)"

	# generate 3072 bit private RSA key
	openssl genrsa -out $(PRIVATE_KEY) -3 $(KEY_SIZE)
	
	echo "$(INDENT)[EXT] $(PUBLIC_KEY)"
	# extract public key
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY) 
	
	# sign enclave
	#sgx_sign sign -key private_key.pem -enclave Enclave/tresorencl.so -out tresorencl.signed.so
	
.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(OBJECTS)
	$(RM) $(OBJECTS)
	
	echo "$(INDENT)[RM]" $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	$(RM) $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	
	echo "$(INDENT)[RM]" $(TRUSTED_OBJECTS)
	$(RM) $(TRUSTED_OBJECTS)
	
	echo "$(INDENT)[RM]" $(TRUSTED_CODE)
	$(RM) $(TRUSTED_CODE)
	
	echo "$(INDENT)[RM]" $(UNTRUSTED_OBJECTS)
	$(RM) $(UNTRUSTED_OBJECTS)
	
	echo "$(INDENT)[RM]" $(UNTRUSTED_CODE)
	$(RM) $(UNTRUSTED_CODE)
	
	echo "$(INDENT)[RM]" $(OUTPUT_U)
	$(RM) $(OUTPUT_U)
	

