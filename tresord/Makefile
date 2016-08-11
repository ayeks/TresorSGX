SGX_SDK ?= /opt/intel/sgxsdk
SGX_INCLUDE = $(SGX_SDK)/include
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
NETLINK_INCLUDE = /usr/include/libnl3
NETLINK_LIB = /lib/x86_64-linux-gnu
COMMON               = ../tresorcommon
ENCLDIRS              = ../tresorencl/Enclave


CC                   = gcc
AS                   = gcc
AR                   = ar
LD                   = gcc
CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables -fno-common -Wno-attributes -g
ARFLAGS              = -rcs
#INCLUDE		     = -IInclude -IApp -I$(SGX_INCLUDE)
OBJECTS              = tresord.o
INCLUDE		     = -IInclude -IApp -I$(SGX_INCLUDE) -I$(NETLINK_INCLUDE) -I$(COMMON) -I$(ENCLDIRS)
LIB_SGX_URTS         = -lsgx_urts
LIB_UAE_SERVICE      = -lsgx_uae_service

LIBS                 = -ltresorencl_proxy $(LIB_SGX_URTS) $(LIB_UAE_SERVICE) -lpthread -lnl-genl-3 -lnl-3
LIB_DIRS             = $(ENCLDIRS:%=-L %)                                            \
			$(patsubst %,-L%,$(subst :, ,$(SGX_LIBRARY_PATH))) -L$(NETLINK_LIB)
BUILDDIRS            = $(ENCLDIRS:%=build-%)
CLEANDIRS            = $(ENCLDIRS:%=clean-%)
SCRUBDIRS            = $(ENCLDIRS:%=scrub-%)
CONFIGDIRS           = $(ENCLDIRS:%=config-%)
INSTALLDIRS          = $(ENCLDIRS:%=install-%)
UNINSTALLDIRS        = $(ENCLDIRS:%=uninstall-%)
OUTPUT               = tresord

.SILENT:
all:	$(OUTPUT)
	
$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	#echo "[   building   ]"
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT)
	$(LD) $(OBJECTS) $(LIB_DIRS) $(LIBS) -o $(OUTPUT)
	
%.o : %.c
	echo "$(INDENT)[CC]" $<
	echo $(CC) $(CFLAGS) $(INCLUDE) -c $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

.PHONY: scrub
scrub:  $(SCRUBDIRS)
	#echo "[   scrubbing   ]"

.PHONY: configure
configure: $(CONFIGDIRS)
	#echo "[   configuring   ]"
	
.PHONY: install
install:  $(INSTALLDIRS)
	#echo "[   installing   ]"

.PHONY: uninstall
uninstall: $(UNINSTALLDIRS)
	#echo "[   uninstalling   ]"

.PHONY: clean
clean: $(CLEANDIRS)
	#echo "[   cleaning   ]"
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS)
	rm -f $(OUTPUT)
	
$(BUILDDIRS): force_check
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS): force_check
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(SCRUBDIRS): force_check
	echo "$(INDENT)[===] $(@:scrub-%=%) [===]"
	$(MAKE) scrub -C $(@:scrub-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CONFIGDIRS): force_check
	echo "$(INDENT)[===] $(@:config-%=%) [===]"
	$(MAKE) configure -C $(@:config-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(INSTALLDIRS): force_check
	echo "$(INDENT)[===] $(@:install-%=%) [===]"
	$(MAKE) install -C $(@:install-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(UNINSTALLDIRS): force_check
	echo "$(INDENT)[===] $(@:uninstall-%=%) [===]"
	$(MAKE) uninstall -C $(@:uninstall-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

force_check:
	true

