# Runscript compiles all parts of the system and executes them in the correct order
# The test_tresor_lkm tests the TresorSGX Crypto API module from kernel space

echo "running test tresorsgx"

# Step 1: make all system components
echo "Step 1: make components"

# Step 1.1: create RSA keypair for enclave signing
cd tresorencl/Enclave;
if make 2>&1 | grep -q "error"
    then echo "ERROR during enclave make configure"; make configure; exit 1;
    else echo "SUCCESS creating RSA key pair for enclave"
fi
cd ../..

# Step 1.2: make the daemon
cd tresord;
if make 2>&1 | grep -q "error:"
    then echo "ERROR found in TRESORD"; make; exit 1;
    else echo "SUCCESS making TRESORD"
fi
cd ..

# Step 1.3: make the kernel module
cd tresorlkm;
if make 2>&1 | grep -q "error:"
    then echo "ERROR found in tresorlkm"; make; exit 1;
    else echo "SUCCESS making tresorlkm"
fi
cd ..

# Step 1.4: optional for usage, simply tests TresorSGX after initialisation
cd test_tresor_lkm;
if make 2>&1 | grep -q "error:"
    then echo "ERROR found in test_tresor_lkm"; make; exit 1;
    else echo "SUCCESS making test_tresor_lkm"
fi
cd ..

# Step 2: load the kernel module
echo "Step 2: insmod tresorlkm"
sudo insmod ./tresorlkm/tresorlkm.ko

sleep 2

# Step 3: execute the daemon
echo "Step 3: run tresord"
./tresord/tresord

# Step 4: check if the key setting by pipe is enabled, if so make and start the key setter
echo "Step 4: check if set key by pipe is activated.."
if grep -q 'SETKEY_BYPIPE\s*(1)' ./tresorcommon/tresorcommon.h 
    then echo "SETKEY_BYPIPE == 1"; cd ./tresor_setkey/; make; cd ..; echo "insert user password:"; ./tresor_setkey/tresor_setkey
    else echo "SETKEY_BYPIPE == 0"
fi

sleep 2

# Step 5: load the test kernel module
echo "Step 5: insmod test_tresor_lkm"
sudo insmod ./test_tresor_lkm/test_tresor_lkm.ko

sleep 2

# print the last lines of the syslog. search for "test_tresor_lkm: ended successfully"
echo "Step 6: Print syslog:"
tail -n 10 /var/log/syslog
