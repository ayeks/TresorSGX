echo "shutdown test tresorsgx"

echo "rmmod test_tresor_lkm"
sudo rmmod ./test_tresor_lkm/test_tresor_lkm.ko

sleep 2

echo "kill tresord"
sudo kill -15 $(pidof ./tresord/tresord)

sleep 2

echo "rmmod tresorlkm"
sudo rmmod ./tresorlkm/tresorlkm.ko