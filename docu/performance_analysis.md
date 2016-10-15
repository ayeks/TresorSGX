# Performance analysis with hdparm and dd 

The performance of TresorSGX was compared to a non-encrypted plain partition, a standard AES encrypted partition and a TresorSGX encrypted partition.

## Summarized Results

The testing platform was a *2015 Dell Inspiron 7559* with an *Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz*, *16GiB System memory* and a *Seagate ST1000LM024 HN-M* hard drive. The operating system was an *Ubuntu 15.10* running the Linux kernel version *4.4.7*.

Three different partitions were mounted on the same hard disk for the evaluation. 24 tests were executed before calculating the median of the results. The Linux [dd](http://linux.die.net/man/1/dd) tool was used to analyse the write performance and [hdparm](http://linux.die.net/man/8/hdparm) for measuring the read performance. hdparm was executed with the -t and -T option. The first option performs uncached disk reads. The buffer cache is cleared before performing the read. The second option performs cached reads, which displays the reading speed from the Linux buffer cache without disk access. 

| Test Results in MB/s | Plain | AES | TresorSGX |
|------|-------|-----|-----------|
|dd 100mb block write | 107 | 104.5 | 1.1 |
|hdparm uncached read |  110.14 | 113.7 | 1.125 |
|hdparm cached read | 13289.53 | 12004.325 | 1576.69 |

TresorSGX achieves about 1% of the read / write performance on disk and about 10% the read performance from the buffer cache. To write one block encrypted on disk the system must send the data block over the Netlink bus to the daemon. The daemon must enter the enclave, which is another context switch. The enclave encrypts the block using the AESNI instructions. The enclave returns the encrypted block, which is send over the Netlink bus back to the Tresor kernel module. TresorSGX works as proof of concept and its performance can be improved in future work. The usage of **SYS V Message Queues** and **SYS V Shared Memory** should result in a much better performance.

## Setup

Create TresorSGX partition:
```
sudo cryptsetup create testtresorsgx /dev/sdb7 --cipher tresorsgx --key-size 128
mkfs.ext2 /dev/mapper/testtresorsgx
mount /dev/mapper/testtresorsgx /media/testtresorsgx/
```

Create AES Partition:
```
sudo cryptsetup create testaes /dev/sdb8 --cipher aes --key-size 128
mkfs.ext2 /dev/mapper/testaes
mount /dev/mapper/testaes /media/testaes/
```

## Run test

Modify and execute `./perf_test.sh` or use the following snippet on the mapped partitions. It will run each test 24 times.

```
NAME=testtresorsgx

for i in `seq 1 24`;
do
	sudo dd if=/dev/zero of=/media/$NAME/tempfile bs=100M count=1 conv=fdatasync,notrunc 2>&1 | tail -n 1
done 

for i in `seq 1 24`;
do
	sudo hdparm -t /dev/mapper/$NAME | tail -n 1
done 

for i in `seq 1 24`;
do
	sudo hdparm -T /dev/mapper/$NAME | tail -n 1
done
```

## Full Results

### PLAIN
```
104857600 bytes (105 MB) copied, 1,02306 s, 102 MB/s
104857600 bytes (105 MB) copied, 0,977272 s, 107 MB/s
104857600 bytes (105 MB) copied, 0,96648 s, 108 MB/s
104857600 bytes (105 MB) copied, 0,988197 s, 106 MB/s
104857600 bytes (105 MB) copied, 0,976765 s, 107 MB/s
104857600 bytes (105 MB) copied, 0,99923 s, 105 MB/s
104857600 bytes (105 MB) copied, 0,966252 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,965689 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,995176 s, 105 MB/s
104857600 bytes (105 MB) copied, 1,00347 s, 104 MB/s
104857600 bytes (105 MB) copied, 0,999203 s, 105 MB/s
104857600 bytes (105 MB) copied, 0,964882 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,971862 s, 108 MB/s
104857600 bytes (105 MB) copied, 0,977336 s, 107 MB/s
104857600 bytes (105 MB) copied, 1,00826 s, 104 MB/s
104857600 bytes (105 MB) copied, 1,12039 s, 93,6 MB/s
104857600 bytes (105 MB) copied, 0,978891 s, 107 MB/s
104857600 bytes (105 MB) copied, 0,965869 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,965598 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,965786 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,998971 s, 105 MB/s
104857600 bytes (105 MB) copied, 1,00774 s, 104 MB/s
104857600 bytes (105 MB) copied, 0,990196 s, 106 MB/s
104857600 bytes (105 MB) copied, 0,965692 s, 109 MB/s
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.13 MB/sec
Timing buffered disk reads: 330 MB in  3.01 seconds = 109.67 MB/sec
Timing buffered disk reads: 330 MB in  3.01 seconds = 109.66 MB/sec
Timing buffered disk reads: 332 MB in  3.02 seconds = 110.11 MB/sec
Timing buffered disk reads: 332 MB in  3.02 seconds = 110.12 MB/sec
Timing buffered disk reads: 332 MB in  3.02 seconds = 110.11 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.12 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.14 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.13 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.13 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.13 MB/sec
Timing buffered disk reads: 328 MB in  3.00 seconds = 109.33 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.16 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.14 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.14 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.16 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.15 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.16 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.17 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.16 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.16 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.17 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.18 MB/sec
Timing buffered disk reads: 332 MB in  3.01 seconds = 110.18 MB/sec
Timing cached reads:   25644 MB in  2.00 seconds = 12836.07 MB/sec
Timing cached reads:   24894 MB in  2.00 seconds = 12460.96 MB/sec
Timing cached reads:   25600 MB in  2.00 seconds = 12814.92 MB/sec
Timing cached reads:   26192 MB in  2.00 seconds = 13112.28 MB/sec
Timing cached reads:   25402 MB in  2.00 seconds = 12715.69 MB/sec
Timing cached reads:   27232 MB in  2.00 seconds = 13633.27 MB/sec
Timing cached reads:   25358 MB in  2.00 seconds = 12702.80 MB/sec
Timing cached reads:   22482 MB in  2.00 seconds = 11252.19 MB/sec
Timing cached reads:   27932 MB in  2.00 seconds = 13983.15 MB/sec
Timing cached reads:   26548 MB in  2.00 seconds = 13289.36 MB/sec
Timing cached reads:   27696 MB in  2.00 seconds = 13864.80 MB/sec
Timing cached reads:   26278 MB in  2.00 seconds = 13154.02 MB/sec
Timing cached reads:   27136 MB in  2.00 seconds = 13589.09 MB/sec
Timing cached reads:   26708 MB in  2.00 seconds = 13369.61 MB/sec
Timing cached reads:   28104 MB in  2.00 seconds = 14070.00 MB/sec
Timing cached reads:   27264 MB in  2.00 seconds = 13648.28 MB/sec
Timing cached reads:   27826 MB in  2.00 seconds = 13929.95 MB/sec
Timing cached reads:   24870 MB in  2.00 seconds = 12448.85 MB/sec
Timing cached reads:   26548 MB in  2.00 seconds = 13289.70 MB/sec
Timing cached reads:   26450 MB in  2.00 seconds = 13240.17 MB/sec
Timing cached reads:   26514 MB in  2.00 seconds = 13271.94 MB/sec
Timing cached reads:   26736 MB in  2.00 seconds = 13383.77 MB/sec
Timing cached reads:   26660 MB in  2.00 seconds = 13345.51 MB/sec
Timing cached reads:   26938 MB in  2.00 seconds = 13485.47 MB/sec
```

### AES
```
104857600 bytes (105 MB) copied, 1,18115 s, 88,8 MB/s
104857600 bytes (105 MB) copied, 1,02872 s, 102 MB/s
104857600 bytes (105 MB) copied, 0,966114 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,965683 s, 109 MB/s
104857600 bytes (105 MB) copied, 0,966563 s, 108 MB/s
104857600 bytes (105 MB) copied, 0,997715 s, 105 MB/s
104857600 bytes (105 MB) copied, 0,989554 s, 106 MB/s
104857600 bytes (105 MB) copied, 0,981488 s, 107 MB/s
104857600 bytes (105 MB) copied, 0,994705 s, 105 MB/s
104857600 bytes (105 MB) copied, 0,954451 s, 110 MB/s
104857600 bytes (105 MB) copied, 0,995095 s, 105 MB/s
104857600 bytes (105 MB) copied, 1,02202 s, 103 MB/s
104857600 bytes (105 MB) copied, 1,1182 s, 93,8 MB/s
104857600 bytes (105 MB) copied, 1,03035 s, 102 MB/s
104857600 bytes (105 MB) copied, 1,0205 s, 103 MB/s
104857600 bytes (105 MB) copied, 1,19903 s, 87,5 MB/s
104857600 bytes (105 MB) copied, 1,33448 s, 78,6 MB/s
104857600 bytes (105 MB) copied, 0,985027 s, 106 MB/s
104857600 bytes (105 MB) copied, 1,00159 s, 105 MB/s
104857600 bytes (105 MB) copied, 1,0296 s, 102 MB/s
104857600 bytes (105 MB) copied, 0,987914 s, 106 MB/s
104857600 bytes (105 MB) copied, 1,03266 s, 102 MB/s
104857600 bytes (105 MB) copied, 1,01218 s, 104 MB/s
104857600 bytes (105 MB) copied, 1,01608 s, 103 MB/s
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.66 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.65 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.66 MB/sec
Timing buffered disk reads: 340 MB in  3.01 seconds = 112.80 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.67 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.68 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.68 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.69 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.71 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.68 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.69 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.70 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.71 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.70 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.72 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.70 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.71 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.71 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.72 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.74 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.72 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.74 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.74 MB/sec
Timing buffered disk reads: 342 MB in  3.01 seconds = 113.74 MB/sec
Timing cached reads:   21870 MB in  2.00 seconds = 10946.90 MB/sec
Timing cached reads:   22282 MB in  2.00 seconds = 11151.74 MB/sec
Timing cached reads:   25484 MB in  2.00 seconds = 12759.09 MB/sec
Timing cached reads:   27594 MB in  2.00 seconds = 13814.17 MB/sec
Timing cached reads:   27638 MB in  2.00 seconds = 13837.99 MB/sec
Timing cached reads:   24220 MB in  2.00 seconds = 12123.35 MB/sec
Timing cached reads:   25230 MB in  2.00 seconds = 12628.97 MB/sec
Timing cached reads:   27330 MB in  2.00 seconds = 13682.14 MB/sec
Timing cached reads:   18246 MB in  2.00 seconds = 9131.30 MB/sec
Timing cached reads:   25460 MB in  2.00 seconds = 12744.31 MB/sec
Timing cached reads:   25398 MB in  2.00 seconds = 12714.44 MB/sec
Timing cached reads:   27814 MB in  2.00 seconds = 13924.96 MB/sec
Timing cached reads:   22722 MB in  2.00 seconds = 11372.56 MB/sec
Timing cached reads:   22362 MB in  2.00 seconds = 11192.19 MB/sec
Timing cached reads:   22248 MB in  2.00 seconds = 11138.35 MB/sec
Timing cached reads:   22702 MB in  2.00 seconds = 11365.54 MB/sec
Timing cached reads:   22588 MB in  2.00 seconds = 11309.10 MB/sec
Timing cached reads:   23740 MB in  2.00 seconds = 11885.30 MB/sec
Timing cached reads:   23426 MB in  2.00 seconds = 11725.43 MB/sec
Timing cached reads:   22756 MB in  2.00 seconds = 11393.50 MB/sec
Timing cached reads:   17574 MB in  2.00 seconds = 8799.93 MB/sec
Timing cached reads:   26858 MB in  2.00 seconds = 13448.88 MB/sec
Timing cached reads:   27634 MB in  2.00 seconds = 13834.35 MB/sec
Timing cached reads:   28184 MB in  2.00 seconds = 14110.11 MB/sec
```

### TRESORSGX

For additional information I enabled the monitoring of the netlink operations. In the following you can see the required netlink messages and callbacks for encrypting 105MB.

```
sudo dd if=/dev/zero of=/media/testtresorsgx/tempfile bs=100M count=1 conv=fdatasync,notrunc
	1+0 records in
	1+0 records out
	104857600 bytes (105 MB) copied, 91,5715 s, 1,1 MB/s

pre encrypt: 
	mon_nl_cb: 11252553, mon_nl_cb_fails:0, mon_nl_send:11252549, mon_nl_send_fails:0, mon_encrypt:11122947, mon_encrypt_fails:0, mon_decrypt:129601, mon_decrypt_fails:0, mon_setkey:4, mon_setkey_fails:0
post encrypt:
	mon_nl_cb: 17813065, mon_nl_cb_fails:0, mon_nl_send:17813061, mon_nl_send_fails:0, mon_encrypt:17683459, mon_encrypt_fails:0, mon_decrypt:129601, mon_decrypt_fails:0, mon_setkey:4, mon_setkey_fails:0
```

```
104857600 bytes (105 MB) copied, 92,3919 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,0696 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 90,8594 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,2528 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,1856 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 92,4903 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 92,0558 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,7607 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,2323 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,5721 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,2175 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,2368 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,4442 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,9309 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 90,7654 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 90,7294 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,1484 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,3997 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,0346 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,2326 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 91,1419 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,3237 s, 1,1 MB/s
104857600 bytes (105 MB) copied, 90,6785 s, 1,2 MB/s
104857600 bytes (105 MB) copied, 91,6027 s, 1,1 MB/s
Timing buffered disk reads:   4 MB in  3.41 seconds =   1.17 MB/sec
Timing buffered disk reads:   4 MB in  3.58 seconds =   1.12 MB/sec
Timing buffered disk reads:   4 MB in  3.57 seconds =   1.12 MB/sec
Timing buffered disk reads:   4 MB in  3.53 seconds =   1.13 MB/sec
Timing buffered disk reads:   4 MB in  3.71 seconds =   1.08 MB/sec
Timing buffered disk reads:   4 MB in  3.61 seconds =   1.11 MB/sec
Timing buffered disk reads:   4 MB in  3.58 seconds =   1.12 MB/sec
Timing buffered disk reads:   4 MB in  3.61 seconds =   1.11 MB/sec
Timing buffered disk reads:   4 MB in  3.52 seconds =   1.14 MB/sec
Timing buffered disk reads:   4 MB in  3.51 seconds =   1.14 MB/sec
Timing buffered disk reads:   4 MB in  3.68 seconds =   1.09 MB/sec
Timing buffered disk reads:   4 MB in  3.57 seconds =   1.12 MB/sec
Timing buffered disk reads:   4 MB in  3.46 seconds =   1.15 MB/sec
Timing buffered disk reads:   4 MB in  3.55 seconds =   1.13 MB/sec
Timing buffered disk reads:   4 MB in  3.60 seconds =   1.11 MB/sec
Timing buffered disk reads:   4 MB in  3.47 seconds =   1.15 MB/sec
Timing buffered disk reads:   4 MB in  3.51 seconds =   1.14 MB/sec
Timing buffered disk reads:   4 MB in  3.63 seconds =   1.10 MB/sec
Timing buffered disk reads:   4 MB in  3.48 seconds =   1.15 MB/sec
Timing buffered disk reads:   4 MB in  3.72 seconds =   1.08 MB/sec
Timing buffered disk reads:   4 MB in  3.57 seconds =   1.12 MB/sec
Timing buffered disk reads:   4 MB in  3.51 seconds =   1.14 MB/sec
Timing buffered disk reads:   4 MB in  3.52 seconds =   1.14 MB/sec
Timing buffered disk reads:   4 MB in  3.55 seconds =   1.13 MB/sec
Timing cached reads:   3542 MB in  2.00 seconds = 1771.19 MB/sec
Timing cached reads:   2056 MB in  2.00 seconds = 1028.09 MB/sec
Timing cached reads:   1890 MB in  2.00 seconds = 945.04 MB/sec
Timing cached reads:   2842 MB in  2.00 seconds = 1421.09 MB/sec
Timing cached reads:   3668 MB in  2.00 seconds = 1834.22 MB/sec
Timing cached reads:   3396 MB in  2.00 seconds = 1698.26 MB/sec
Timing cached reads:   3650 MB in  2.00 seconds = 1825.21 MB/sec
Timing cached reads:   3728 MB in  2.00 seconds = 1864.21 MB/sec
Timing cached reads:   3054 MB in  2.00 seconds = 1527.15 MB/sec
Timing cached reads:   3268 MB in  2.00 seconds = 1634.24 MB/sec
Timing cached reads:   1310 MB in  2.00 seconds = 655.00 MB/sec
Timing cached reads:   3446 MB in  2.00 seconds = 1723.21 MB/sec
Timing cached reads:   3008 MB in  2.00 seconds = 1504.13 MB/sec
Timing cached reads:   3090 MB in  2.00 seconds = 1545.20 MB/sec
Timing cached reads:   3328 MB in  2.00 seconds = 1664.23 MB/sec
Timing cached reads:   3204 MB in  2.00 seconds = 1602.15 MB/sec
Timing cached reads:   3168 MB in  2.00 seconds = 1584.13 MB/sec
Timing cached reads:   2618 MB in  2.00 seconds = 1309.13 MB/sec
Timing cached reads:   2808 MB in  2.00 seconds = 1404.13 MB/sec
Timing cached reads:   3314 MB in  2.00 seconds = 1657.19 MB/sec
Timing cached reads:   3024 MB in  2.00 seconds = 1512.10 MB/sec
Timing cached reads:   3138 MB in  2.00 seconds = 1569.25 MB/sec
Timing cached reads:   4088 MB in  2.00 seconds = 2044.29 MB/sec
Timing cached reads:   2164 MB in  2.00 seconds = 1082.08 MB/sec
```
