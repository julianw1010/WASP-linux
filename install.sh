sudo rm /boot/vmlinuz-6.15*
sudo rm /boot/initrd.img-6.15*
git pull
git log -1 --pretty=format:"%h %s (%ci)"
make -j$(nproc)
sudo make modules_install
sudo make install
gcc -o waspd waspd.c
