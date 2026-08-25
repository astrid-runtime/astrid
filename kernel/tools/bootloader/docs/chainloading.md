# Chainloading

Chainloading is a technique that allows one bootloader to call another bootloader as if the system had just booted up. [GNU GRUB](https://www.gnu.org/software/grub/) is one such bootloader which is commonly used for chainloading, as it presents a menu which you can use to select the OS you'd like to boot from. We're using `grub2` here.

Create a file under `iso/boot/grub/grub.cfg` in the root directory of your OS's source tree. In it, put:

```
menuentry "myOS" {
	chainloader (hd1)+1
}
```

This tells grub that our binary is installed on the first partition of the `hd1` disk. If you're trying to boot on real hardware you may need to edit this value as appropriate. Alternatively, you should be able to create a partition on the same ISO file that grub creates and copy the binary there.

Next, create the ISO with:
```
grub-mkrescue -o grub.iso iso
```

Testing with QEMU (replacing `my_os` with the name of your OS's target):
```
qemu-system-x86_64 -hda grub.iso -hdb target/x86_64-my_os/debug/bootimage-my_os.bin
```
