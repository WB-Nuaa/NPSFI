# How Bit Flips Disrupt Networking: Revealing Vulnerability in the Linux Kernel Network Protocol Stack (NPSFI)

## Overview
Each folder is a function and contains the error information, instruction information, and logs.
The most important files in each folder are as follows:
- error.log: the error information after each bit of each instruction in the function is flipped.
- received_data.log: the packet received by the client.
- result: contains detailed error information.
- addr_instruction.json: the information and addresses of each instruction in the function.
- analyse.py or analyse-origin.py: a program for analyzing functions.
  
## Environmental configuration
- Linux kernel: 5.4.18
- QEMU: 6.2.0, the parameters are as follows:
  - qemu-system-aarch64 \
      -machine virt \
      -nographic \
      -m size=2048M \
      -cpu cortex-a72 \
      -smp 8 \
      -kernel ./arch/arm64/boot/Image \
      -drive format=raw,file=init.img,id=hd0,if=none \
      -device virtio-blk-device,drive=hd0 \
      -append "noinitrd root=/dev/vda rw nokaslr console=ttyAMA0 loglevel=8" > qemu.log\
      -monitor telnet:127.0.0.1:4444,server,nowait \
      -gdb tcp::1234 -S \
      -netdev socket,id=net0,udp=192.168.1.100:5000,localaddr=192.168.1.110:5000 \
      -device e1000,netdev=net0 \
      -netdev user,id=user0 \
      -device e1000,netdev=user0 
- numpy: 1.18.5
- 
