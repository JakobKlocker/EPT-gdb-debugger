#!/bin/bash
KVM_MOD="/home/jakob/ept_debugger/linux-16.9/arch/x86/kvm/kvm.ko"
KVM_INTEL_MOD="/home/jakob/ept_debugger/linux-16.9/arch/x86/kvm/kvm-intel.ko"

echo "[*] Shutting down KVM modules..."

sudo rmmod kvm_intel 
sudo rmmod kvm 

if lsmod | grep -q "kvm"; then
    echo "[!] ERROR: KVM modules are still in use! Is QEMU still running?"
    exit 1
fi

echo "[*] Loading new modules from build directory..."

sudo insmod $KVM_MOD
sudo insmod $KVM_INTEL_MOD enable_pml=0

sudo chmod 666 /dev/kvm 
