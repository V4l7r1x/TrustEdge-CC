# TrustEdge-CC: QEMU OP-TEE Node Guide

This module provides the **ARM Cortex-A TrustZone-A OP-TEE edge node** for the TrustEdge-CC federated anomaly detection system.

---

## 1. Fast Standalone Mode (High-Fidelity OP-TEE Runtime)

The standalone runner implements the complete OP-TEE GlobalPlatform protocol, isolation forest training in secure memory, ECDSA P-256 signing with hardware-sealed identity, and AES-256-GCM encryption without requiring external compilation:

```bash
# From project root
python3 qemu_node/qemu_runner.py --server http://localhost:8000 --node-id qemu-arm-cortex-a
```

---

## 2. Upstream OP-TEE on QEMU ARMv8 / ARMv7 Compilation Guide

If you wish to build and boot the complete upstream OP-TEE Linux stack on QEMU:

### Prerequisites:
```bash
sudo apt update
sudo apt install -y android-tools-adb android-tools-fastboot autoconf \
    automake bc bison build-essential ccache cscope curl device-tree-compiler \
    expect flex ftp-upload gdisk iasl libattr1-dev libcap-dev libfdt-dev \
    libftdi-dev libglib2.0-dev libgmp-dev libhidapi-dev libmpc-dev \
    libncurses5-dev libpixman-1-dev libssl-dev libtool make \
    mtools netcat ninja-build python3-crypto python3-cryptography \
    python3-pip python3-pyelftools rsync unzip uuid-dev xdg-utils \
    xterm xz-utils zlib1g-dev qemu-system-arm qemu-system-aarch64
```

### Build OP-TEE for QEMUv8 (Cortex-A53 / A72 TrustZone):
```bash
mkdir -p ~/optee-project && cd ~/optee-project
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync -j4

# Build toolchains and QEMU image
cd build
make -j2 toolchains
make -j$(nproc)

# Copy TrustEdge-CC TA into the TA directory
cp -r /home/valx/.gemini/antigravity/scratch/trustedge-cc/qemu_node/optee_ta optee_examples/trustedge_ta

# Run QEMU with OP-TEE
make run
```

Inside the QEMU terminal:
```bash
# Inside Normal World (Linux REE):
xtest
# Launch TrustEdge-CC host client
python3 /root/qemu_runner.py
```
