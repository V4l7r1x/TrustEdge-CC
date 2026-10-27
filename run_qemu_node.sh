#!/usr/bin/env bash
# TrustEdge-CC: Launch QEMU ARM Cortex-A OP-TEE Node
cd "$(dirname "$0")"
echo "=== Starting QEMU ARM TrustZone-A OP-TEE Node ==="
python3 qemu_node/qemu_runner.py --server http://localhost:8000 --node-id qemu-arm-cortex-a
