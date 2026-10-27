#!/usr/bin/env bash
# TrustEdge-CC: Launch All Heterogeneous Nodes (QEMU + Pico 1 + Pico 2)
cd "$(dirname "$0")"

trap "kill 0" EXIT

echo "=== Launching TrustEdge-CC Heterogeneous Edge Topology ==="
echo "[1/3] Starting QEMU ARM TrustZone-A Node..."
python3 qemu_node/qemu_runner.py --server http://localhost:8000 --node-id qemu-arm-cortex-a &
PID1=$!

sleep 1
echo "[2/3] Starting Pico 1 Device (RP2350 Cortex-M33 / TF-M)..."
python3 pico_nodes/pico_simulator.py --server http://localhost:8000 --node-id pico2-device-1 &
PID2=$!

sleep 1
echo "[3/3] Starting Pico 2 Device (RP2350 Cortex-M33 / TF-M)..."
python3 pico_nodes/pico_simulator.py --server http://localhost:8000 --node-id pico2-device-2 &
PID3=$!

echo "All 3 heterogeneous edge nodes running! Press Ctrl+C to stop all."
wait
