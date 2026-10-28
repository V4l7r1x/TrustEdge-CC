# TrustEdge-CC: Confidential Federated Anomaly Detection for Resource-Constrained IoT Edge Networks Using Heterogeneous ARM TrustZone TEEs

**Project Group Members:**
- Sonu Biju 
- Avesh V Pillai 
- Gagan Pradeep 
- Sajitha P S 

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Zero-Trust Orchestrator         |
                      |   (FastAPI / Flask Secure Server)     |
                      |  - Cryptographic Gatekeeper (ECDSA)   |
                      |  - Additive Aggregator (FedAvg)       |
                      |  - Poisoning Defense Engine           |
                      |  - Real-time Cyber Security Dashboard |
                      +-------------------+-------------------+
                                          |
        +---------------------------------+---------------------------------+
        | (mTLS / REST / WebSocket)       |                                 |
        v                                 v                                 v
+-----------------------+     +-----------------------+     +-----------------------+
|       Node 1          |     |       Node 2          |     |       Node 3          |
|      QEMU Node        |     |     Pico 1 Device     |     |     Pico 2 Device     |
|(ARM Cortex-A TrustZone|     | (RP2350 TrustZone-M)  |     | (RP2350 TrustZone-M)  |
|       OP-TEE)         |     |        TF-M)          |     |        TF-M)          |
| - Isolation Forest TA |     | - Isolation Forest    |     | - Isolation Forest    |
| - Hardware-Sealed Key |     | - Sealed OTP Key      |     | - Sealed OTP Key      |
| - AES-GCM Encryption  |     | - AES-GCM Encryption  |     | - AES-GCM Encryption  |
| - Virtual Telemetry   |     | - Physical DHT11      |     | - Physical DHT11      |
+-----------------------+     +-----------------------+     +-----------------------+
```

---

## Key Modules Implemented

1. **Module 1: IoT Data Collection**  
   Collects temperature and humidity readings using the DHT11 sensor connected to Raspberry Pi Pico 2 boards on GPIO 15 (with virtual telemetry replay for QEMU).
2. **Module 2: Secure Execution Environment (Heterogeneous TEEs)**  
   - **ARM Cortex-A (QEMU):** OP-TEE Trusted Application with GlobalPlatform API.
   - **RP2350 Cortex-M33 (Pico 2):** Trusted Firmware-M (TF-M) Secure World partition.
3. **Module 3: In-TEE Anomaly Detection**  
   Isolation Forest anomaly detection executes entirely inside Secure RAM. Memory footprint is strictly kept under **160 KB** (empirically ~14.7 KB), making it ideal for microcontrollers.
4. **Module 4: Cryptographic Security**  
   - **ECDSA NIST P-256 (secp256r1):** Digital signatures over update digests using hardware-sealed keys.
   - **AES-256-GCM:** Authenticated encryption for confidential model parameter transit.
   - **SHA-256:** Cryptographic integrity proofs.
5. **Module 5: Federated Aggregation & Orchestration**  
   Zero-Trust orchestrator verifies incoming TEE signatures before ensembling updates into the global forest. Corrupted updates or forged signatures are dropped instantly.
6. **Module 6: Monitoring & Security Dashboard**  
   Glassmorphism cyber-security dashboard with real-time WebSockets, live telemetry graphs, in-enclave anomaly score tracker, attack simulation buttons, and cryptographic audit logs.

---

## Directory Structure

```
trustedge-cc/
├── README.md
├── run_dashboard.sh             # Launch FastAPI dashboard on port 8000
├── run_qemu_node.sh             # Launch QEMU OP-TEE node
├── run_all_nodes.sh             # Launch QEMU + Pico 1 + Pico 2 simultaneously
├── common/
│   ├── crypto_utils.py          # ECDSA P-256 & AES-256-GCM cryptographic engine
│   └── isolation_forest.py      # Resource-constrained Federated Isolation Forest (<160KB RAM)
├── dashboard/
│   ├── server.py                # FastAPI REST & WebSocket server
│   ├── fl_orchestrator.py       # Zero-Trust gatekeeper & FedAvg aggregator
│   ├── static/
│   │   ├── css/dashboard.css    # Cyber security glassmorphism styling
│   │   └── js/app.js            # Live telemetry & Chart.js controller
│   └── templates/
│       └── index.html           # Command center web UI
├── qemu_node/
│   ├── qemu_runner.py           # QEMU OP-TEE edge node runner
│   ├── optee_ta/                # Native C OP-TEE Trusted Application source & Makefile
│   └── setup_qemu_optee.md      # Upstream OP-TEE QEMU build instructions
├── pico_nodes/
│   ├── pico_simulator.py        # RP2350 TF-M node simulator (for instant testing)
│   ├── pico_serial_bridge.py    # USB CDC UART relay for physical Pico 2 boards
│   ├── pico_micropython/        # Plug-and-play MicroPython firmware for Pico 2
│   │   └── main.py
│   └── pico_firmware/           # Native C Pico SDK firmware with DHT11 driver
│       ├── CMakeLists.txt
│       └── non_secure/main.c
└── tests/
    └── test_trustedge_e2e.py    # Complete automated validation test suite
```

---

## Step-by-Step Execution Guide

### Step 1: Start the Dashboard & Orchestrator
Open a terminal and run:
```bash
cd /home/valx/.gemini/antigravity/scratch/trustedge-cc
./run_dashboard.sh
```
Open your browser and navigate to: **`http://localhost:8000`**

---

### Step 2: Start the QEMU Node (ARM TrustZone-A / OP-TEE)
In a second terminal:
```bash
cd /home/valx/.gemini/antigravity/scratch/trustedge-cc
./run_qemu_node.sh
```
Watch the QEMU node authenticate via OP-TEE attestation, appear on the topology cards, and stream live DHT11 telemetry into the dashboard!

---

### Step 3: Connect Physical Pico 2 Boards (or Launch Simulators)

#### Option A: Immediate Simulation (Pico 1 & Pico 2)
In a third terminal:
```bash
# Launch Pico 1 (RP2350 TF-M)
python3 pico_nodes/pico_simulator.py --server http://localhost:8000 --node-id pico2-device-1

# Launch Pico 2 (RP2350 TF-M)
python3 pico_nodes/pico_simulator.py --server http://localhost:8000 --node-id pico2-device-2
```
Or launch all nodes in one go:
```bash
./run_all_nodes.sh
```

#### Option B: Connecting Physical Pico 2 Boards with DHT11
1. Connect DHT11 `DATA` pin to **GPIO 15**, `VCC` to **3.3V (Pin 36)**, and `GND` to **GND (Pin 38)** on the Pico 2.
2. Flash `pico_nodes/pico_micropython/main.py` or build the C firmware with Pico SDK.
3. Plug the Pico 2 into your computer via USB.
4. Launch the USB serial bridge:
```bash
python3 pico_nodes/pico_serial_bridge.py
```
The bridge auto-detects `/dev/ttyACM0` and relays sensor packets directly to the Orchestrator!

---

### Step 4: Federated Learning & Zero-Trust Defense Demo
1. **Trigger FL Round:** Click **"Trigger FL Round"** on the dashboard. Watch each node train its local forest inside its TEE, sign with ECDSA, encrypt with AES-GCM, and watch the orchestrator aggregate them into the Global Model.
2. **Inject Sensor Anomaly:** Click **"Toggle Sensor Anomaly"** on any node. Watch the in-enclave anomaly score spike above the `0.58` threshold and trigger the alert badge.
3. **Simulate Poisoning Attack:** Click **"Simulate Poisoning Attack"**. An adversarial update with forged signatures is dispatched. Watch the Zero-Trust Orchestrator flag and drop it instantly without corrupting the global model!
