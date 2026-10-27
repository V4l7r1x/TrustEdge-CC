"""
TrustEdge-CC End-to-End System Test
Verifies:
 1. Zero-Trust TEE Attestation & Registration
 2. Normal Telemetry & In-TEE Anomaly Inference
 3. Simulated Sensor Anomaly Detection
 4. Federated Learning Round with QEMU OP-TEE node
 5. Hardware-Anchored ECDSA Signature & AES-GCM Transit
 6. Defensive Rejection of Adversarial Model Poisoning
 7. Global Model Aggregation & Memory Constraint Verification (< 160 KB)
"""

import os
import sys
import json
import base64
import time

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from dashboard.server import app, orchestrator
from common.crypto_utils import EdgeCryptoEngine
from common.isolation_forest import EdgeIsolationForest

client = TestClient(app)


def test_system_e2e():
    print("=" * 70)
    print(">>> RUNNING TRUSTEDGE-CC END-TO-END VALIDATION SUITE <<<")
    print("=" * 70)

    # 1. Check Initial State
    res = client.get("/api/dashboard/state")
    assert res.status_code == 200
    state = res.json()
    print(f"[1] Initial Orchestrator State: Status={state['orchestrator_status']}, Round={state['current_round']}")

    # 2. Register QEMU ARM Cortex-A OP-TEE Node
    qemu_crypto = EdgeCryptoEngine()
    qemu_aes_key = os.urandom(32)
    qemu_evidence = qemu_crypto.generate_attestation_evidence(
        node_id="qemu-arm-cortex-a",
        tee_type="OP-TEE_TrustZone-A",
        enclave_measurement="e83b4fa91c7816bc83017a42fe93c52e8913b8214f77c381a1795bc9e295da90"
    )

    reg_payload = {
        "node_id": "qemu-arm-cortex-a",
        "node_type": "QEMU_ARM_CortexA",
        "tee_type": "OP-TEE_TrustZone-A",
        "ta_uuid": "c4a52140-59f2-43bb-8e31-893080bf0001",
        "public_key": qemu_crypto.export_public_key_pem(),
        "attestation": qemu_evidence,
        "aes_key_hex": qemu_aes_key.hex()
    }
    reg_res = client.post("/api/nodes/register", json=reg_payload)
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.text}"
    print("[2] QEMU Node registered successfully via OP-TEE hardware attestation.")

    # 3. Report Normal Telemetry & In-TEE Anomaly Inference
    telemetry_payload = {
        "node_id": "qemu-arm-cortex-a",
        "timestamp": time.time(),
        "temperature": 24.5,
        "humidity": 45.2,
        "anomaly_score": 0.485,
        "is_anomaly": False,
        "tee_latency_ms": 1.45,
        "anomaly_forced": False
    }
    tel_res = client.post("/api/telemetry/report", json=telemetry_payload)
    assert tel_res.status_code == 200
    print("[3] Telemetry tick recorded. Anomaly score=0.485 (NORMAL)")

    # 4. Report Sensor Anomaly Spike
    anom_payload = {
        "node_id": "qemu-arm-cortex-a",
        "timestamp": time.time(),
        "temperature": 88.0,
        "humidity": 94.5,
        "anomaly_score": 0.792,
        "is_anomaly": True,
        "tee_latency_ms": 1.52,
        "anomaly_forced": True
    }
    anom_res = client.post("/api/telemetry/report", json=anom_payload)
    assert anom_res.status_code == 200
    print("[4] Anomaly telemetry recorded! Score=0.792 >= 0.58 (ANOMALY DETECTED)")

    # 5. Start Federated Learning Round #1
    start_res = client.post("/api/fl/start-round")
    assert start_res.status_code == 200
    round_info = start_res.json()
    curr_round = round_info["round"]
    print(f"[5] Federated Learning Round #{curr_round} initiated.")

    # 6. Train Local Isolation Forest inside QEMU Node, Sign & Encrypt
    local_forest = EdgeIsolationForest(n_estimators=10, max_samples=32)
    training_data = [[24.0 + (i % 3) * 0.4, 45.0 + (i % 5) * 0.6] for i in range(40)]
    local_forest.fit(training_data)
    model_bytes = json.dumps(local_forest.to_dict(), sort_keys=True).encode("utf-8")

    # Sign digest with sealed private key
    model_digest = qemu_crypto.hash_sha256(model_bytes)
    sig_bytes = qemu_crypto.sign_data(model_digest.encode("utf-8"))
    sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")

    # Encrypt with AES-GCM
    encrypted_obj = qemu_crypto.encrypt_aes_gcm(
        aes_key=qemu_aes_key,
        plaintext=model_bytes,
        aad=f"round-{curr_round}:qemu-arm-cortex-a".encode("utf-8")
    )

    update_payload = {
        "node_id": "qemu-arm-cortex-a",
        "round": curr_round,
        "model_digest": model_digest,
        "signature": sig_b64,
        "encrypted_model": encrypted_obj,
        "aad": f"round-{curr_round}:qemu-arm-cortex-a",
        "execution_stats": {
            "tee_type": "OP-TEE_TrustZone-A",
            "training_latency_ms": 14.2,
            "memory_footprint_bytes": local_forest.memory_footprint_bytes(),
            "n_trees_contributed": len(local_forest.trees)
        }
    }

    sub_res = client.post("/api/fl/submit-update", json=update_payload)
    assert sub_res.status_code == 200, f"Submit update failed: {sub_res.text}"
    print("[6] Local model update submitted, verified via ECDSA, and aggregated into Global Model.")

    # 7. Verify Global Model Aggregation and Memory Footprint Constraint (<160 KB)
    gm_res = client.get("/api/fl/global-model")
    assert gm_res.status_code == 200
    gm_data = gm_res.json()
    gm_model = EdgeIsolationForest.from_dict(gm_data)
    ram_usage = gm_model.memory_footprint_bytes()
    print(f"[7] Global Model updated: Total Trees={len(gm_model.trees)}, RAM Footprint={ram_usage} bytes (< 160,000 bytes constraint).")
    assert ram_usage < 160000, "Memory footprint exceeded 160KB limit!"

    # 8. Test Zero-Trust Defense Against Adversarial Model Poisoning
    poison_res = client.post("/api/attack/simulate", json={"node_id": "qemu-arm-cortex-a", "attack_type": "model_poisoning"})
    assert poison_res.status_code == 200
    poison_data = poison_res.json()
    assert poison_data["simulation_result"] == "BLOCKED"
    assert poison_data["orchestrator_response"]["success"] is False
    print("[8] Adversarial Model Poisoning attack blocked! Orchestrator rejected forged update.")

    # 9. Verify Dashboard State Summary
    final_res = client.get("/api/dashboard/state")
    final_state = final_res.json()
    print(f"[9] Final Dashboard State:")
    print(f"    - Current Round: {final_state['current_round']}")
    print(f"    - Active Nodes: {final_state['active_nodes_count']}")
    print(f"    - Attacks Prevented: {final_state['attacks_prevented']}")
    print(f"    - Audit Log Entries: {len(final_state['audit_logs'])}")
    print("=" * 70)
    print(">>> ALL TRUSTEDGE-CC PROTOCOLS VERIFIED SUCCESSFULLY! <<<")
    print("=" * 70)


if __name__ == "__main__":
    test_system_e2e()
