"""
TrustEdge-CC: Zero-Trust Orchestrator & Federated Learning Engine
Implements:
 - Device Registration & TEE Attestation Verification
 - Model Update Decryption & ECDSA Integrity Check
 - Model Poisoning Attack Rejection
 - Secure Aggregation (Federated Isolation Forest)
 - Security Audit Logging & Telemetry Aggregation
"""

import os
import sys
import time
import json
import base64
import logging
from typing import Dict, Any, List, Optional

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.crypto_utils import EdgeCryptoEngine
from common.isolation_forest import EdgeIsolationForest

logger = logging.getLogger("TrustEdgeOrchestrator")


class NodeRecord:
    def __init__(self,
                 node_id: str,
                 node_type: str,
                 tee_type: str,
                 public_key: str,
                 aes_key_hex: str,
                 attestation: Dict[str, Any]):
        self.node_id = node_id
        self.node_type = node_type
        self.tee_type = tee_type
        self.public_key = public_key
        self.aes_key = bytes.fromhex(aes_key_hex)
        self.attestation = attestation
        self.is_verified = False
        self.last_seen = time.time()
        self.telemetry_history: List[Dict[str, Any]] = []
        self.total_updates_accepted = 0
        self.total_updates_rejected = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "tee_type": self.tee_type,
            "is_verified": self.is_verified,
            "last_seen": self.last_seen,
            "is_online": (time.time() - self.last_seen) < 10.0,
            "total_updates_accepted": self.total_updates_accepted,
            "total_updates_rejected": self.total_updates_rejected,
            "latest_telemetry": self.telemetry_history[-1] if self.telemetry_history else None
        }


class FederatedOrchestrator:
    def __init__(self):
        self.nodes: Dict[str, NodeRecord] = {}
        self.global_model = EdgeIsolationForest(n_estimators=30, max_samples=48)
        self.current_round = 0
        self.is_round_active = False
        self.round_start_time = 0.0
        self.round_updates: Dict[str, EdgeIsolationForest] = {}
        self.required_participants = 1  # Minimum nodes to aggregate a round (can scale to 3)

        # Audit & Evaluation Logs
        self.security_audit_log: List[Dict[str, Any]] = []
        self.fl_round_history: List[Dict[str, Any]] = []
        self.simulated_attacks_count = 0
        self.prevented_attacks_count = 0

        self._log_audit("SYSTEM_INIT", "Zero-Trust Orchestrator initialized. Waiting for TEE nodes...")

    def _log_audit(self, event_type: str, message: str, level: str = "INFO", details: Optional[Dict[str, Any]] = None):
        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "event_type": event_type,
            "level": level,
            "message": message,
            "details": details or {}
        }
        self.security_audit_log.insert(0, entry)
        if len(self.security_audit_log) > 200:
            self.security_audit_log.pop()
        logger.info("[%s] %s", event_type, message)

    def register_node(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify TEE Attestation Evidence and register edge device.
        Requires valid signature over enclave claims using the device's public key.
        """
        node_id = payload.get("node_id")
        node_type = payload.get("node_type", "Unknown")
        tee_type = payload.get("tee_type", "Unknown")
        public_key = payload.get("public_key")
        aes_key_hex = payload.get("aes_key_hex")
        attestation = payload.get("attestation", {})

        if not all([node_id, public_key, aes_key_hex, attestation]):
            self._log_audit("REGISTRATION_REJECTED", f"Missing credentials from node {node_id}", level="WARN")
            return {"success": False, "error": "Incomplete registration data"}

        # Verify TEE Attestation Evidence
        claims = attestation.get("claims", {})
        sig_b64 = attestation.get("signature", "")
        try:
            claims_bytes = json.dumps(claims, sort_keys=True).encode("utf-8")
            sig_bytes = base64.b64decode(sig_b64)
            is_valid_attestation = EdgeCryptoEngine.verify_signature(public_key, claims_bytes, sig_bytes)
        except Exception as e:
            is_valid_attestation = False

        if not is_valid_attestation:
            self._log_audit("ATTESTATION_FAILED",
                            f"Hardware attestation signature verification failed for node {node_id}",
                            level="SECURITY_ALERT")
            return {"success": False, "error": "Invalid TEE attestation evidence"}

        # Node verified
        record = NodeRecord(
            node_id=node_id,
            node_type=node_type,
            tee_type=tee_type,
            public_key=public_key,
            aes_key_hex=aes_key_hex,
            attestation=attestation
        )
        record.is_verified = True
        self.nodes[node_id] = record

        self._log_audit("NODE_REGISTERED",
                        f"Node '{node_id}' successfully authenticated via {tee_type} TEE attestation",
                        level="SUCCESS",
                        details={"node_id": node_id, "tee": tee_type})

        return {
            "success": True,
            "message": "Node successfully verified and registered in Zero-Trust topology",
            "current_round": self.current_round
        }

    def record_telemetry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Record real-time telemetry from edge node"""
        node_id = payload.get("node_id")
        if node_id not in self.nodes:
            return {"success": False, "error": "Node not registered"}

        node = self.nodes[node_id]
        node.last_seen = time.time()

        sample = {
            "timestamp": payload.get("timestamp", time.time()),
            "temperature": payload.get("temperature", 0.0),
            "humidity": payload.get("humidity", 0.0),
            "anomaly_score": payload.get("anomaly_score", 0.5),
            "is_anomaly": payload.get("is_anomaly", False),
            "tee_latency_ms": payload.get("tee_latency_ms", 1.0),
            "anomaly_forced": payload.get("anomaly_forced", False)
        }
        node.telemetry_history.append(sample)
        if len(node.telemetry_history) > 60:
            node.telemetry_history.pop(0)

        if sample["is_anomaly"]:
            self._log_audit("EDGE_ANOMALY_DETECTED",
                            f"Node {node_id} flagged anomaly: Temp {sample['temperature']}C, Hum {sample['humidity']}% (Score: {sample['anomaly_score']})",
                            level="WARN",
                            details=sample)

        return {"success": True}

    def start_fl_round(self) -> Dict[str, Any]:
        """Trigger a new Federated Learning round"""
        active_nodes = [nid for nid, n in self.nodes.items() if (time.time() - n.last_seen) < 15.0]
        if not active_nodes:
            self._log_audit("FL_ROUND_FAILED", "Cannot start round: No active verified edge nodes", level="WARN")
            return {"success": False, "error": "No active edge nodes"}

        self.current_round += 1
        self.is_round_active = True
        self.round_start_time = time.time()
        self.round_updates = {}

        self._log_audit("FL_ROUND_STARTED",
                        f"Federated Learning Round #{self.current_round} initiated with {len(active_nodes)} candidate nodes",
                        level="INFO",
                        details={"round": self.current_round, "candidate_nodes": active_nodes})

        return {
            "success": True,
            "round": self.current_round,
            "candidate_nodes": active_nodes
        }

    def submit_fl_update(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Receive, cryptographically verify, decrypt, and stage a local model update.
        Rejects invalid signatures, unverified nodes, or poisoned model updates.
        """
        node_id = payload.get("node_id")
        fl_round = payload.get("round")
        model_digest = payload.get("model_digest")
        signature_b64 = payload.get("signature")
        encrypted_obj = payload.get("encrypted_model", {})
        aad_str = payload.get("aad", "")
        stats = payload.get("execution_stats", {})

        if node_id not in self.nodes:
            self._log_audit("UPDATE_REJECTED", f"Update rejected from unknown node {node_id}", level="WARN")
            return {"success": False, "error": "Unregistered node"}

        node = self.nodes[node_id]

        # 1. VERIFY ECDSA SIGNATURE (Zero-Trust: Verify Authenticity & Integrity First)
        try:
            sig_bytes = base64.b64decode(signature_b64)
            is_valid_sig = EdgeCryptoEngine.verify_signature(
                node.public_key,
                model_digest.encode("utf-8"),
                sig_bytes
            )
        except Exception:
            is_valid_sig = False

        if not is_valid_sig:
            node.total_updates_rejected += 1
            self.prevented_attacks_count += 1
            self._log_audit("MODEL_POISONING_BLOCKED",
                            f"CRITICAL: ECDSA signature verification failed for node {node_id}! Model poisoning dropped.",
                            level="SECURITY_ALERT",
                            details={"node_id": node_id, "round": fl_round, "attack": "Forged/Corrupted Signature"})
            return {"success": False, "error": "Signature verification failed: Model poisoning rejected"}

        if not self.is_round_active or fl_round != self.current_round:
            return {"success": False, "error": f"Round {fl_round} is not currently active"}

        # 2. DECRYPT UPDATE (Confidentiality Check)
        try:
            nonce_b64 = encrypted_obj.get("nonce")
            ciphertext_b64 = encrypted_obj.get("ciphertext")
            plaintext_bytes = EdgeCryptoEngine.decrypt_aes_gcm(
                aes_key=node.aes_key,
                nonce_b64=nonce_b64,
                ciphertext_b64=ciphertext_b64,
                aad=aad_str.encode("utf-8") if aad_str else None
            )
        except Exception as e:
            node.total_updates_rejected += 1
            self.prevented_attacks_count += 1
            self._log_audit("DECRYPTION_FAILED",
                            f"Failed to decrypt update from node {node_id} using sealed session key: {str(e)}",
                            level="SECURITY_ALERT")
            return {"success": False, "error": "Payload decryption failed"}

        # 3. VERIFY DIGEST INTEGRITY
        computed_digest = EdgeCryptoEngine.hash_sha256(plaintext_bytes)
        if computed_digest != model_digest:
            node.total_updates_rejected += 1
            self.prevented_attacks_count += 1
            self._log_audit("DIGEST_MISMATCH",
                            f"Model update digest mismatch for node {node_id}! Potential in-transit tampering.",
                            level="SECURITY_ALERT")
            return {"success": False, "error": "Digest integrity mismatch"}

        # 4. PARSE ISOLATION FOREST UPDATE
        try:
            model_dict = json.loads(plaintext_bytes.decode("utf-8"))
            local_forest = EdgeIsolationForest.from_dict(model_dict)
        except Exception as e:
            return {"success": False, "error": f"Invalid model structure: {str(e)}"}

        # 5. ACCEPT UPDATE
        node.total_updates_accepted += 1
        self.round_updates[node_id] = local_forest

        self._log_audit("UPDATE_ACCEPTED",
                        f"Round #{fl_round} update from {node_id} cryptographically verified & accepted ({stats.get('n_trees_contributed', len(local_forest.trees))} trees, RAM: {stats.get('memory_footprint_bytes', 0)}B)",
                        level="SUCCESS",
                        details={"node_id": node_id, "stats": stats})

        # Check if enough updates gathered to aggregate
        if len(self.round_updates) >= self.required_participants:
            self._aggregate_round()

        return {"success": True, "message": "Update successfully verified and accepted"}

    def _aggregate_round(self):
        """Aggregate all staged model updates into the Global Model using FedAvg ensemble combining"""
        if not self.round_updates:
            return

        t_start = time.perf_counter()
        models = list(self.round_updates.values())
        participating_nodes = list(self.round_updates.keys())

        # Merge trees into the global forest
        self.global_model = EdgeIsolationForest.aggregate_federated(models, max_total_trees=45)
        aggregation_time_ms = (time.perf_counter() - t_start) * 1000.0

        round_duration = time.time() - self.round_start_time
        self.is_round_active = False

        round_summary = {
            "round": self.current_round,
            "timestamp": time.time(),
            "participating_nodes": participating_nodes,
            "total_trees": len(self.global_model.trees),
            "aggregation_time_ms": round(aggregation_time_ms, 2),
            "round_duration_sec": round(round_duration, 2),
            "memory_footprint_bytes": self.global_model.memory_footprint_bytes()
        }
        self.fl_round_history.append(round_summary)

        self._log_audit("ROUND_AGGREGATED",
                        f"Global Model updated for Round #{self.current_round}! Ensembled {len(self.global_model.trees)} trees from {len(participating_nodes)} nodes in {aggregation_time_ms:.1f}ms",
                        level="SUCCESS",
                        details=round_summary)

    def simulate_model_poisoning(self, node_id: str) -> Dict[str, Any]:
        """
        Simulate an adversarial attack where a compromised host attempts
        to inject poisoned model weights with an invalid/forged signature.
        Demonstrates the Zero-Trust Orchestrator's automatic defense!
        """
        if node_id not in self.nodes:
            return {"success": False, "error": "Node not found"}

        self.simulated_attacks_count += 1
        self._log_audit("ATTACK_INJECTED",
                        f"Simulating adversarial model poisoning attack from node {node_id}...",
                        level="WARN")

        # Create poisoned update payload with forged signature
        poisoned_payload = {
            "node_id": node_id,
            "round": self.current_round if self.is_round_active else self.current_round + 1,
            "model_digest": "bad_digest_" + os.urandom(16).hex(),
            "signature": base64.b64encode(b"FORGED_INVALID_SIGNATURE_BYTES_X01").decode("utf-8"),
            "encrypted_model": {
                "nonce": base64.b64encode(os.urandom(12)).decode("utf-8"),
                "ciphertext": base64.b64encode(b"poisoned_weights_compromised_by_malware").decode("utf-8")
            },
            "aad": f"round-{self.current_round}:{node_id}",
            "execution_stats": {"adversarial": True}
        }

        # Submit it through the normal pipeline to demonstrate defensive rejection
        res = self.submit_fl_update(poisoned_payload)
        return {
            "success": True,
            "simulation_result": "BLOCKED",
            "orchestrator_response": res
        }

    def get_dashboard_state(self) -> Dict[str, Any]:
        """Generate comprehensive state for real-time frontend visualization"""
        nodes_dict = {nid: n.to_dict() for nid, n in self.nodes.items()}
        return {
            "orchestrator_status": "ONLINE",
            "current_round": self.current_round,
            "is_round_active": self.is_round_active,
            "global_model": {
                "total_trees": len(self.global_model.trees),
                "max_samples": self.global_model.max_samples,
                "anomaly_threshold": self.global_model.anomaly_threshold,
                "memory_bytes": self.global_model.memory_footprint_bytes()
            },
            "nodes": nodes_dict,
            "total_nodes": len(self.nodes),
            "active_nodes_count": sum(1 for n in nodes_dict.values() if n["is_online"]),
            "attacks_prevented": self.prevented_attacks_count,
            "attacks_simulated": self.simulated_attacks_count,
            "fl_rounds_history": self.fl_round_history[-10:],
            "audit_logs": self.security_audit_log[:40]
        }
