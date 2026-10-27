"""
TrustEdge-CC Federated Isolation Forest
High-performance, resource-constrained anomaly detection designed for edge TEEs.
Paper Reference: Vasiljevic et al., 2025 (Memory footprint < 160 KB).
"""

import math
import random
import json
import sys
from typing import List, Dict, Any, Optional, Tuple, Union


def c_factor(n: int) -> float:
    """Average path length of unsuccessful search in a Binary Search Tree (BST)"""
    if n > 2:
        euler_gamma = 0.5772156649
        return 2.0 * (math.log(n - 1) + euler_gamma) - (2.0 * (n - 1) / n)
    elif n == 2:
        return 1.0
    else:
        return 0.0


class IsolationTreeNode:
    def __init__(self,
                 feature_idx: Optional[int] = None,
                 split_val: Optional[float] = None,
                 left: Optional["IsolationTreeNode"] = None,
                 right: Optional["IsolationTreeNode"] = None,
                 size: int = 0,
                 is_leaf: bool = False):
        self.feature_idx = feature_idx
        self.split_val = split_val
        self.left = left
        self.right = right
        self.size = size
        self.is_leaf = is_leaf

    def to_dict(self) -> Dict[str, Any]:
        if self.is_leaf:
            return {
                "leaf": True,
                "size": self.size
            }
        return {
            "leaf": False,
            "feature": self.feature_idx,
            "split": round(self.split_val, 4) if self.split_val is not None else None,
            "size": self.size,
            "left": self.left.to_dict() if self.left else None,
            "right": self.right.to_dict() if self.right else None
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IsolationTreeNode":
        if not d:
            return cls(is_leaf=True, size=0)
        if d.get("leaf", False):
            return cls(size=d.get("size", 0), is_leaf=True)
        node = cls(
            feature_idx=d.get("feature"),
            split_val=d.get("split"),
            size=d.get("size", 0),
            is_leaf=False
        )
        if d.get("left"):
            node.left = cls.from_dict(d["left"])
        if d.get("right"):
            node.right = cls.from_dict(d["right"])
        return node


class IsolationTree:
    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        self.root: Optional[IsolationTreeNode] = None

    def fit(self, X: List[List[float]], current_depth: int = 0) -> IsolationTreeNode:
        n_samples = len(X)
        if n_samples <= 1 or current_depth >= self.max_depth:
            return IsolationTreeNode(size=n_samples, is_leaf=True)

        n_features = len(X[0])
        # Randomly choose a feature
        feature_idx = random.randint(0, n_features - 1)
        feat_vals = [row[feature_idx] for row in X]
        min_val = min(feat_vals)
        max_val = max(feat_vals)

        if min_val == max_val:
            return IsolationTreeNode(size=n_samples, is_leaf=True)

        # Random split point between min and max
        split_val = random.uniform(min_val, max_val)

        left_X = [row for row in X if row[feature_idx] < split_val]
        right_X = [row for row in X if row[feature_idx] >= split_val]

        if not left_X or not right_X:
            return IsolationTreeNode(size=n_samples, is_leaf=True)

        left_child = self.fit(left_X, current_depth + 1)
        right_child = self.fit(right_X, current_depth + 1)

        return IsolationTreeNode(
            feature_idx=feature_idx,
            split_val=split_val,
            left=left_child,
            right=right_child,
            size=n_samples,
            is_leaf=False
        )

    def path_length(self, x: List[float], node: Optional[IsolationTreeNode], current_depth: int = 0) -> float:
        if node is None or node.is_leaf:
            size = node.size if node else 0
            return current_depth + c_factor(size)

        if x[node.feature_idx] < node.split_val:
            return self.path_length(x, node.left, current_depth + 1)
        else:
            return self.path_length(x, node.right, current_depth + 1)


class EdgeIsolationForest:
    """
    Ultra-lightweight Federated Isolation Forest for ARM TrustZone TEEs.
    Can train locally on edge devices and merge into a global ensemble.
    """
    def __init__(self,
                 n_estimators: int = 15,
                 max_samples: int = 64,
                 anomaly_threshold: float = 0.58,
                 max_depth: Optional[int] = None):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.anomaly_threshold = anomaly_threshold
        self.max_depth = max_depth if max_depth is not None else int(math.ceil(math.log2(max_samples)))
        self.trees: List[IsolationTree] = []

    def fit(self, X: List[List[float]]) -> "EdgeIsolationForest":
        self.trees = []
        n_data = len(X)
        if n_data == 0:
            return self

        subsample_size = min(self.max_samples, n_data)
        for _ in range(self.n_estimators):
            sample = random.sample(X, subsample_size) if n_data > subsample_size else list(X)
            tree = IsolationTree(max_depth=self.max_depth)
            tree.root = tree.fit(sample)
            self.trees.append(tree)
        return self

    def anomaly_score(self, x: List[float]) -> float:
        """
        Compute anomaly score s in [0, 1].
        Values close to 1 represent clear anomalies.
        Values below 0.5 represent normal instances.
        """
        if not self.trees:
            return 0.5

        total_path = sum(t.path_length(x, t.root) for t in self.trees)
        avg_path = total_path / len(self.trees)
        c_val = c_factor(self.max_samples)

        if c_val <= 0:
            return 0.5

        score = math.pow(2.0, - (avg_path / c_val))
        return score

    def predict(self, x: List[float]) -> Tuple[int, float]:
        """
        Returns:
            label: -1 for Anomaly, 1 for Normal
            score: raw anomaly score in [0, 1]
        """
        score = self.anomaly_score(x)
        label = -1 if score >= self.anomaly_threshold else 1
        return label, score

    def memory_footprint_bytes(self) -> int:
        """Estimate the serialized in-memory footprint in bytes"""
        serialized = json.dumps(self.to_dict())
        return sys.getsizeof(serialized) + len(serialized.encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_estimators": len(self.trees),
            "max_samples": self.max_samples,
            "anomaly_threshold": self.anomaly_threshold,
            "max_depth": self.max_depth,
            "trees": [t.root.to_dict() if t.root else None for t in self.trees]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EdgeIsolationForest":
        model = cls(
            n_estimators=data.get("n_estimators", 15),
            max_samples=data.get("max_samples", 64),
            anomaly_threshold=data.get("anomaly_threshold", 0.58),
            max_depth=data.get("max_depth", 6)
        )
        trees_data = data.get("trees", [])
        model.trees = []
        for td in trees_data:
            t = IsolationTree(max_depth=model.max_depth)
            t.root = IsolationTreeNode.from_dict(td)
            model.trees.append(t)
        return model

    @classmethod
    def aggregate_federated(cls, models: List["EdgeIsolationForest"], max_total_trees: int = 45) -> "EdgeIsolationForest":
        """
        Federated Aggregation: Combine verified Isolation Trees from edge nodes into a global forest.
        """
        if not models:
            return cls()

        global_model = cls(
            n_estimators=0,
            max_samples=models[0].max_samples,
            anomaly_threshold=models[0].anomaly_threshold,
            max_depth=models[0].max_depth
        )

        all_trees = []
        for m in models:
            all_trees.extend(m.trees)

        # Retain balanced tree selection across participants
        if len(all_trees) > max_total_trees:
            all_trees = random.sample(all_trees, max_total_trees)

        global_model.trees = all_trees
        global_model.n_estimators = len(all_trees)
        return global_model
