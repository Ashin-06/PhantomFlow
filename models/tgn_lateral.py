# models/tgn_lateral.py
"""
Temporal Graph Network (TGN) that models multi-host communication graphs.
Detects lateral movement patterns that single-flow models miss entirely.

Key insight: C2 implants often move laterally (10.x.x.1 → 10.x.x.2 → 10.x.x.3).
The GRAPH of who-talks-to-whom over time encodes this pattern.
A normal workstation speaks to a few servers. A compromised host starts
speaking to unusual peers it never talked to before.

Architecture: Each host = graph node. Each flow = temporal edge.
TGN updates node embeddings as new edges arrive.
Classifier then predicts whether a node is exhibiting lateral movement.

Requires: torch-geometric >= 2.4.0
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import time


class TemporalEdgeEncoder(nn.Module):
    """Encodes a temporal edge (flow) into a fixed-size embedding."""

    def __init__(self, edge_feat_dim: int = 10, embed_dim: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(edge_feat_dim, 32),
            nn.ReLU(),
            nn.Linear(32, embed_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TimeEncoder(nn.Module):
    """
    Encodes relative time as a learnable sinusoidal feature.
    This lets the model learn which time scales matter —
    daily rhythms vs. second-level beacon timing.
    """

    def __init__(self, dim: int = 16):
        super().__init__()
        self.w = nn.Linear(1, dim)
        nn.init.uniform_(self.w.weight, 0, 1)

    def forward(self, t: torch.Tensor) -> torch.Tensor:
        t = t.unsqueeze(-1)
        return torch.cos(self.w(t))


class TGNMemory(nn.Module):
    """
    Per-node memory module — each node carries a state vector
    that gets updated whenever it sends or receives a flow.
    """

    def __init__(self, num_nodes: int, mem_dim: int = 64):
        super().__init__()
        self.num_nodes = num_nodes
        self.mem_dim = mem_dim
        self.memory = nn.Parameter(
            torch.zeros(num_nodes, mem_dim), requires_grad=False
        )
        self.last_update = nn.Parameter(
            torch.zeros(num_nodes), requires_grad=False
        )
        self.gru = nn.GRUCell(mem_dim, mem_dim)

    def get_memory(self, node_ids: torch.Tensor) -> torch.Tensor:
        return self.memory[node_ids]

    def update(self, node_ids: torch.Tensor, messages: torch.Tensor):
        """Update memory for nodes with aggregated messages."""
        old_mem = self.memory[node_ids]
        new_mem = self.gru(messages, old_mem)
        self.memory.data[node_ids] = new_mem

    def reset(self):
        self.memory.data.zero_()
        self.last_update.data.zero_()


class TGNLateralMovementDetector(nn.Module):
    """
    Temporal Graph Network for lateral movement detection.
    
    Pipeline per batch:
    1. Encode edge features (flow metadata) + time
    2. Aggregate messages for source/destination nodes
    3. Update node memories via GRU
    4. Compute node embeddings using attention aggregation of neighbors
    5. Classify: is this node exhibiting lateral movement?
    
    Trained on sequences of flows where some hosts are flagged
    as lateral-movement nodes (infected, pivoting).
    """

    def __init__(self,
                 num_nodes: int = 65536,    # Max unique IPs (use hash bucketing)
                 node_feat_dim: int = 8,    # Per-node features (degree, etc.)
                 edge_feat_dim: int = 10,   # Per-flow features
                 mem_dim: int = 64,
                 embed_dim: int = 64,
                 time_dim: int = 16,
                 num_heads: int = 4):
        super().__init__()

        self.mem_dim = mem_dim
        self.embed_dim = embed_dim

        # Modules
        self.time_enc = TimeEncoder(time_dim)
        self.edge_enc = TemporalEdgeEncoder(edge_feat_dim, embed_dim)
        self.memory = TGNMemory(num_nodes, mem_dim)

        # Message function: mem_src || mem_dst || edge_feat || time_feat → message
        msg_input_dim = mem_dim + mem_dim + embed_dim + time_dim
        self.msg_fn = nn.Sequential(
            nn.Linear(msg_input_dim, mem_dim),
            nn.ReLU(),
            nn.Linear(mem_dim, mem_dim),
        )

        # Temporal graph attention
        self.attn = nn.MultiheadAttention(
            embed_dim=mem_dim,
            num_heads=num_heads,
            batch_first=True,
        )

        # Node classifier
        self.classifier = nn.Sequential(
            nn.Linear(mem_dim + node_feat_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 2),  # lateral_movement / normal
        )

    def compute_messages(self,
                          src_ids: torch.Tensor,
                          dst_ids: torch.Tensor,
                          edge_feats: torch.Tensor,
                          timestamps: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Compute messages for source and destination nodes."""
        src_mem = self.memory.get_memory(src_ids)
        dst_mem = self.memory.get_memory(dst_ids)
        edge_emb = self.edge_enc(edge_feats)
        time_emb = self.time_enc(timestamps.float())

        combined = torch.cat([src_mem, dst_mem, edge_emb, time_emb], dim=1)
        msg = self.msg_fn(combined)
        return msg, msg  # src message, dst message (symmetric here)

    def forward(self,
                src_ids: torch.Tensor,
                dst_ids: torch.Tensor,
                edge_feats: torch.Tensor,
                timestamps: torch.Tensor,
                node_feats: torch.Tensor,
                query_node_ids: torch.Tensor) -> torch.Tensor:
        """
        Forward pass. Returns logits for query_node_ids.
        """
        # Compute and apply messages
        src_msgs, dst_msgs = self.compute_messages(
            src_ids, dst_ids, edge_feats, timestamps
        )

        # Update memories (aggregate messages per node)
        self.memory.update(src_ids, src_msgs)
        self.memory.update(dst_ids, dst_msgs)

        # Get updated memories for query nodes
        query_mem = self.memory.get_memory(query_node_ids)  # (N, mem_dim)
        query_feats = node_feats[query_node_ids]             # (N, node_feat_dim)

        # Self-attention over query node memories
        q_attn, _ = self.attn(
            query_mem.unsqueeze(0),
            query_mem.unsqueeze(0),
            query_mem.unsqueeze(0),
        )
        q_attn = q_attn.squeeze(0)

        # Classify
        combined = torch.cat([q_attn, query_feats], dim=1)
        return self.classifier(combined)

    def reset_memory(self):
        self.memory.reset()


class LateralMovementMonitor:
    """
    Wraps TGN for real-time lateral movement monitoring.
    Maintains a running IP → node_id mapping and updates
    the graph as new flows arrive.
    
    Usage in pipeline:
        monitor = LateralMovementMonitor()
        monitor.load("models/tgn_lateral.pt")
        result = monitor.process_flow(flow_dict)
    """

    MAX_NODES = 65536  # Hash bucket size

    def __init__(self):
        self.model = TGNLateralMovementDetector(num_nodes=self.MAX_NODES)
        self.ip_to_id: Dict[str, int] = {}
        self.node_stats: Dict[int, Dict] = defaultdict(lambda: {
            "out_degree": 0,
            "in_degree": 0,
            "unique_dsts": set(),
            "unique_srcs": set(),
            "bytes_sent": 0,
            "first_seen": None,
        })
        self.device = torch.device("cpu")

    def _ip_to_node_id(self, ip: str) -> int:
        if ip not in self.ip_to_id:
            self.ip_to_id[ip] = hash(ip) % self.MAX_NODES
        return self.ip_to_id[ip]

    def _get_node_features(self, node_id: int) -> List[float]:
        s = self.node_stats[node_id]
        return [
            float(s["out_degree"]),
            float(s["in_degree"]),
            float(len(s["unique_dsts"])),
            float(len(s["unique_srcs"])),
            float(s["bytes_sent"]) / 1e6,
            # New connection burst: unique_dsts / (out_degree+1)
            len(s["unique_dsts"]) / (s["out_degree"] + 1),
            # Ratio of new destinations (lateral movement = high)
            min(1.0, len(s["unique_dsts"]) / max(1, s["out_degree"])),
            0.0,  # reserved
        ]

    def process_flow(self, flow: Dict) -> Optional[Dict]:
        """
        Process a single flow and check for lateral movement.
        Returns alert dict if lateral movement detected, else None.
        """
        src_ip = flow.get("src", "")
        dst_ip = flow.get("dst", "")
        if not src_ip or not dst_ip:
            return None

        src_id = self._ip_to_node_id(src_ip)
        dst_id = self._ip_to_node_id(dst_ip)
        ts = torch.tensor([flow.get("ts", time.time())], dtype=torch.float32)

        # Update stats
        self.node_stats[src_id]["out_degree"] += 1
        self.node_stats[src_id]["unique_dsts"].add(dst_ip)
        self.node_stats[src_id]["bytes_sent"] += flow.get("orig_bytes", 0)
        self.node_stats[dst_id]["in_degree"] += 1
        self.node_stats[dst_id]["unique_srcs"].add(src_ip)

        # Build edge features
        edge_feat = torch.tensor([[
            flow.get("orig_bytes", 0) / 1e6,
            flow.get("resp_bytes", 0) / 1e6,
            float(flow.get("dport", 0)) / 65535,
            flow.get("duration_s", 0) / 3600,
            flow.get("bytes_ratio", 0),
            flow.get("periodicity_score", 0),
            flow.get("iat_cv", 0),
            1.0 if flow.get("dport") in [445, 135, 139, 3389, 5985] else 0.0,  # lateral ports
            flow.get("pkt_size_entropy", 0) / 4.0,
            float(flow.get("proto", "tcp") == "tcp"),
        ]], dtype=torch.float32)

        # Build node feature matrix
        all_node_ids = list(set(self.node_stats.keys()))
        node_feats = torch.zeros(self.MAX_NODES, 8, dtype=torch.float32)
        for nid in all_node_ids:
            node_feats[nid] = torch.tensor(self._get_node_features(nid))

        src_t = torch.tensor([src_id])
        dst_t = torch.tensor([dst_id])
        query = torch.tensor([src_id])

        self.model.eval()
        with torch.no_grad():
            logits = self.model(src_t, dst_t, edge_feat, ts, node_feats, query)
            prob = torch.softmax(logits, dim=1)[0, 1].item()

        # Alert on high lateral movement probability
        if prob > 0.75:
            unique_new_dst_count = len(self.node_stats[src_id]["unique_dsts"])
            return {
                "type": "lateral_movement",
                "src": src_ip,
                "dst": dst_ip,
                "probability": float(prob),
                "unique_destinations": unique_new_dst_count,
                "out_degree": self.node_stats[src_id]["out_degree"],
                "lateral_port": flow.get("dport"),
                "mitre_ttps": ["T1021", "T1570", "T1550"],
                "explanation": (
                    f"{src_ip} contacted {unique_new_dst_count} unique internal hosts "
                    f"(lateral movement score: {prob:.2f}). "
                    f"Suspicious port: {flow.get('dport')}."
                ),
            }
        return None

    def load(self, path: str):
        state = torch.load(path, map_location="cpu")
        self.model.load_state_dict(state["model"])
        self.ip_to_id = state.get("ip_to_id", {})
        print(f"[TGN] Loaded from {path}")

    def save(self, path: str):
        torch.save({
            "model": self.model.state_dict(),
            "ip_to_id": self.ip_to_id,
        }, path)
