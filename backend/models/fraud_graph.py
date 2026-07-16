"""
FinSpark — Fraud Graph Engine
Builds a network graph of suspicious transaction chains
for visualization in the D3.js frontend.
"""
import random
from datetime import datetime, timedelta


def generate_fraud_network(n_nodes: int = 20) -> dict:
    """
    Generates a synthetic fraud transaction network.
    Returns nodes + edges compatible with D3 force-directed graph.
    """
    account_types = ["CHECKING", "SAVINGS", "CRYPTO_WALLET", "SHELL_CORP",
                     "OFFSHORE", "MONEY_MULE", "LEGITIMATE"]
    risk_colors = {
        "SHELL_CORP": "#ff4444",
        "OFFSHORE": "#ff6b00",
        "CRYPTO_WALLET": "#ff9500",
        "MONEY_MULE": "#ff4444",
        "CHECKING": "#00d4aa",
        "SAVINGS": "#00d4aa",
        "LEGITIMATE": "#4caf50",
    }

    nodes = []
    edges = []
    node_ids = [f"ACC{random.randint(10000,99999)}" for _ in range(n_nodes)]

    for nid in node_ids:
        acc_type = random.choice(account_types)
        risk = (
            "HIGH" if acc_type in ["SHELL_CORP", "MONEY_MULE", "OFFSHORE"] else
            "MEDIUM" if acc_type in ["CRYPTO_WALLET"] else "LOW"
        )
        nodes.append({
            "id": nid,
            "type": acc_type,
            "risk": risk,
            "color": risk_colors.get(acc_type, "#888"),
            "balance": round(random.uniform(1000, 5000000), 2),
            "txn_count": random.randint(1, 200),
            "country": random.choice(["US", "IN", "RU", "CN", "NG", "UA", "DE"]),
        })

    # Generate edges (transactions between accounts)
    high_risk_nodes = [n["id"] for n in nodes if n["risk"] == "HIGH"]
    edge_set = set()
    n_edges = min(n_nodes * 2, 40)

    for _ in range(n_edges):
        if high_risk_nodes and random.random() > 0.4:
            src = random.choice(high_risk_nodes)
        else:
            src = random.choice(node_ids)
        dst = random.choice(node_ids)
        if src != dst and (src, dst) not in edge_set:
            edge_set.add((src, dst))
            amount = round(random.uniform(5000, 2000000), 2)
            edges.append({
                "source": src,
                "target": dst,
                "amount": amount,
                "currency": random.choice(["USD", "EUR", "INR"]),
                "suspicious": amount > 500000 or (
                    any(n["id"] == src and n["risk"] == "HIGH" for n in nodes)
                ),
                "timestamp": (
                    datetime.utcnow() - timedelta(hours=random.randint(0, 72))
                ).isoformat(),
            })

    suspicious_edges = [e for e in edges if e["suspicious"]]
    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "suspicious_edges": len(suspicious_edges),
            "high_risk_accounts": len(high_risk_nodes),
            "total_suspicious_volume": round(
                sum(e["amount"] for e in suspicious_edges), 2
            ),
        }
    }


def detect_layering_pattern(edges: list) -> list:
    """
    Detects money-laundering layering: rapid multi-hop transfers
    through intermediary accounts.
    """
    patterns = []
    account_flows = {}
    for e in edges:
        if e["source"] not in account_flows:
            account_flows[e["source"]] = []
        account_flows[e["source"]].append(e)

    for acc, outflows in account_flows.items():
        if len(outflows) >= 3:
            total = sum(o["amount"] for o in outflows)
            patterns.append({
                "account": acc,
                "pattern": "LAYERING",
                "hop_count": len(outflows),
                "total_volume": round(total, 2),
                "severity": "HIGH" if total > 1000000 else "MEDIUM",
                "description": (
                    f"Account {acc} fanned out {len(outflows)} transfers "
                    f"totaling ${total:,.0f} — potential layering pattern"
                ),
            })
    return patterns
