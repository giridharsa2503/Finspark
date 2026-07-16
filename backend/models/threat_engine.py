"""
FinSpark — AI Threat Detection Engine
Correlates cybersecurity telemetry with transactional behaviour
using Isolation Forest anomaly detection + behavioral rule engine.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import random
import time
from datetime import datetime, timedelta


# ── Synthetic data generator ─────────────────────────────────────────────────
def generate_telemetry_event() -> dict:
    """Generates a synthetic cybersecurity telemetry event."""
    event_types = [
        "FAILED_LOGIN", "SUCCESSFUL_LOGIN", "VPN_ACCESS",
        "PRIVILEGE_ESCALATION", "PORT_SCAN", "LATERAL_MOVEMENT",
        "DATA_EXFILTRATION", "ENDPOINT_ALERT", "MALWARE_DETECTED",
        "UNUSUAL_API_CALL"
    ]
    countries = ["US", "IN", "RU", "CN", "BR", "NG", "UA", "DE", "GB", "FR"]
    event = random.choice(event_types)
    is_suspicious = event in ["PRIVILEGE_ESCALATION", "DATA_EXFILTRATION",
                               "LATERAL_MOVEMENT", "MALWARE_DETECTED", "PORT_SCAN"]
    return {
        "event_id": f"TEL-{random.randint(10000,99999)}",
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event,
        "source_ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "country": random.choice(countries),
        "user_id": f"USR{random.randint(1000,9999)}",
        "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]) if is_suspicious else random.choice(["LOW", "LOW", "MEDIUM"]),
        "failed_logins": random.randint(5, 30) if is_suspicious else random.randint(0, 2),
        "bytes_transferred": random.randint(500000, 50000000) if event == "DATA_EXFILTRATION" else random.randint(100, 50000),
        "is_suspicious": is_suspicious,
    }


def generate_transaction_event() -> dict:
    """Generates a synthetic banking transaction event."""
    txn_types = [
        "WIRE_TRANSFER", "CARD_PAYMENT", "ATM_WITHDRAWAL",
        "INTERNAL_TRANSFER", "CRYPTO_PURCHASE", "FOREX_EXCHANGE",
        "LARGE_CASH_DEPOSIT", "ONLINE_PURCHASE"
    ]
    txn = random.choice(txn_types)
    high_risk = txn in ["WIRE_TRANSFER", "CRYPTO_PURCHASE", "LARGE_CASH_DEPOSIT"]
    amount = random.uniform(50000, 5000000) if high_risk else random.uniform(10, 10000)

    countries = ["US", "IN", "RU", "CN", "BR", "NG", "UA", "DE", "GB", "FR"]
    return {
        "txn_id": f"TXN-{random.randint(100000,999999)}",
        "timestamp": datetime.utcnow().isoformat(),
        "txn_type": txn,
        "user_id": f"USR{random.randint(1000,9999)}",
        "amount": round(amount, 2),
        "currency": random.choice(["USD", "EUR", "INR", "GBP", "CNY"]),
        "country_origin": random.choice(countries),
        "country_dest": random.choice(countries),
        "is_cross_border": random.random() > 0.5,
        "velocity_score": round(random.uniform(0.1, 1.0), 3),
        "geo_mismatch": random.random() > 0.7,
        "is_flagged": high_risk and random.random() > 0.4,
    }


# ── Isolation Forest model ────────────────────────────────────────────────────
class ThreatDetectionEngine:
    """
    AI-powered threat detection using Isolation Forest.
    Trained on synthetic normal behaviour; anomalies = threats.
    """
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.08,   # ~8% expected anomaly rate
            random_state=42,
            max_features=1.0
        )
        self.scaler = StandardScaler()
        self._train()

    def _generate_training_data(self, n=5000):
        """Generate synthetic normal + anomaly training samples."""
        # Normal patterns
        normal = np.column_stack([
            np.random.normal(500, 200, n),        # avg amount
            np.random.normal(2, 1, n),             # failed logins
            np.random.normal(0.3, 0.1, n),         # velocity score
            np.random.binomial(1, 0.1, n),         # geo_mismatch
            np.random.normal(5000, 2000, n),       # bytes transferred
            np.random.normal(1, 0.5, n),           # cross border
        ])
        # Anomaly patterns (high-risk)
        anomaly_n = int(n * 0.1)
        anomalies = np.column_stack([
            np.random.normal(150000, 50000, anomaly_n),
            np.random.normal(15, 5, anomaly_n),
            np.random.normal(0.9, 0.05, anomaly_n),
            np.ones(anomaly_n),
            np.random.normal(5000000, 1000000, anomaly_n),
            np.ones(anomaly_n),
        ])
        return np.vstack([normal, anomalies])

    def _train(self):
        X = self._generate_training_data()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

    def score_event(self, telemetry: dict, transaction: dict) -> dict:
        """
        Correlate a telemetry event with a transaction and return threat score.
        Returns risk_score (0-100), threat_level, explanation.
        """
        features = np.array([[
            transaction.get("amount", 0),
            telemetry.get("failed_logins", 0),
            transaction.get("velocity_score", 0),
            int(transaction.get("geo_mismatch", False)),
            telemetry.get("bytes_transferred", 0),
            int(transaction.get("is_cross_border", False)),
        ]])

        features_scaled = self.scaler.transform(features)
        anomaly_score = self.model.decision_function(features_scaled)[0]
        prediction = self.model.predict(features_scaled)[0]  # -1 = anomaly

        # Convert to 0-100 risk score (higher = more risky)
        raw_risk = max(0, min(100, int(50 - anomaly_score * 50)))

        # Boost score based on rule-based signals
        rule_boost = 0
        triggered_rules = []

        if telemetry.get("event_type") in ["DATA_EXFILTRATION", "LATERAL_MOVEMENT"]:
            rule_boost += 25
            triggered_rules.append("Critical telemetry event detected")

        if transaction.get("amount", 0) > 100000 and telemetry.get("failed_logins", 0) > 5:
            rule_boost += 20
            triggered_rules.append("High-value transaction after repeated auth failures")

        if transaction.get("geo_mismatch") and transaction.get("is_cross_border"):
            rule_boost += 15
            triggered_rules.append("Geo-velocity anomaly: location mismatch on cross-border transfer")

        if telemetry.get("event_type") == "PRIVILEGE_ESCALATION":
            rule_boost += 20
            triggered_rules.append("Privilege escalation precedes financial transaction")

        final_score = min(100, raw_risk + rule_boost)

        if final_score >= 80:
            threat_level = "CRITICAL"
        elif final_score >= 60:
            threat_level = "HIGH"
        elif final_score >= 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        explanation = self._generate_explanation(
            telemetry, transaction, final_score, triggered_rules
        )

        return {
            "risk_score": final_score,
            "threat_level": threat_level,
            "anomaly_detected": prediction == -1,
            "triggered_rules": triggered_rules,
            "explanation": explanation,
            "model": "IsolationForest + RuleEngine",
            "correlated_event": {
                "telemetry_event": telemetry.get("event_type"),
                "transaction_type": transaction.get("txn_type"),
                "user_id": telemetry.get("user_id"),
            }
        }

    def _generate_explanation(self, tel, txn, score, rules) -> str:
        parts = []
        if txn.get("amount", 0) > 50000:
            parts.append(f"High-value transaction (${txn['amount']:,.0f})")
        if tel.get("failed_logins", 0) > 3:
            parts.append(f"{tel['failed_logins']} failed login attempts detected")
        if txn.get("geo_mismatch"):
            parts.append("Geographic location mismatch")
        if txn.get("is_cross_border"):
            parts.append(f"Cross-border transfer ({txn.get('country_origin','?')} → {txn.get('country_dest','?')})")
        if tel.get("bytes_transferred", 0) > 1000000:
            parts.append(f"Unusually large data transfer ({tel['bytes_transferred']/1e6:.1f} MB)")
        for rule in rules:
            if rule not in parts:
                parts.append(rule)
        if not parts:
            parts.append("Statistical anomaly detected by Isolation Forest model")
        return ". ".join(parts[:4]) + f". Risk Score: {score}/100."


# Global model instance (loaded once)
_engine = None

def get_engine() -> ThreatDetectionEngine:
    global _engine
    if _engine is None:
        _engine = ThreatDetectionEngine()
    return _engine
