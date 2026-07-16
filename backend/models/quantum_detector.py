"""
FinSpark — Quantum Risk Detector
Identifies harvest-now-decrypt-later (HNDL) attack indicators and
other quantum-era threat signatures in banking telemetry.
"""
import random
import numpy as np
from datetime import datetime


# Known quantum-vulnerable cipher suites
QUANTUM_VULNERABLE_CIPHERS = [
    "RSA-2048", "ECDH-P256", "RSA-4096", "DH-2048",
    "ECDSA-P384", "RSA-1024"
]

POST_QUANTUM_SAFE = [
    "CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "SPHINCS+",
    "NTRU", "McEliece"
]

HNDL_INDICATORS = [
    "bulk_encrypted_traffic",
    "unusual_key_exchange_pattern",
    "large_tls_session_volume",
    "protocol_downgrade_attempt",
    "cryptographic_agility_probe",
    "encrypted_data_exfiltration",
]


def generate_quantum_telemetry() -> dict:
    """
    Generates synthetic quantum-risk telemetry event.
    Models harvest-now-decrypt-later (HNDL) attack patterns.
    """
    indicators = random.sample(HNDL_INDICATORS, k=random.randint(1, 3))
    cipher = random.choice(QUANTUM_VULNERABLE_CIPHERS + POST_QUANTUM_SAFE * 3)
    is_vulnerable = cipher in QUANTUM_VULNERABLE_CIPHERS

    # HNDL: attacker harvests large encrypted blobs of financial data
    data_volume_gb = round(random.uniform(0.1, 120), 2)
    is_hndl = (data_volume_gb > 50 and is_vulnerable
               and "encrypted_data_exfiltration" in indicators)

    return {
        "event_id": f"QNT-{random.randint(10000,99999)}",
        "timestamp": datetime.utcnow().isoformat(),
        "cipher_suite": cipher,
        "is_quantum_vulnerable_cipher": is_vulnerable,
        "hndl_indicators": indicators,
        "encrypted_data_volume_gb": data_volume_gb,
        "tls_version": random.choice(["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]),
        "key_exchange_attempts": random.randint(1, 500),
        "is_hndl_suspected": is_hndl,
        "quantum_risk_score": _compute_quantum_risk(
            is_vulnerable, indicators, data_volume_gb
        ),
        "recommendation": _get_recommendation(cipher, is_hndl),
    }


def _compute_quantum_risk(is_vulnerable: bool, indicators: list, volume: float) -> int:
    """Scores quantum risk 0–100."""
    score = 0
    if is_vulnerable:
        score += 35
    score += len(indicators) * 10
    if volume > 10:
        score += int(min(35, volume / 4))
    if "encrypted_data_exfiltration" in indicators and is_vulnerable:
        score += 20
    return min(100, score)


def _get_recommendation(cipher: str, is_hndl: bool) -> str:
    if is_hndl:
        return ("URGENT: Suspected Harvest-Now-Decrypt-Later attack. "
                f"Migrate {cipher} to CRYSTALS-Kyber immediately. "
                "Isolate affected endpoints and review all data egress.")
    if cipher in QUANTUM_VULNERABLE_CIPHERS:
        return (f"Cipher {cipher} is quantum-vulnerable. "
                "Plan migration to post-quantum cryptography (NIST PQC standards).")
    return f"Cipher {cipher} is post-quantum safe. Continue monitoring."


def get_quantum_risk_summary(events: list) -> dict:
    """Aggregates multiple quantum telemetry events into a summary."""
    if not events:
        return {"status": "NO_DATA"}
    scores = [e["quantum_risk_score"] for e in events]
    hndl_count = sum(1 for e in events if e["is_hndl_suspected"])
    vulnerable_count = sum(1 for e in events if e["is_quantum_vulnerable_cipher"])
    return {
        "total_events": len(events),
        "average_quantum_risk": round(np.mean(scores), 1),
        "max_quantum_risk": max(scores),
        "hndl_suspected_count": hndl_count,
        "quantum_vulnerable_cipher_count": vulnerable_count,
        "overall_quantum_posture": (
            "CRITICAL" if max(scores) >= 80 else
            "HIGH" if max(scores) >= 60 else
            "MEDIUM" if max(scores) >= 40 else "LOW"
        ),
        "top_threats": [e for e in events if e["quantum_risk_score"] >= 60][:5],
    }
