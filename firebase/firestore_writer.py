"""
FinSpark — Firebase Firestore Writer
Runs as a background thread: generates AI threat data every 30s
and pushes it to Firebase Firestore collections.

Collections written:
  /threats          — correlated AI threat events
  /quantum_risks    — quantum telemetry events
  /fraud_alerts     — fraud pattern detections
  /dashboard_kpis   — aggregated KPI snapshot
"""
import sys
import os
import time
import random
import threading
from datetime import datetime, timezone

import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import firebase_admin
from firebase_admin import credentials, firestore

from models.threat_engine import get_engine, generate_telemetry_event, generate_transaction_event
from models.quantum_detector import generate_quantum_telemetry, get_quantum_risk_summary
from models.fraud_graph import generate_fraud_network, detect_layering_pattern

# ─────────────────────────────────────────────────────────────────────────────
# Firebase Init
# ─────────────────────────────────────────────────────────────────────────────
_SERVICE_KEY = os.path.join(os.path.dirname(__file__), 'serviceAccountKey.json')
_db = None
_initialized = False


def load_env():
    """Load environment variables from .env file manually."""
    for p in ['.env', os.path.join(os.path.dirname(__file__), '.env'), os.path.join(os.path.dirname(__file__), '..', '.env')]:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k:
                            os.environ[k] = v
                break
            except Exception as e:
                print(f"[EnvLoader] Error loading {p}: {e}")


def init_firebase() -> bool:
    """
    Initialize Firebase Admin SDK using environment variables or a key file.
    Returns True if successful, False otherwise.
    """
    global _db, _initialized
    if _initialized:
        return True

    load_env()

    cred = None

    # Option 1: Use FIREBASE_SERVICE_ACCOUNT_JSON
    creds_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if creds_json and "YOUR_PRIVATE_KEY" not in creds_json and '"private_key": ""' not in creds_json:
        try:
            creds_dict = json.loads(creds_json)
            # Private keys can sometimes have escaped newlines
            if "private_key" in creds_dict:
                creds_dict["private_key"] = creds_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(creds_dict)
            print("[Firebase] Initializing from FIREBASE_SERVICE_ACCOUNT_JSON environment variable.")
        except Exception as e:
            print(f"[Firebase] Error parsing JSON credentials from environment: {e}")

    # Option 2: Use individual env variables
    if not cred and os.environ.get("FIREBASE_PROJECT_ID") and os.environ.get("FIREBASE_PRIVATE_KEY") and os.environ.get("FIREBASE_CLIENT_EMAIL"):
        # Make sure they are not placeholders
        if "YOUR_" not in os.environ.get("FIREBASE_PRIVATE_KEY", ""):
            try:
                private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
                creds_dict = {
                    "type": "service_account",
                    "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
                    "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID"),
                    "private_key": private_key,
                    "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
                    "client_id": os.environ.get("FIREBASE_CLIENT_ID"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_X509_CERT_URL")
                }
                # Clean up empty or missing keys
                creds_dict = {k: v for k, v in creds_dict.items() if v}
                cred = credentials.Certificate(creds_dict)
                print("[Firebase] Initializing from individual environment variables.")
            except Exception as e:
                print(f"[Firebase] Error building credentials from environment: {e}")

    # Option 3: Fallback to local serviceAccountKey.json
    if not cred:
        if os.path.exists(_SERVICE_KEY):
            try:
                cred = credentials.Certificate(_SERVICE_KEY)
                print(f"[Firebase] Initializing from local key file: {_SERVICE_KEY}")
            except Exception as e:
                print(f"[Firebase] Error loading key file {_SERVICE_KEY}: {e}")
        else:
            print(
                f"[Firebase] No credentials found. serviceAccountKey.json not found at {_SERVICE_KEY} and "
                "no Firebase environment variables were found in .env.\n"
                "           Continuing with local-only mode."
            )
            return False

    try:
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        _db = firestore.client()
        _initialized = True
        print("[Firebase] Connected to Firestore successfully.")
        return True
    except Exception as e:
        print(f"[Firebase] Initialization failed: {e}")
        return False


def get_db():
    return _db


# ─────────────────────────────────────────────────────────────────────────────
# Writers
# ─────────────────────────────────────────────────────────────────────────────
def _serialize(obj):
    """Make objects JSON/Firestore-safe."""
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float, str)):
        return obj
    return str(obj)


def write_threat_batch(engine, batch_size: int = 10):
    """Generate AI threat events and write to Firestore /threats collection."""
    db = get_db()
    if not db:
        return

    batch = db.batch()
    for _ in range(batch_size):
        tel = generate_telemetry_event()
        txn = generate_transaction_event()
        txn['user_id'] = tel['user_id']
        result = engine.score_event(tel, txn)

        doc = {
            'id': f"ALERT-{random.randint(100000,999999)}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'telemetry_event': tel['event_type'],
            'transaction_type': txn['txn_type'],
            'user_id': tel['user_id'],
            'country': tel['country'],
            'amount': round(txn['amount'], 2),
            'currency': txn['currency'],
            'risk_score': result['risk_score'],
            'threat_level': result['threat_level'],
            'explanation': result['explanation'],
            'triggered_rules': result['triggered_rules'],
            'geo_mismatch': bool(txn.get('geo_mismatch', False)),
            'is_cross_border': bool(txn.get('is_cross_border', False)),
            'failed_logins': tel.get('failed_logins', 0),
            'bytes_transferred': tel.get('bytes_transferred', 0),
            'created_at': firestore.SERVER_TIMESTAMP,
        }

        ref = db.collection('threats').document(doc['id'])
        batch.set(ref, _serialize(doc))

    batch.commit()
    print(f"[Firebase] Wrote {batch_size} threat events to Firestore.")


def write_quantum_batch(batch_size: int = 8):
    """Write quantum risk events to Firestore /quantum_risks collection."""
    db = get_db()
    if not db:
        return

    events = [generate_quantum_telemetry() for _ in range(batch_size)]
    summary = get_quantum_risk_summary(events)

    batch = db.batch()
    for e in events:
        ref = db.collection('quantum_risks').document(e['event_id'])
        doc = {**e, 'created_at': firestore.SERVER_TIMESTAMP}
        batch.set(ref, _serialize(doc))

    # Write summary doc
    summary_ref = db.collection('quantum_risks').document('_summary')
    batch.set(summary_ref, {
        **_serialize(summary),
        'updated_at': firestore.SERVER_TIMESTAMP,
    })

    batch.commit()
    print(f"[Firebase] Wrote {batch_size} quantum events + summary to Firestore.")


def write_fraud_network():
    """Write fraud network snapshot to Firestore /fraud_alerts collection."""
    db = get_db()
    if not db:
        return

    network = generate_fraud_network(n_nodes=20)
    patterns = detect_layering_pattern(network['edges'])

    summary = network['summary']
    doc = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_nodes': summary['total_nodes'],
        'total_edges': summary['total_edges'],
        'suspicious_edges': summary['suspicious_edges'],
        'high_risk_accounts': summary['high_risk_accounts'],
        'total_suspicious_volume': summary['total_suspicious_volume'],
        'pattern_count': len(patterns),
        'patterns': _serialize(patterns[:10]),
        'created_at': firestore.SERVER_TIMESTAMP,
    }

    db.collection('fraud_alerts').document('latest').set(doc)
    print(f"[Firebase] Wrote fraud network snapshot ({len(patterns)} patterns).")


def write_dashboard_kpis(engine):
    """Write aggregated KPI snapshot to Firestore /dashboard_kpis/latest."""
    db = get_db()
    if not db:
        return

    events = []
    for _ in range(50):
        tel = generate_telemetry_event()
        txn = generate_transaction_event()
        txn['user_id'] = tel['user_id']
        result = engine.score_event(tel, txn)
        events.append(result)

    levels = [e['threat_level'] for e in events]
    scores = [e['risk_score'] for e in events]

    doc = {
        'total_events_analyzed': 50,
        'threats_detected': levels.count('CRITICAL') + levels.count('HIGH'),
        'avg_risk_score': round(sum(scores) / len(scores), 1),
        'false_positive_reduction': f"{random.randint(68,85)}%",
        'model_accuracy': '94.3%',
        'events_per_second': random.randint(120, 280),
        'severity_breakdown': {
            'CRITICAL': levels.count('CRITICAL'),
            'HIGH': levels.count('HIGH'),
            'MEDIUM': levels.count('MEDIUM'),
            'LOW': levels.count('LOW'),
        },
        'quantum_posture': random.choice(['HIGH', 'MEDIUM', 'HIGH', 'CRITICAL']),
        'updated_at': firestore.SERVER_TIMESTAMP,
    }

    db.collection('dashboard_kpis').document('latest').set(doc)
    print("[Firebase] Wrote KPI snapshot to Firestore.")


# ─────────────────────────────────────────────────────────────────────────────
# Background Thread
# ─────────────────────────────────────────────────────────────────────────────
_writer_thread = None
_stop_event = threading.Event()


def _writer_loop(interval_seconds: int = 30):
    """Background loop: writes all data to Firestore every `interval_seconds`."""
    print(f"[Firebase] Writer thread started (interval: {interval_seconds}s)")
    engine = get_engine()

    while not _stop_event.is_set():
        try:
            write_threat_batch(engine, batch_size=10)
            write_quantum_batch(batch_size=8)
            write_fraud_network()
            write_dashboard_kpis(engine)
            print(f"[Firebase] Full sync complete. Next sync in {interval_seconds}s.")
        except Exception as e:
            print(f"[Firebase] Writer error: {e}")

        _stop_event.wait(interval_seconds)


def start_writer_thread(interval_seconds: int = 30):
    """Start the Firestore writer background thread."""
    global _writer_thread

    if not init_firebase():
        print("[Firebase] Skipping writer thread — Firebase not initialized.")
        return

    _stop_event.clear()
    _writer_thread = threading.Thread(
        target=_writer_loop,
        args=(interval_seconds,),
        daemon=True,
        name="FirestoreWriter"
    )
    _writer_thread.start()


def stop_writer_thread():
    """Gracefully stop the writer thread."""
    _stop_event.set()
    if _writer_thread:
        _writer_thread.join(timeout=5)
        print("[Firebase] Writer thread stopped.")
