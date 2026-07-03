"""
Synthetic IDOR Dataset Generator
Creates a large, realistic labeled dataset for IDOR ML model training.

Generates 1000+ samples with:
  - Normal access (self_access=1, same user → same resource)
  - IDOR patterns (different user accessing another user's resource)
  - Various response patterns, status codes, response sizes
"""

import pandas as pd
import numpy as np
import random
import string
import uuid
import os
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def random_uuid():
    return str(uuid.uuid4())

def random_user_id(numeric=True):
    if numeric:
        return random.randint(100, 9999)
    return "user_" + "".join(random.choices(string.ascii_lowercase, k=5))

ENDPOINTS = [
    "/user/profile",
    "/api/users/{id}",
    "/account/{id}/settings",
    "/orders/{id}",
    "/documents/{id}/view",
    "/admin/user/{id}",
    "/profile?id={id}",
    "/api/v1/accounts/{id}",
]

STATUS_DISTRIBUTIONS = {
    "normal_200":  {"status": 200, "length_range": (500, 3000)},
    "normal_404":  {"status": 404, "length_range": (50, 200)},
    "normal_403":  {"status": 403, "length_range": (50, 150)},
    "idor_success": {"status": 200, "length_range": (400, 2800)},  # IDOR — other user's data returned
    "idor_partial": {"status": 200, "length_range": (100, 600)},   # Partial data leak
}

SENSITIVE_KEYWORDS = [
    "email", "phone", "credit_card", "address", "ssn",
    "password", "token", "secret", "api_key", "account_balance",
]

METHODS = ["GET", "GET", "GET", "POST"]  # Mostly GET


# ─────────────────────────────────────────────────────────────────────────────
# Sample Generators
# ─────────────────────────────────────────────────────────────────────────────

def make_normal_sample(user_id: int, n_users: int) -> dict:
    """Generate a normal (non-IDOR) access record."""
    endpoint_tmpl = random.choice(ENDPOINTS)
    endpoint      = endpoint_tmpl.replace("{id}", str(user_id))
    method        = random.choice(METHODS)
    status_info   = STATUS_DISTRIBUTIONS["normal_200"] if random.random() > 0.1 else STATUS_DISTRIBUTIONS["normal_404"]
    response_len  = random.randint(*status_info["length_range"])
    has_sensitive = random.random() < 0.3  # Own profile may have personal data

    param_str = f"id={user_id}"
    return {
        "user_id":           user_id,
        "target_id":         user_id,
        "endpoint":          endpoint_tmpl.replace("{id}", ""),
        "parameter":         param_str,
        "url":               f"http://localhost{endpoint}",
        "method":            method,
        "status_code":       status_info["status"],
        "response_length":   response_len,
        "sensitive_data_found": int(has_sensitive),
        "has_auth_header":   1,
        "self_access":       1,
        "is_unauthorized":   0,
    }


def make_idor_sample(attacker_id: int, victim_id: int, is_detectable: bool = True) -> dict:
    """Generate an IDOR access record (attacker accesses victim's resource)."""
    endpoint_tmpl = random.choice(ENDPOINTS)
    endpoint      = endpoint_tmpl.replace("{id}", str(victim_id))
    method        = "GET"

    if is_detectable:
        # Classic IDOR: attacker gets victim's data successfully (200 OK)
        status_info = STATUS_DISTRIBUTIONS["idor_success"]
        has_sensitive = random.random() < 0.75  # High chance of sensitive data
    else:
        # Blocked IDOR: returns 403 or 404 (access control working)
        status_info = random.choice([
            STATUS_DISTRIBUTIONS["normal_403"],
            STATUS_DISTRIBUTIONS["normal_404"],
        ])
        has_sensitive = False

    response_len = random.randint(*status_info["length_range"])
    param_str    = f"id={victim_id}"

    return {
        "user_id":           attacker_id,
        "target_id":         victim_id,
        "endpoint":          endpoint_tmpl.replace("{id}", ""),
        "parameter":         param_str,
        "url":               f"http://localhost{endpoint}",
        "method":            method,
        "status_code":       status_info["status"],
        "response_length":   response_len,
        "sensitive_data_found": int(has_sensitive),
        "has_auth_header":   random.choice([0, 1]),  # Sometimes no auth header
        "self_access":       0,
        "is_unauthorized":   1 if is_detectable else 0,
    }


def generate_dataset(n_samples: int = 1200, idor_ratio: float = 0.40, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic IDOR dataset.

    Args:
        n_samples:   Total number of rows to generate.
        idor_ratio:  Fraction that are IDOR (positive) samples.
        seed:        Random seed for reproducibility.

    Returns:
        DataFrame with raw features and `is_unauthorized` label.
    """
    random.seed(seed)
    np.random.seed(seed)

    n_idor   = int(n_samples * idor_ratio)
    n_normal = n_samples - n_idor

    # Pool of users
    user_ids = list(range(1, 201))

    rows = []

    # ── Normal samples ──────────────────────────────────────────────────────
    for _ in range(n_normal):
        uid = random.choice(user_ids)
        rows.append(make_normal_sample(uid, len(user_ids)))

    # ── IDOR samples ────────────────────────────────────────────────────────
    n_detectable = int(n_idor * 0.7)   # 70% successful IDOR (detectable)
    n_blocked    = n_idor - n_detectable  # 30% blocked (not detectable)

    for _ in range(n_detectable):
        attacker, victim = random.sample(user_ids, 2)
        rows.append(make_idor_sample(attacker, victim, is_detectable=True))

    for _ in range(n_blocked):
        attacker, victim = random.sample(user_ids, 2)
        rows.append(make_idor_sample(attacker, victim, is_detectable=False))

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)  # Shuffle

    print(f"Dataset generated: {len(df)} rows")
    print(f"  Normal (is_unauthorized=0): {(df['is_unauthorized'] == 0).sum()}")
    print(f"  IDOR   (is_unauthorized=1): {(df['is_unauthorized'] == 1).sum()}")
    print(f"  Class balance: {df['is_unauthorized'].mean() * 100:.1f}% IDOR")

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    out_dir = "projects/auth_session/data"
    os.makedirs(out_dir, exist_ok=True)

    output_path = os.path.join(out_dir, "idor_dataset_synthetic.csv")

    print("Generating synthetic IDOR dataset...")
    df = generate_dataset(n_samples=1200, idor_ratio=0.40)
    df.to_csv(output_path, index=False)
    print(f"\nSaved to: {output_path}")
    print("\nSample rows:")
    print(df.head(5).to_string(index=False))


if __name__ == "__main__":
    main()
