# X.509 Cryptographic Collision Analysis Suite

A Python-based desktop cybersecurity application that demonstrates **Birthday Paradox attacks on weak X.509 certificate parameter generation schemes**, along with **cryptographic prevention mechanisms** and a **9-graph analytics dashboard**.

This project simulates how poor randomness in certificate generation can lead to **collisions, identity spoofing, and trust bypass attacks**.

---

## Project Overview

X.509 certificates are widely used in:

* SSL/TLS
* HTTPS websites
* Public Key Infrastructure (PKI)
* Digital signatures
* Certificate Authorities (CA)

The security of these certificates depends heavily on:

* secure serial number generation
* unpredictable entropy
* strong hashing
* strict encoding rules

This project demonstrates how weak entropy sources make certificates vulnerable to **Birthday Paradox collision attacks**.

---

## Core Cryptographic Concept

### Birthday Paradox Attack

The Birthday Paradox states that in a surprisingly small sample size, the probability of collisions becomes very high.

In cryptography, this means two different certificates or keys may produce the same identifier, hash, or serial value.

This enables:

* identity spoofing
* forged certificates
* trust chain bypass
* collision based attacks

For a space of size `N`, collision probability becomes significant near `sqrt(N)`.

For weak 20-bit randomness:

`N = 2^20 = 1,048,576`

A few thousand samples are enough to create high collision probability.

---

## X.509 Vulnerability Demonstrated

The following entropy schemes are tested:

### 1. Sequential Counter

`0,1,2,3,4...`

Extremely predictable.

Attack type:

* predictability attack
* replay
* serial spoofing

### 2. Timestamp Based

Uses Unix timestamp style values.

Low entropy and highly guessable.

### 3. Weak Random (20-bit)

Uses only 20 bits of randomness.

This is highly vulnerable to Birthday attacks.

### 4. Secure CSPRNG (128-bit)

Uses 128-bit randomness as the secure prevention model.

Collision probability is practically negligible.

---

## Attack Algorithm Used

The attack module performs collision detection over **25 batches of 2000 keys each**.

### Logic

1. Create an empty set
2. Iterate through generated keys
3. Check whether key already exists
4. If yes -> collision found
5. Mark batch as vulnerable

### Collision Detection Algorithm

```python
seen = set()

for value in batch:
    if value in seen:
        collision_found = True
    seen.add(value)
```

---

## Prevention Techniques Implemented

### 1. CSPRNG Secure Random Numbers

Uses 128-bit cryptographically strong randomness.

Key space: `2^128`

### 2. SHA-256 Strong Hashing

Prevents weak hash collisions seen in legacy algorithms like MD5 and SHA-1.

### 3. Inner–Outer OID Matching

Ensures inner and outer signature algorithms in X.509 certificates match.

### 4. Strict DER Encoding

Prevents encoding malleability.

### 5. CRL / OCSP Revocation

Simulates live certificate revocation checks.

---

## Graphs and Analytics Dashboard

The system generates **9 analytics plots**:

1. Attack Success Rate
2. Time vs Parameter Size
3. Integrity Rate
4. Latency Overhead
5. Scheme Comparison
6. Attack Methodology
7. Prevention Effectiveness
8. Resource Usage
9. Security Improvement

---

## Step by Step Implementation

### Step 1 — Key Generation Module

Implements vulnerable and secure entropy models.

### Step 2 — Attack Module

Runs Birthday collision attack.

### Step 3 — Prevention Module

Applies security mechanisms.

### Step 4 — Analytics Module

Generates 9 matplotlib plots.

### Step 5 — UI Framework

Built using Tkinter for desktop visualization.

---

## Tech Stack

* Python
* Tkinter
* Matplotlib
* Random module
* Set based collision detection

---

## How to Run

```bash
pip install -r requirements.txt
python main.py
```

---

## Learning Outcome

This project demonstrates practical understanding of:

* X.509 certificate security
* Birthday paradox
* collision attacks
* PKI vulnerabilities
* cryptographic prevention
* security analytics visualization

---

## Authors

Group Project by:

* Parnika Banerjee
* Niyathi S Vedagiri
* Anna Sunny George
