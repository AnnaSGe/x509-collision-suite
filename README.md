# X.509 Cryptographic Collision Analysis Suite

A Python desktop app for demonstrating the Birthday Paradox attack against weak X.509 key generation schemes, with live analytics graphs.

---

## Requirements

- Python **3.8 or higher**
- Windows / macOS / Linux

---

## Step-by-Step Setup

### Step 1 — Install Python

If you don't have Python installed:

1. Go to https://www.python.org/downloads/
2. Download the latest **Python 3.x** installer for your OS
3. Run the installer
 - On Windows: **check "Add Python to PATH"** before clicking Install
4. Verify it worked — open a terminal and run:
 ```
 python --version
 ```
 You should see something like `Python 3.11.x`

---

### Step 2 — Download the project files

Save both of these files into the **same folder** on your computer:

- `crypto_suite_fixed.py`
- `requirements.txt`

---

### Step 3 — Install dependencies

Open a terminal (Command Prompt / PowerShell on Windows, Terminal on Mac/Linux), navigate to your folder, and run:

```
pip install -r requirements.txt
```

This will install:
- `matplotlib` — for the 9-plot analytics dashboard
- `numpy` — required by matplotlib

> **Note:** `tkinter` is built into Python and does **not** need to be installed via pip.
> If you're on Linux and tkinter is missing, run: `sudo apt install python3-tk`

---

### Step 4 — Run the app

In the same terminal, run:

```
python crypto_suite_fixed.py
```

The app window will open.

---

## How to Use

1. **Key / Parameter Gen tab** — Select an entropy scheme (e.g. Weak Random or CSPRNG), click **Generate 25 Batches**. The log will show sample generated key values.

2. **Run Attack Suite tab** — Click **Exploit Parameters** to run the Birthday Paradox attack against the generated keys. Results show per-batch collision status and an overall success rate.

3. **Apply Prevention tab** — Select a prevention mechanism (e.g. CSPRNG, SHA-256, DER) and click **Apply Prevention** to re-generate secure keys and re-run the attack.

4. **Analytics & Graphs tab** — After running both an attack and a prevention, click this tab to view 9 rubric plots comparing vulnerable vs secure configurations.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: matplotlib` | Run `pip install -r requirements.txt` again |
| `No module named tkinter` (Linux) | Run `sudo apt install python3-tk` |
| Blank graph / graphs not showing | Make sure you run **both** Attack and Prevention before opening the Graphs tab |
| `python` not recognised (Windows) | Try `python3` instead, or re-install Python with "Add to PATH" checked |
