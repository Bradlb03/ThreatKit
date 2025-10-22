# Password Strength Module

This module provides a lightweight wrapper around **zxcvbn**, a password strength estimator designed by Dropbox.  
It evaluates password strength based on real-world patterns rather than arbitrary complexity rules.

---

## How zxcvbn Works

- **Pattern and dictionary matching:**  
  zxcvbn checks for common passwords, names, keyboard patterns (e.g., `qwerty`, `123456`), and dictionary words.  
  It also detects substitutions like `P@ssw0rd` that appear complex but are still predictable.

- **Entropy estimation:**  
  The library calculates the estimated number of guesses required to crack the password and derives a realistic “crack time” estimate.

- **Feedback and suggestions:**  
  Each analysis returns a numeric score (0–4), a human-readable crack-time approximation, and tailored suggestions for improvement.

---

## How the UI Will Use It

- **Real-time strength meter:**  
  As users type their password, the score (0–4) updates dynamically in the browser.

- **Helpful suggestions:**  
  Text feedback appears below the password field, such as:  
  - “Add another word”  
  - “Avoid common phrases or repeats”  
  - “Use a mix of letters, numbers, and symbols”

---

## Why This Matters

Providing clear, evidence-based feedback helps users create stronger and more memorable passwords.  
Instead of relying on arbitrary rules (like “must contain one number and symbol”), zxcvbn gives context — showing *why* a password is weak and *how* to improve it.  
This approach improves both **security** and **usability**, empowering users to make smarter password choices.

---

## Example Usage

```bash
pip install zxcvbn
python password_strength.py
