# Password Module Privacy Policy

This document outlines the privacy and data-handling practices for the **Password Strength Module**.

---

## Privacy Overview

Because this module processes sensitive user input, strict privacy controls are enforced by design.

### 1. Passwords Are Never Stored
- Passwords entered into this module are **never written to disk**, databases, or logs.  
- All evaluations occur **in memory only** during the active session.

### 2. No Plaintext Logging
- Plaintext passwords are **not printed, saved, or transmitted**.  
- Any test or logging functionality uses **masked passwords** to prevent exposure.

### 3. Local Evaluation Only
- The zxcvbn strength estimation runs **entirely on the client side** or within the local application memory.  
- No network requests or third-party transmissions occur when evaluating password strength.

### 4. Future Breach Check Integration
If breach-check functionality (such as **Have I Been Pwned**) is added later:
- It **must** use the [k-anonymity API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).  
- This ensures that **raw passwords are never sent** over the network.  
- Only the **first 5 characters of the password hash (SHA-1)** are transmitted to perform secure range-based matching.

---

## Summary

| Policy Area | Practice |
|--------------|-----------|
| Password Storage | Never stored or logged |
| Evaluation Location | In-memory only |
| Transmission | None (offline/local processing) |
| Logging | Masked or anonymized only |
| Future Breach Checks | Must use k-anonymity protocol |

---

### Why This Matters

Passwords are among the most sensitive forms of user data.  
By ensuring all processing occurs locally and securely, this module:
- Prevents accidental leaks or retention of user credentials  
- Enables secure, transparent password feedback  
- Aligns with best practices in **data minimization** and **privacy-by-design**

---

**Last Updated:** October 2025
