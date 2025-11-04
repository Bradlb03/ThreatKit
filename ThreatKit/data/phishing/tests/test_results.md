# Example Emails for `phishing/rules.py`

Weights recap (used to compute `risk_score`):  
- `rule_sender_mismatch` = 20  
- `rule_urgency_keywords` = 15  
- `rule_ip_links` = 25  
- `rule_risky_attachments` = 40  
Threshold for flagging: **30**


## Benign emails (should not trip detectors):
```python
test_email = {
    "from": "NewYorkTime@email.com",
    "return_path": "NewYorkTime@email.com",
    "subject": "Daily crossword puzzle",
    "body": "Click here: https://newyorktime.com",
    "attachments": ["newyork.jpg"]
}
```
**Results**

Risk Score: 0
Flagged: False (threshold=30)

**Triggered rules:**
  - None
---
```python
test_email = {
    "from": "apple@apple.com",
    "return_path": "apple@apple.com",
    "subject": "New Iphone 16",
    "body": "Click here: https://apple.com/Iphone16",
    "attachments": ["Iphone.jpg"]
}
```
**Results**

Risk Score: 0
Flagged: False (threshold=30)

**Triggered rules:**
  - None
---
```python
test_email = {
    "from": "google@google.com",
    "return_path": "google@google.com",
    "subject": "Checkout this new AI",
    "body": "Click here: https://googleai.com",
    "attachments": [""]
}
```
**Results**

Risk Score: 0
Flagged: False (threshold=30)

**Triggered rules:**
  - None
---
```python
test_email = {
    "from": "openAI@gmail.com",
    "return_path": "openAI@gmail.com",
    "subject": "Download newest AI model",
    "body": "Click here: https://openAI.com",
    "attachments": ["AI.jpg"]
}
```
**Results**

Risk Score: 0
Flagged: False (threshold=30)

**Triggered rules:**
  - None
---
```python
test_email = {
        "from": "news@news.com",
        "return_path": "news@news.com",
        "subject": "Limited time deal for subscription",
        "body": "Click here: https://news.com/subscription",
        "attachments": [""]
}
```
**Results**

Risk Score: 15
Flagged: False (threshold=30)

**Triggered rules:**
  - [15 pts] Urgency keywords detected (e.g., 'limited time').
---




## Phishing emails (should trip detectors)

```python
test_email = {
    "from": "support@paypal.com",
    "return_path": "attacker@malicious.org",
    "subject": "URGENT: Verify your account",
    "body": "Click here: http://192.168.0.100/login",
    "attachments": ["document.exe"]
}
```

**Results**  
Risk Score: 100  
Flagged: True (threshold=30)  

**Triggered rules:**  
- [20 pts] Sender mismatch: From header does not match Return-Path.  
- [15 pts] Urgency keywords detected (e.g., 'verify').  
- [25 pts] Suspicious links: email body includes a link with a raw IP address.  
- [40 pts] Risky attachment detected: 'document.exe'.  

---
```python
test_email = {
    "from": "JohnSmith12@apple.com",
    "return_path": "appleorganization@google.com",
    "subject": "Warning: Apple Account Suspended",
    "body": "Click here: http://168.0.2.12/apple",
    "attachments": ["apple.png"]
}
```

**Results**  
Risk Score: 60  
Flagged: True (threshold=30)  

**Triggered rules:**  
- [20 pts] Sender mismatch: From header does not match Return-Path.  
- [15 pts] Urgency keywords detected (e.g., 'account suspended').  
- [25 pts] Suspicious links: email body includes a link with a raw IP address. 

---
```python
    test_email = {
        "from": "MaliciousJoe@email.com",
        "return_path": "MailciousJoe@email.com",
        "subject": "Acess to your account will be locked in 48 hours",
        "body": "Click here: http://unlockaccount.com",
        "attachments": ["lock.exe"]
    }
```
**Results:**

Risk Score: 55
Flagged: True (threshold=30)

**Triggered rules:**
  - [15 pts] Urgency keywords detected (e.g., 'locked').
  - [40 pts] Risky attachment detected: 'lock.exe'.
---
```python
    test_email = {
        "from": "MaliciousJoe@email.com",
        "return_path": "MailciousJoe@email.com",
        "subject": "Clicker here for a free prize!",
        "body": "Click here: http://168.16.12.132.com",
        "attachments": ["image.jpg"]
    }
```
**Results:**

Risk Score: 65
Flagged: True (threshold=30)

**Triggered rules:**
  - [25 pts] Suspicious links: email body includes a link with a raw IP address.
  - [40 pts] Risky attachment detected: 'image.exe'.
---
```python
    test_email = {
         "from": "Andrewemail@gmail.com",
        "return_path": "Applesupport2@phishing.com",
        "subject": "Confirm now! password breach",
        "body": "Click here: http://168.16.12.55.net",
        "attachments": ["password.bat"]
    }
```
**Results:**

Risk Score: 100
Flagged: True (threshold=30)

**Triggered rules:**
  - [20 pts] Sender mismatch: From header does not match Return-Path.
  - [15 pts] Urgency keywords detected (e.g., 'confirm now').
  - [25 pts] Suspicious links: email body includes a link with a raw IP address.
  - [40 pts] Risky attachment detected: 'password.bat'.
