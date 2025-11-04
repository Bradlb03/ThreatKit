# Phishing Detection Module

## Overview
This module focuses on detecting phishing attempts in emails using a set of rule-based heuristics. Phishing attacks are one of the most common and dangerous threats faced by end-users, often designed to steal credentials, financial information, or other sensitive data. 

## Typical Phishing Techniques
Phishing emails often share recognizable patterns and red flags, including:
- **Sender mismatch**: The `From` header does not align with the `Return-Path`, suggesting spoofed addresses.
- **Urgency or fear tactics**: Keywords such as “urgent,” “verify,” or “immediately” attempt to pressure users into acting quickly.
- **Suspicious links**: URLs that use raw IP addresses or domains that look similar to legitimate ones (typosquatting).
- **Risky attachments**: Executables or unusual file types (`.exe`, `.scr`, `.bat`) often carry malware.
- **Reply-to mismatch** *(future rule option)*: Cases where the reply-to field differs from the sender, potentially redirecting responses to attackers.

## Rule-Based Detection
Our current system applies simple but effective rules to score and flag emails:
- **Sender mismatch rule** → Detects spoofed headers.  
- **Urgency keyword rule** → Flags psychological pressure tactics.  
- **Suspicious link rule** → Looks for raw IPs or domains that don’t align with known safe patterns.  
- **Attachment rule** → Identifies file extensions frequently used in malware delivery.  

Each triggered rule contributes points toward a **Risk Score**, with higher scores indicating a greater chance of phishing.

## Future Plan
In **Week 8**, we will expand beyond static rules by implementing a **TF-IDF baseline classifier**. This machine learning model will analyze email text features statistically and provide another layer of phishing detection. This allows the system to generalize beyond fixed patterns.

## Explainability
Transparency is a core design principle. The system will explain **why** a message was flagged:
- Highlighting **specific keywords** (e.g., “verify,” “password,” “urgent”) that triggered urgency rules.
- Pointing out **headers** (e.g., mismatched `From` vs. `Return-Path`) that indicated suspicious sender behavior.
- Marking **URLs** or domains in the body that matched risky link patterns.
- Listing **attachments** by name/type that contributed to the risk score.

This ensures users are not only warned but also educated on **what made the email suspicious**, empowering them to recognize similar threats in the future.