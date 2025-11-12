#!/usr/bin/env python3
"""
Generate synthetic email datasets for ThreatKit evaluation.

Creates phishing and benign (safe) samples with return_path left blank.
Outputs CSV with columns: subject,from,return_path,to,body,label
(label: 1=phishing, 0=safe)

Usage (from repo root):
  PYTHONPATH=. python3 -m threatkit.emailcheck.eval.make_synthetic_dataset \
      --phish 500 --safe 500 \
      --out threatkit/emailcheck/eval/mixed_1000.csv
"""

import argparse, os, random, uuid
from datetime import datetime
import pandas as pd

RNG_SEED = 42
TO_ADDR = "user@example.com"

PHISH_SUBJECTS = [
    "Urgent: Verify your account",
    "Action required: Update billing information",
    "Security alert: Unusual sign-in detected",
    "Password reset required",
    "Your payment failed - retry now",
    "Important: Tax refund information",
    "Payroll update needed for {name}",
    "Confirm your identity to avoid suspension",
    "Your package is being held - pay customs",
    "Wire transfer authorization required",
    "Document signature required: {doc}",
    "Mailbox quota exceeded - increase now",
]
SAFE_SUBJECTS = [
    "Team sync notes for {date}",
    "Calendar invite: Project standup",
    "Lunch tomorrow?",
    "Receipt for your recent purchase #{num}",
    "Weekly newsletter",
    "Welcome to the company portal",
    "Vacation request confirmation",
    "Benefits enrollment information",
    "Class schedule update",
    "Hiring committee agenda",
    "Facilities maintenance schedule",
    "Quarterly report draft for review",
]

PHISH_SENDER_DOMAINS = [
    "mail.example-security.com", "accounts.example-pay.com", "no-reply.banksecure.com",
    "billing.examplecorp.com", "alerts.corpmail.com", "service.notifications.com",
    "mailer.example-invoices.com", "support.examplecommerce.com"
]
SAFE_SENDER_DOMAINS = [
    "company.com", "corp.company.com", "news.company.com",
    "hr.company.com", "it.company.com", "finance.company.com",
    "university.edu", "dept.university.edu"
]

PHISH_LINK_DOMAINS = [
    "secure-login.example", "update-account.example", "billing-pay.example",
    "invoice-view.example", "parcel-hold.example", "verify-user.example",
    "tax-refund.example", "doc-sign.example"
]

def make_url(domain, https=False):
    tld = random.choice([".com",".net",".info",".xyz"])
    path = random.choice(["/login","/secure","/verify","/invoice","/pay","/confirm","/auth","/download"])
    q = "?id=" + str(uuid.uuid4())[:8]
    scheme = "https" if https else "http"
    sub = random.choice(["", "www.", "secure.", "accounts."])
    return f"{scheme}://{sub}{domain}{tld}{path}{q}"

PHISH_BODIES = [
    "We attempted to process your transaction but it failed. Verify billing immediately: {url}\n\nRegards,\nSupport Team",
    "Your account was flagged for suspicious activity. To avoid suspension, confirm identity here: {url}",
    "Please download the attached invoice and remit payment within 24 hours. Invoice link: {url}",
    "Your package is held by customs. Pay the customs fee here: {url}\nTracking: {tracking}",
    "A recent sign-in from a new device was detected. If this was not you, reset password: {url}\nSecurity Team",
    "You have an unread message that requires your signature. View document: {url}\nDocument: {doc}",
    "Your subscription renewal failed. Update payment method: {url}",
    "You reached 99% of your mailbox quota. Increase quota: {url}\nIT Operations",
]
SAFE_BODIES = [
    "Hi team,\n\nPlease find the meeting notes attached. Let me know if anything is missing.\n\nThanks.",
    "Hello,\n\nReminder for tomorrow's standup at 9:30 AM in room 204.\n\n— PMO",
    "Hey,\n\nWant to grab lunch tomorrow at 12:30?\n\n— Alex",
    "Hello,\n\nYour receipt is available in the company portal.\n\nThanks,\nFinance",
    "Dear colleague,\n\nOur benefits enrollment window opens next Monday. See the internal portal for details.",
    "Hi,\n\nHere's the quarterly report draft. Please comment in the shared doc by EOD Friday.",
    "Greetings,\n\nFacilities will conduct routine maintenance this weekend. No action needed.",
    "Hello,\n\nWelcome aboard! Your onboarding checklist is on the intranet.",
]

NAMES = ["Andrew","Michael","Bennet","Palmer","Eric","Customer","Jordan","Taylor","Casey"]
DOCS  = ["Agreement.pdf","Invoice.pdf","W-2.pdf","Statement.pdf","Policy.pdf","Contract.pdf"]

def make_sender(domains):
    local = random.choice(["support","no-reply","billing","accounts","admin","service","notifications","hr","security","news","it","finance"])
    dom = random.choice(domains)
    return f"{local}@{dom}"

def gen_phish():
    subj_t = random.choice(PHISH_SUBJECTS)
    num = random.randint(1000,9999)
    subj = subj_t.format(num=num, name=random.choice(NAMES), doc=random.choice(DOCS))
    sender = make_sender(PHISH_SENDER_DOMAINS)
    url = make_url(random.choice(PHISH_LINK_DOMAINS), https=False)
    tracking = "TRK" + str(random.randint(100000,999999))
    body_t = random.choice(PHISH_BODIES)
    body = body_t.format(url=url, num=num, tracking=tracking, doc=random.choice(DOCS))
    # add urgency occasionally
    if random.random() < 0.5:
        body = "URGENT: " + body
    # sometimes add a second link
    if random.random() < 0.3:
        body += f"\n\nClick here: {make_url(random.choice(PHISH_LINK_DOMAINS), https=True)}"
    return {
        "subject": subj,
        "from": sender,
        "return_path": "",
        "to": TO_ADDR,
        "body": body,
        "label": 1,
    }

def gen_safe():
    subj_t = random.choice(SAFE_SUBJECTS)
    num = random.randint(1000,9999)
    subj = subj_t.format(num=num, date=datetime.utcnow().strftime("%b %d"), name=random.choice(NAMES))
    sender = make_sender(SAFE_SENDER_DOMAINS)
    body = random.choice(SAFE_BODIES)
    # occasionally include a **legit**-looking internal link (should not trigger phish):
    if random.random() < 0.25:
        body += f"\n\nSee portal: {make_url('portal.company', https=True)}"
    return {
        "subject": subj,
        "from": sender,
        "return_path": "",
        "to": TO_ADDR,
        "body": body,
        "label": 0,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=500, help="Number of phishing samples (label=1)")
    ap.add_argument("--safe", type=int, default=500, help="Number of safe samples (label=0)")
    ap.add_argument("--seed", type=int, default=RNG_SEED, help="Random seed")
    args = ap.parse_args()

    random.seed(args.seed)

    rows = []
    for _ in range(args.phish):
        rows.append(gen_phish())
    for _ in range(args.safe):
        rows.append(gen_safe())
    random.shuffle(rows)

    # Determine output path automatically: same directory this script is in
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "test_emails.csv")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    pd.DataFrame(rows).to_csv(out_path, index=False)
    print(f"Wrote {len(rows)} rows to {out_path} (phish={args.phish}, safe={args.safe})")

if __name__ == "__main__":
    main()