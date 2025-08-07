# Email Security Checker

A command-line tool to check email security configurations (SPF, DKIM, and DMARC) for any domain.

## Installation

```bash
pip install checkdmarc dnspython termcolor
```

## Usage

### Command Line

Check a specific domain:
```bash
python mail.py -d example.com
python mail.py --domain example.com
```

### Interactive Mode

Run without arguments to enter the domain interactively:
```bash
python mail.py
```

## What it Checks

### SPF (Sender Policy Framework)
- Verifies if the domain has a valid SPF record
- Shows the SPF policy and any warnings

### DKIM (DomainKeys Identified Mail)
- Searches for common DKIM selectors
- Reports found DKIM records (note: comprehensive DKIM verification requires email headers)

### DMARC (Domain-based Message Authentication)
- Checks for DMARC record validity
- Reports the DMARC policy:
  - **none**: Monitor only (shows warning)
  - **quarantine**: Send suspicious emails to spam
  - **reject**: Block suspicious emails

## Example Output

```
Checking records for example.com...

==================================================
      SPF (Sender Policy Framework) Check
==================================================
SPF Record      [PASS] Found: v=spf1 include:_spf.google.com ~all

==================================================
   DKIM (DomainKeys Identified Mail) Check
==================================================
DKIM Record     [PASS] Found a DKIM record with selector: 'google'

==================================================
DMARC (Domain-based Message Authentication) Check
==================================================
DMARC Record    [PASS] Found: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
DMARC Policy    [PASS] Policy is 'reject'. Suspicious emails will be blocked.
```

## Understanding DMARC Policies

DMARC protects your domain from being spoofed in outgoing emails:
- It tells receiving servers how to handle emails claiming to be from your domain
- It does NOT affect emails you receive
- It helps protect your domain's reputation and prevent phishing