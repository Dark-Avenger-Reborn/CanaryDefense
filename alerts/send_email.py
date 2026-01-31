"""
Utility for sending alert emails.

The function attempts to send via SMTP using environment variables:
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SENDER.
If SMTP is not configured, it logs to stdout so the caller can still
observe the notification in development.
"""

import os
import smtplib
from email.mime.text import MIMEText
from typing import Iterable, Tuple


def send_email(recipients: Iterable[str], subject: str, body: str) -> Tuple[bool, str]:
    """
    Send an email to the provided recipients.

    Returns:
        (success flag, message)
    """
    recipients = [r for r in recipients if r]
    if not recipients:
        return False, "No recipients provided"

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_SENDER", smtp_user or "alerts@example.com")

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    if not smtp_host or not smtp_user or not smtp_password:
        print(f"[alert-email] SMTP not configured; would send to {recipients}: {subject}\n{body}")
        return True, "SMTP not configured; logged instead"

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(sender, recipients, msg.as_string())
        return True, "Email sent"
    except Exception as exc:  # pragma: no cover - network dependent
        print(f"[alert-email] Failed to send email: {exc}")
        return False, str(exc)
