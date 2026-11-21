"""Send a plain-text email through the SMTP server given in .env (optional feature)."""
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


def email_configured():
    c = current_app.config
    return bool(c.get("SMTP_HOST") and c.get("SMTP_FROM") and c.get("PUBLIC_URL"))


def send_mail(to, subject, body):
    """Return True if the SMTP server accepted the message, False on any failure."""
    c = current_app.config
    msg = EmailMessage()
    msg["From"] = c["SMTP_FROM"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        if c["SMTP_SECURITY"] == "ssl":
            smtp = smtplib.SMTP_SSL(c["SMTP_HOST"], c["SMTP_PORT"], timeout=10,
                                    context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(c["SMTP_HOST"], c["SMTP_PORT"], timeout=10)
        with smtp:
            if c["SMTP_SECURITY"] == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if c["SMTP_USER"]:
                smtp.login(c["SMTP_USER"], c["SMTP_PASSWORD"])
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        current_app.logger.warning("Could not send email: %s", exc)
        return False
