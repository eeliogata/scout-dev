import requests
from fastapi import HTTPException

from threat_monitor.config import Settings
from threat_monitor.contracts import Alert
from threat_monitor.storage.db import ConfigurationError


def send_alert(settings: Settings, company_name: str, alert: Alert) -> int:
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        raise ConfigurationError("Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID on the server to send alerts")
    text = (
        f"scout.dev · {company_name}\n"
        f"Severity: {alert.severity.value} · Status: {alert.status.value}\n\n"
        f"{alert.title}\n\n{alert.explanation}"
    )
    # Budget UTF-16 units conservatively, including non-BMP characters.
    if len(text.encode("utf-16-le")) > 8000:
        text = text.encode("utf-16-le")[:7900].decode("utf-16-le", errors="ignore") + "\n[Truncated]"
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{settings.telegram_bot_token.get_secret_value()}/sendMessage",
            json={"chat_id": settings.telegram_chat_id, "text": text,
                  "link_preview_options": {"is_disabled": True}},
            timeout=(5, 20),
            allow_redirects=False,
        )
        result = response.json()
    except (requests.RequestException, ValueError):
        raise HTTPException(502, "Telegram delivery could not be confirmed. Check the chat before trying again.") from None
    if not response.ok or not isinstance(result, dict) or result.get("ok") is not True:
        raise HTTPException(502, "Telegram rejected the message. Check the server bot token and chat permissions.")
    message = result.get("result")
    if not isinstance(message, dict) or not isinstance(message.get("message_id"), int):
        raise HTTPException(502, "Telegram delivery could not be confirmed. Check the chat before trying again.")
    return message["message_id"]
