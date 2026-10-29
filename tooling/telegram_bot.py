#!/usr/bin/env python3
"""
Telegram bot for SOC Lab.

Reads config from environment:
    TELEGRAM_TOKEN       — bot token (required)
    TELEGRAM_PROXY_URL   — optional custom API URL (e.g. Cloudflare Worker)
    TELEGRAM_API_URL     — fallback: direct Telegram API (default)
"""
import os
import subprocess
from pathlib import Path

import telebot

BASE_DIR = Path(__file__).resolve().parent.parent

TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TOKEN:
    raise SystemExit("❌ TELEGRAM_TOKEN env var is required")

# Cloudflare Worker proxy (если задан) + fallback на прямой API
PROXY_URL = os.getenv("TELEGRAM_PROXY_URL")
DIRECT_URL = os.getenv("TELEGRAM_API_URL", "https://api.telegram.org/bot{0}/{1}")

if PROXY_URL:
    telebot.apihelper.API_URL = PROXY_URL
else:
    telebot.apihelper.API_URL = DIRECT_URL

bot = telebot.TeleBot(TOKEN)


def run_bash(script: str, *args: str) -> str:
    """Call a Bash script from tooling/ and return its output."""
    path = BASE_DIR / "tooling" / script
    if not path.exists():
        return f"❌ Script not found: {script}"
    try:
        res = subprocess.run(
            ["bash", str(path), *args],
            capture_output=True, text=True, timeout=60,
        )
        return res.stdout.strip() or res.stderr.strip() or "✅ OK"
    except subprocess.TimeoutExpired:
        return "⏱ Command timed out (60s)"
    except Exception as e:
        return f"❌ Error: {e}"


@bot.message_handler(commands=["start", "help"])
def cmd_start(m):
    bot.reply_to(m, (
        "🤖 SOC Lab Bot\n\n"
        "/health — check services\n"
        "/correlate <IP> — attack timeline\n"
    ))


@bot.message_handler(commands=["health"])
def cmd_health(m):
    bot.reply_to(m, run_bash("health_check.sh"))


@bot.message_handler(commands=["correlate"])
def cmd_correlate(m):
    parts = m.text.split()
    if len(parts) != 2:
        return bot.reply_to(m, "Usage: /correlate <IP>")
    bot.reply_to(m, run_bash("correlate.sh", parts[1]))


if __name__ == "__main__":
    print(f"[+] Bot started. API: {telebot.apihelper.API_URL}")
    bot.infinity_polling(timeout=60, long_polling_timeout=30)
