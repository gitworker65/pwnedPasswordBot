# === Imports ===
# Standard library imports
import os
import time
import json
import hashlib
import logging
from threading import Thread

# Third-party imports
import requests
from flask import Flask
from zxcvbn import zxcvbn
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode

# === Logging Setup ===
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO)
logger = logging.getLogger(__name__)

# === Configuration ===
TOKEN = os.environ.get("BOT_TOKEN")
if not TOKEN:
    raise ValueError(
        "No BOT_TOKEN found in environment variables. Please set it in Replit Secrets."
    )

STATS_FILE = "user_stats.json"
MAX_PASSWORDS_PER_MESSAGE = 25

user_last_msg_time = {}
user_stats = {}


# === Utility Functions ===
def load_stats():
    global user_stats
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                user_stats = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading stats file: {e}")
            user_stats = {}
    else:
        user_stats = {}


def save_stats():
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(user_stats, f, indent=2)
    except IOError as e:
        logger.error(f"Error saving stats file: {e}")


# === Password Logic ===
def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()


def check_hibp(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(
            url, timeout=5, headers={'User-Agent': 'Telegram-Password-Bot'})
        response.raise_for_status()
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        logger.error(f"HIBP API request failed: {e}")
        return []


def check_pwned(password):
    if not password:
        return 0
    sha = sha1_hash(password)
    prefix, suffix = sha[:5], sha[5:]
    lines = check_hibp(prefix)
    for line in lines:
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def get_password_strength_text(password):
    if not password:
        return "N/A"
    result = zxcvbn(password)
    score = result['score']
    strength_text = {
        0: "❎ Very Weak",
        1: "🔸 Weak",
        2: "🔹 Okay",
        3: "✅ Strong",
        4: "☑️ Very Strong",
    }
    return strength_text.get(score, "Unknown")


# === Bot Handlers ===
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 **Welcome to the Password Analyzer Bot!**\n\n"
        "To check passwords, send them in a single message, separated by **commas**. "
        "For example: `password123, qwerty, mySuperSecretPa$$`\n\n"
        f"You can check up to **{MAX_PASSWORDS_PER_MESSAGE}** passwords at once.",
        parse_mode=ParseMode.MARKDOWN)


async def handle_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    current_time = time.time()

    if user_id in user_last_msg_time and current_time - user_last_msg_time[
            user_id] < 10:
        await update.message.reply_text(
            "⏳ Please slow down... wait 10 seconds before sending another request."
        )
        return
    user_last_msg_time[user_id] = current_time

    passwords = [
        pwd.strip() for pwd in update.message.text.split(',') if pwd.strip()
    ]

    if not passwords:
        await update.message.reply_text(
            "❗️ Please send at least one password to analyze.")
        return

    if len(passwords) > MAX_PASSWORDS_PER_MESSAGE:
        await update.message.reply_text(
            f"❗️ You can only check up to {MAX_PASSWORDS_PER_MESSAGE} passwords at a time. "
            "Please reduce the number and try again.")
        return

    status_message = await update.message.reply_text(
        f"🔍 Analyzing {len(passwords)} password(s)...")

    result_lines = []
    for pwd in passwords:
        display_pwd = f"`{pwd}`" if len(pwd) <= 15 else f"`{pwd[:12]}...`"
        strength_text = get_password_strength_text(pwd)
        pwned_count = check_pwned(pwd)

        if pwned_count > 0:
            pwned_status = f"❌ Pwned ({pwned_count:,} times)"
        else:
            pwned_status = "✅ Safe"

        line = f"{display_pwd} | {strength_text} | {pwned_status}"
        result_lines.append(line)

    # Final output formatting with separator lines
    report_title = "*Password Analysis Report*\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    decorated_lines = []
    for line in result_lines:
        decorated_lines.append(line)
        decorated_lines.append("─" * 30)

    report_body = "\n".join(decorated_lines)
    report_footer = "👨‍💻 Developed by: [*Ashmit*](https://t.me/cotactsadmin_bot)"

    final_report = f"{report_title}\n{report_body}\n{report_footer}"

    await status_message.edit_text(final_report, parse_mode=ParseMode.MARKDOWN)

    user_stats[str(user_id)] = user_stats.get(str(user_id), 0) + len(passwords)
    save_stats()
    logger.info(f"User {user_id} checked {len(passwords)} passwords.")


# === Keep-alive Server ===
flask_app = Flask('')


@flask_app.route('/')
def home():
    return "Bot is alive and running!"


def run_flask():
    flask_app.run(host='0.0.0.0', port=8080)


def keep_alive():
    t = Thread(target=run_flask)
    t.start()


# === Main Execution ===
if __name__ == "__main__":
    load_stats()
    keep_alive()

    application = ApplicationBuilder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_passwords))

    logger.info("Bot is starting with updated report layout...")
    application.run_polling()
