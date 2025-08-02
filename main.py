import logging
import os
import asyncio
import requests
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters
)
from zxcvbn import zxcvbn
from flask import Flask
from threading import Thread

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Telegram token from environment
TOKEN = os.environ.get("BOT_TOKEN")

# Flask keep-alive
app = Flask(__name__)
@app.route('/')
def home():
    return 'Bot is alive!'

def run_flask():
    app.run(host='0.0.0.0', port=8080)

# Password check
def check_pwned_password(password: str) -> int:
    import hashlib
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    res = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
    hashes = (line.split(':') for line in res.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

# Handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Send me any password, and I’ll check its strength and if it's been pwned.")

async def handle_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    if not password:
        await update.message.reply_text("❌ No password detected. Please send a valid password.")
        return

    result = zxcvbn(password)
    score = result['score']
    crack_time = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    pwned_count = check_pwned_password(password)

    response = f"""🔐 **Password Analysis**
    
🧠 Strength Score: {score}/4
⏱️ Crack Time (Offline): {crack_time}
🔥 Pwned Count: {pwned_count:,} times

{("⚠️ This password has been leaked!" if pwned_count else "✅ This password is not in known breaches.")}"""

    await update.message.reply_text(response, parse_mode='Markdown')

# Main
async def main():
    application = ApplicationBuilder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_password))

    # Start Flask keep-alive
    Thread(target=run_flask).start()

    logger.info("✅ Bot is starting...")
    await application.run_polling()

# Entry point
if __name__ == "__main__":
    asyncio.run(main())
