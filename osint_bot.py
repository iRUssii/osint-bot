import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)
import os

# Import your OSINT modules
from osint_modules.data_collector import OSINTDataCollector
from osint_modules.analyzer import OSINTAnalyzer
from osint_modules.reporter import OSINTReporter
from osint_modules.database import OSINTDatabase
from osint_modules.security import SecurityManager, secure_operation

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

class OSINTBot:
    def __init__(self, token: str):
        self.application = Application.builder().token(token).build()

        # Initialize modules
        self.data_collector = OSINTDataCollector()
        self.analyzer = OSINTAnalyzer()
        self.reporter = OSINTReporter()
        self.database = OSINTDatabase()
        self.security_manager = SecurityManager()

        # Register command and callback handlers
        self.setup_handlers()

    def setup_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start))
        self.application.add_handler(CommandHandler("phone", self.phone_lookup))
        self.application.add_handler(CallbackQueryHandler(self.button_callback))
        # Add other handlers as needed

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "Welcome to the OSINT Bot!\n"
            "Use /phone <number> for phone OSINT lookup.\n"
            "Other commands: /help"
        )

    @secure_operation('phone_lookup')
    async def phone_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text(
                "Please provide a phone number. Usage: `/phone <number>`",
                parse_mode='Markdown'
            )
            return

        phone_number = context.args[0]
        await update.message.reply_text(
            f"🔍 Searching for OSINT data for phone: `{phone_number}`...",
            parse_mode='Markdown'
        )

        # Collect and analyze phone data
        phone_data = self.data_collector.collect_phone_info(phone_number)
        analysis_data = self.analyzer.analyze_phone_data(phone_data)
        self.database.store_phone_lookup(phone_data, analysis_data)
        self.database.store_analysis_result('phone', phone_number, analysis_data)
        report = self.reporter.generate_phone_report(phone_data, analysis_data)

        await update.message.reply_text(report, parse_mode='Markdown')

        # Offer download options
        keyboard = [
            [
                InlineKeyboardButton("⬇️ Download as HTML", callback_data=f"download_html_{phone_number}"),
                InlineKeyboardButton("⬇️ Download as Excel", callback_data=f"download_excel_{phone_number}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            "Choose a format to download the phone OSINT report:",
            reply_markup=reply_markup
        )

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        data = query.data

        if data.startswith("download_html_"):
            phone_number = data.replace("download_html_", "")
            html_report = self.reporter.generate_phone_report_html(phone_number)
            with open("phone_report.html", "w", encoding="utf-8") as f:
                f.write(html_report)
            await query.message.reply_document(InputFile("phone_report.html"), filename="phone_report.html")
            try:
                os.remove("phone_report.html")
            except Exception:
                pass

        elif data.startswith("download_excel_"):
            phone_number = data.replace("download_excel_", "")
            excel_bytes = self.reporter.generate_phone_report_excel(phone_number)
            await query.message.reply_document(excel_bytes, filename="phone_report.xlsx")

    def run(self):
        logger.info("OSINT Bot is running...")
        self.application.run_polling()

if __name__ == "__main__":
    import sys

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token and len(sys.argv) > 1:
        token = sys.argv[1]
    if not token:
        print("Please set TELEGRAM_BOT_TOKEN environment variable or pass token as argument.")
        sys.exit(1)

    bot = OSINTBot(token)
    bot.run()
