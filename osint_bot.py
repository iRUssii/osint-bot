python -m ensurepip --upgrade
"""
OSINT Telegram Bot
A simple OSINT (Open Source Intelligence) bot for Telegram with basic information gathering capabilities.
"""

import os
import sys
import asyncio
import logging
import requests
import re
from typing import Optional, Dict, Any
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler, ContextTypes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osint_bot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class OSINTBot:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.application = Application.builder().token(token).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up command and message handlers"""
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("ip", self.ip_lookup))
        self.application.add_handler(CommandHandler("domain", self.domain_lookup))
        self.application.add_handler(CommandHandler("whois", self.whois_lookup))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CallbackQueryHandler(self.button_callback))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        keyboard = [
            [InlineKeyboardButton("🔍 IP Lookup", callback_data="ip_help")],
            [InlineKeyboardButton("🌐 Domain Info", callback_data="domain_help")],
            [InlineKeyboardButton("📋 WHOIS", callback_data="whois_help")],
            [InlineKeyboardButton("❓ Help", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_message = """
🤖 **OSINT Bot** - Open Source Intelligence Tool

Welcome! I can help you gather information about:
• IP addresses
• Domain names
• WHOIS information
• And more OSINT capabilities

Use the buttons below or type commands directly:
/help - Show all available commands
/ip <ip_address> - Look up IP information
/domain <domain> - Get domain information
/whois <domain> - Get WHOIS information
/status - Check bot status
        """
        
        await update.message.reply_text(welcome_message, reply_markup=reply_markup, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_message = """
📚 **Available Commands:**

🔍 **IP Lookup:**
`/ip <ip_address>` - Get information about an IP address

🌐 **Domain Information:**
`/domain <domain>` - Get domain information

📋 **WHOIS Lookup:**
`/whois <domain>` - Get WHOIS information for a domain

⚡ **System:**
`/status` - Check bot status
`/help` - Show this help message

**Example Usage:**
• `/ip 8.8.8.8`
• `/domain google.com`
• `/whois example.com`

⚠️ **Note:** This bot is for educational and legitimate OSINT purposes only.
        """
        await update.message.reply_text(help_message, parse_mode='Markdown')
    
    async def ip_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle IP lookup command"""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: `/ip <ip_address>`", parse_mode='Markdown')
            return
        
        ip_address = context.args[0]
        
        # Validate IP address format
        if not self.is_valid_ip(ip_address):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        try:
            await update.message.reply_text(f"🔍 Looking up information for IP: `{ip_address}`...", parse_mode='Markdown')
            
            # Use ipapi.co for IP geolocation
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=10)
            data = response.json()
            
            if 'error' in data:
                await update.message.reply_text(f"❌ Error: {data['reason']}")
                return
            
            result = f"""
🔍 **IP Information for {ip_address}:**

🌍 **Location:**
• Country: {data.get('country_name', 'Unknown')} ({data.get('country_code', 'Unknown')})
• Region: {data.get('region', 'Unknown')}
• City: {data.get('city', 'Unknown')}
• Timezone: {data.get('timezone', 'Unknown')}

🏢 **Organization:**
• ISP: {data.get('org', 'Unknown')}
• ASN: {data.get('asn', 'Unknown')}

📍 **Coordinates:**
• Latitude: {data.get('latitude', 'Unknown')}
• Longitude: {data.get('longitude', 'Unknown')}
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in IP lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while looking up IP information: {str(e)}")
    
    async def domain_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle domain lookup command"""
        if not context.args:
            await update.message.reply_text("Please provide a domain name. Usage: `/domain <domain>`", parse_mode='Markdown')
            return
        
        domain = context.args[0].lower()
        
        # Validate domain format
        if not self.is_valid_domain(domain):
            await update.message.reply_text("❌ Invalid domain format")
            return
        
        try:
            await update.message.reply_text(f"🌐 Looking up information for domain: `{domain}`...", parse_mode='Markdown')
            
            # Simple domain information
            import socket
            try:
                ip_address = socket.gethostbyname(domain)
                result = f"""
🌐 **Domain Information for {domain}:**

🔗 **DNS Information:**
• IP Address: {ip_address}
• Status: Active

📊 **Additional Info:**
• Domain appears to be resolving correctly
• Use `/ip {ip_address}` for more details about the server
                """
            except socket.gaierror:
                result = f"❌ Domain `{domain}` does not resolve to an IP address"
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in domain lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while looking up domain information: {str(e)}")
    
    async def whois_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle WHOIS lookup command"""
        if not context.args:
            await update.message.reply_text("Please provide a domain name. Usage: `/whois <domain>`", parse_mode='Markdown')
            return
        
        domain = context.args[0].lower()
        
        if not self.is_valid_domain(domain):
            await update.message.reply_text("❌ Invalid domain format")
            return
        
        try:
            await update.message.reply_text(f"📋 Looking up WHOIS information for domain: `{domain}`...", parse_mode='Markdown')
            
            # For a production bot, you would integrate with a WHOIS service
            # This is a placeholder implementation
            result = f"""
📋 **WHOIS Information for {domain}:**

ℹ️ **Note:** This is a simplified implementation.
For full WHOIS functionality, integrate with services like:
• whois-json.whoisxmlapi.com
• whoisapi.whoisxmlapi.com
• Or use python-whois library

🔧 **Current Status:** Basic implementation
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in WHOIS lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while looking up WHOIS information: {str(e)}")
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle status command"""
        status_message = """
⚡ **Bot Status:**

🟢 **Online:** Bot is running normally
🔧 **Features:** IP lookup, Domain info, WHOIS
📊 **Version:** 1.0.0
🕒 **Uptime:** Active

✅ All systems operational
        """
        await update.message.reply_text(status_message, parse_mode='Markdown')
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular text messages"""
        text = update.message.text
        
        # Auto-detect IP addresses or domains in messages
        if self.is_valid_ip(text):
            await update.message.reply_text(f"🔍 Detected IP address! Use `/ip {text}` for detailed information", parse_mode='Markdown')
        elif self.is_valid_domain(text):
            await update.message.reply_text(f"🌐 Detected domain! Use `/domain {text}` for information", parse_mode='Markdown')
        else:
            await update.message.reply_text("💡 Use /help to see available commands or click the buttons in /start")
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        await query.answer()
        
        if query.data == "ip_help":
            await query.edit_message_text("🔍 **IP Lookup**\n\nUse `/ip <ip_address>` to get detailed information about an IP address.\n\nExample: `/ip 8.8.8.8`", parse_mode='Markdown')
        elif query.data == "domain_help":
            await query.edit_message_text("🌐 **Domain Information**\n\nUse `/domain <domain>` to get information about a domain.\n\nExample: `/domain google.com`", parse_mode='Markdown')
        elif query.data == "whois_help":
            await query.edit_message_text("📋 **WHOIS Lookup**\n\nUse `/whois <domain>` to get WHOIS information for a domain.\n\nExample: `/whois example.com`", parse_mode='Markdown')
        elif query.data == "help":
            await self.help_command(update, context)
    
    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(domain))
    
    async def run(self):
        """Run the bot"""
        logger.info("Starting OSINT Bot...")
        
        # Send startup message to admin
        try:
            await self.application.bot.send_message(
                chat_id=self.chat_id,
                text="🤖 OSINT Bot is starting up...",
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Failed to send startup message: {e}")
        
        # Start polling
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()
        
        logger.info("OSINT Bot is running!")
        
        # Keep the bot running
        await self.application.updater.idle()

async def main():
    """Main function"""
    # Get environment variables
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('CHAT_ID')
    
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable is required")
        sys.exit(1)
    
    if not chat_id:
        logger.error("CHAT_ID environment variable is required")
        sys.exit(1)
    
    # Create and run bot
    bot = OSINTBot(token, chat_id)
    
    try:
        await bot.run()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())