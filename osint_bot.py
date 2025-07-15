#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import logging
import json
import sqlite3
from datetime import datetime
import signal
import traceback
from pathlib import Path

# Check for required libraries and install if missing
try:
    import telebot
    import requests
except ImportError:
    print("Installing required packages...")
    os.system("pip install pyTelegramBotAPI requests")
    import telebot
    import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("osint_bot")

# Setup data directory
DATA_DIR = Path("/data")
if not DATA_DIR.exists():
    logger.warning(f"Data directory {DATA_DIR} doesn't exist, using local directory")
    DATA_DIR = Path("./data")
    DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "osint.db"
logger.info(f"Using database at {DB_PATH}")

# Setup database
def setup_database():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Requests table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command TEXT,
            args TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        # IP cache
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Domain cache
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_cache (
            domain TEXT PRIMARY KEY,
            data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        logger.error(traceback.format_exc())
        return False
    return True

# Get token with robust error handling
def get_bot_token():
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not found!")
        sys.exit(1)
    return token

# Register user with error handling
def register_user(user):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO users (id, first_name, last_name, username) VALUES (?, ?, ?, ?)",
            (user.id, user.first_name, user.last_name, user.username)
        )
        conn.commit()
        conn.close()
        logger.debug(f"User registered or updated: {user.id} - {user.first_name}")
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        logger.error(traceback.format_exc())

# Log request with error handling
def log_request(user_id, command, args=""):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO requests (user_id, command, args) VALUES (?, ?, ?)",
            (user_id, command, args)
        )
        conn.commit()
        conn.close()
        logger.debug(f"Request logged: {user_id} - {command} {args}")
    except Exception as e:
        logger.error(f"Error logging request: {e}")
        logger.error(traceback.format_exc())

# Cache functions with error handling
def get_from_cache(table, key_field, key_value):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT data FROM {table} WHERE {key_field} = ? AND datetime(timestamp) > datetime('now', '-1 day')",
            (key_value,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return json.loads(result[0])
        return None
    except Exception as e:
        logger.error(f"Error getting data from cache: {e}")
        logger.error(traceback.format_exc())
        return None

def add_to_cache(table, key_field, key_value, data):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            f"INSERT OR REPLACE INTO {table} ({key_field}, data) VALUES (?, ?)",
            (key_value, json.dumps(data))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error adding data to cache: {e}")
        logger.error(traceback.format_exc())

# Initialize bot with error handling
def create_bot():
    try:
        token = get_bot_token()
        return telebot.TeleBot(token)
    except Exception as e:
        logger.error(f"Error creating bot: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)

# Handle signals for graceful shutdown
def setup_signal_handlers(bot):
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down gracefully...")
        bot.stop_polling()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

# Command handlers
def setup_handlers(bot):
    @bot.message_handler(commands=['start'])
    def start_command(message):
        try:
            register_user(message.from_user)
            log_request(message.from_user.id, "/start")
            
            bot.reply_to(
                message, 
                f"Привет, {message.from_user.first_name}! Я OSINT бот.\n"
                f"Используйте /help чтобы узнать доступные команды."
            )
            logger.info(f"Start command from user {message.from_user.id}")
        except Exception as e:
            logger.error(f"Error in start command: {e}")
            bot.reply_to(message, "Произошла ошибка. Попробуйте позже.")

    @bot.message_handler(commands=['help'])
    def help_command(message):
        try:
            register_user(message.from_user)
            log_request(message.from_user.id, "/help")
            
            help_text = (
                "🔍 *OSINT Bot* 🔍\n\n"
                "Доступные команды:\n"
                "/start - Начать работу с ботом\n"
                "/help - Показать эту справку\n"
                "/ip [IP-адрес] - Получить информацию об IP-адресе\n"
                "/domain [домен] - Получить информацию о домене\n"
                "/stats - Показать статистику использования бота\n"
                "/about - Информация о боте"
            )
            bot.send_message(message.chat.id, help_text, parse_mode="Markdown")
            logger.info(f"Help command from user {message.from_user.id}")
        except Exception as e:
            logger.error(f"Error in help command: {e}")
            bot.reply_to(message, "Произошла ошибка. Попробуйте позже.")

    @bot.message_handler(commands=['ip'])
    def ip_command(message):
        try:
            register_user(message.from_user)
            
            command_parts = message.text.split(' ', 1)
            if len(command_parts) < 2:
                bot.send_message(message.chat.id, "Пожалуйста, укажите IP-адрес. Пример: /ip 8.8.8.8")
                return
                
            ip = command_parts[1].strip()
            log_request(message.from_user.id, "/ip", ip)
            
            # Check cache
            cached_data = get_from_cache("ip_cache", "ip", ip)
            if cached_data:
                logger.info(f"Using cached data for IP: {ip}")
                format_and_send_ip_info(bot, message.chat.id, cached_data)
                return
                
            # Get new data
            logger.info(f"Fetching IP info for: {ip}")
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                add_to_cache("ip_cache", "ip", ip, data)
                format_and_send_ip_info(bot, message.chat.id, data)
            else:
                bot.send_message(
                    message.chat.id, 
                    f"❌ Ошибка получения информации об IP: {response.status_code}"
                )
        except requests.RequestException as e:
            logger.error(f"Network error in IP command: {e}")
            bot.send_message(message.chat.id, "❌ Ошибка сети при получении данных. Попробуйте позже.")
        except Exception as e:
            logger.error(f"Error in IP command: {e}")
            logger.error(traceback.format_exc())
            bot.send_message(message.chat.id, f"❌ Произошла ошибка: {str(e)}")

    def format_and_send_ip_info(bot, chat_id, data):
        result = (
            f"📍 *IP информация*\n\n"
            f"🔹 IP: `{data.get('ip')}`\n"
            f"🔹 Город: {data.get('city', 'Н/Д')}\n"
            f"🔹 Регион: {data.get('region', 'Н/Д')}\n"
            f"🔹 Страна: {data.get('country', 'Н/Д')}\n"
            f"🔹 Организация: {data.get('org', 'Н/Д')}\n"
            f"🔹 Координаты: `{data.get('loc', 'Н/Д')}`"
        )
        bot.send_message(chat_id, result, parse_mode="Markdown")

    @bot.message_handler(commands=['domain'])
    def domain_command(message):
        try:
            register_user(message.from_user)
            
            command_parts = message.text.split(' ', 1)
            if len(command_parts) < 2:
                bot.send_message(message.chat.id, "Пожалуйста, укажите домен. Пример: /domain example.com")
                return
                
            domain = command_parts[1].strip()
            log_request(message.from_user.id, "/domain", domain)
            
            # Check cache
            cached_data = get_from_cache("domain_cache", "domain", domain)
            if cached_data:
                logger.info(f"Using cached data for domain: {domain}")
                format_and_send_domain_info(bot, message.chat.id, domain, cached_data)
                return
                
            # Get new data
            logger.info(f"Fetching domain info for: {domain}")
            try:
                whois_api_key = os.getenv('WHOIS_API_KEY')
                if whois_api_key:
                    response = requests.get(
                        f"https://api.whoisfreaks.com/v1.0/whois?apiKey={whois_api_key}&domainName={domain}&format=json",
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        add_to_cache("domain_cache", "domain", domain, data)
                        format_and_send_domain_info(bot, message.chat.id, domain, data)
                    else:
                        bot.send_message(
                            message.chat.id,
                            f"❌ Ошибка получения информации о домене: {response.status_code}"
                        )
                else:
                    # Fallback to a free service
                    response = requests.get(f"https://api.domainsdb.info/v1/domains/search?domain={domain}", timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('domains') and len(data['domains']) > 0:
                            domain_data = data['domains'][0]
                            add_to_cache("domain_cache", "domain", domain, domain_data)
                            format_and_send_domain_info(bot, message.chat.id, domain, domain_data)
                        else:
                            bot.send_message(message.chat.id, f"❌ Информация о домене {domain} не найдена.")
                    else:
                        bot.send_message(
                            message.chat.id,
                            f"❌ Для расширенной информации нужно настроить API ключ. Установите WHOIS_API_KEY."
                        )
            except requests.RequestException as e:
                logger.error(f"Network error in domain command: {e}")
                bot.send_message(message.chat.id, "❌ Ошибка сети при получении данных. Попробуйте позже.")
        except Exception as e:
            logger.error(f"Error in domain command: {e}")
            logger.error(traceback.format_exc())
            bot.send_message(message.chat.id, f"❌ Произошла ошибка: {str(e)}")

    def format_and_send_domain_info(bot, chat_id, domain, data):
        if isinstance(data, dict) and data.get('create_date'):
            result = (
                f"🌐 *Информация о домене*\n\n"
                f"🔹 Домен: `{domain}`\n"
                f"🔹 Создан: {data.get('create_date', 'Н/Д')}\n"
                f"🔹 Истекает: {data.get('expiry_date', 'Н/Д')}\n"
                f"🔹 Регистратор: {data.get('registrar', 'Н/Д')}\n"
                f"🔹 Владелец: {data.get('registrant', {}).get('name', 'Н/Д')}"
            )
        else:
            result = (
                f"🌐 *Информация о домене*\n\n"
                f"🔹 Домен: `{domain}`\n"
                f"🔹 Создан: {data.get('create_date', 'Н/Д')}\n"
                f"🔹 Обновлен: {data.get('update_date', 'Н/Д')}\n"
                f"🔹 Страна: {data.get('country', 'Н/Д')}"
            )
        
        bot.send_message(chat_id, result, parse_mode="Markdown")

    @bot.message_handler(commands=['stats'])
    def stats_command(message):
        try:
            register_user(message.from_user)
            log_request(message.from_user.id, "/stats")
            
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()
            
            # Get total users
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            # Get total requests
            cursor.execute("SELECT COUNT(*) FROM requests")
            total_requests = cursor.fetchone()[0]
            
            # Get popular commands
            cursor.execute("""
                SELECT command, COUNT(*) as count 
                FROM requests 
                GROUP BY command 
                ORDER BY count DESC 
                LIMIT 5
            """)
            popular_commands = cursor.fetchall()
            
            # Create stats message
            stats_text = (
                "📊 *Статистика бота*\n\n"
                f"👤 Всего пользователей: {total_users}\n"
                f"🔢 Всего запросов: {total_requests}\n\n"
                "📈 Популярные команды:\n"
            )
            
            for cmd, count in popular_commands:
                stats_text += f"  {cmd}: {count} раз\n"
                
            conn.close()
            bot.send_message(message.chat.id, stats_text, parse_mode="Markdown")
            logger.info(f"Stats command from user {message.from_user.id}")
        except Exception as e:
            logger.error(f"Error in stats command: {e}")
            logger.error(traceback.format_exc())
            bot.send_message(message.chat.id, "❌ Ошибка при получении статистики.")

    @bot.message_handler(commands=['about'])
    def about_command(message):
        try:
            register_user(message.from_user)
            log_request(message.from_user.id, "/about")
            
            about_text = (
                "🔍 *OSINT Bot* 🔍\n\n"
                "Бот для сбора и анализа открытой информации.\n\n"
                "🔹 Версия: 1.0.0\n"
                "🔹 Автор: nyrumx\n"
                "🔹 Работает на: Render (background worker)\n"
                f"🔹 Запущен: {datetime.now().strftime('%Y-%m-%d')}\n\n"
                "GitHub: https://github.com/nyrumx/osint-bot"
            )
            
            bot.send_message(message.chat.id, about_text, parse_mode="Markdown")
            logger.info(f"About command from user {message.from_user.id}")
        except Exception as e:
            logger.error(f"Error in about command: {e}")
            logger.error(traceback.format_exc())
            bot.send_message(message.chat.id, "❌ Ошибка при получении информации о боте.")

    @bot.message_handler(func=lambda message: True)
    def unknown_command(message):
        try:
            register_user(message.from_user)
            log_request(message.from_user.id, "unknown", message.text[:50])
            
            bot.reply_to(
                message, 
                "Я не понимаю эту команду. Используйте /help для списка доступных команд."
            )
            logger.info(f"Unknown command from user {message.from_user.id}: {message.text[:50]}")
        except Exception as e:
            logger.error(f"Error in unknown command handler: {e}")
            logger.error(traceback.format_exc())

# Main function with error handling and automatic restarts
def main():
    logger.info("Starting OSINT Bot...")
    
    # Setup database
    if not setup_database():
        logger.error("Failed to setup database. Exiting.")
        sys.exit(1)
    
    # Create bot
    bot = create_bot()
    logger.info("Bot created successfully")
    
    # Setup signal handlers
    setup_signal_handlers(bot)
    
    # Setup command handlers
    setup_handlers(bot)
    
    # Start polling with automatic recovery
    while True:
        try:
            logger.info("Starting bot polling...")
            bot.infinity_polling(timeout=10, long_polling_timeout=5)
        except Exception as e:
            logger.error(f"Polling error: {e}")
            logger.error(traceback.format_exc())
            logger.info("Restarting polling in 10 seconds...")
            time.sleep(10)

if __name__ == "__main__":
    main()