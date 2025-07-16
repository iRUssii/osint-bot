# OSINT Bot

## Overview

OSINT Bot is an open-source Telegram bot for automating Open Source Intelligence (OSINT) gathering, analysis, and reporting.

## Features

- IP Address Lookup
- Domain Information
- WHOIS Lookup
- Phone Number OSINT (`/phone` command)
- Downloadable reports (HTML/Excel)
- Extensible for new OSINT features

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone https://github.com/iRUssii/osint-bot.git
   cd osint-bot
   ```

2. **Install dependencies (with Poetry):**
   ```sh
   poetry install
   ```

3. **Set your environment variables:**
   - `TELEGRAM_BOT_TOKEN`
   - `CHAT_ID` (for admin notifications)

4. **Run the bot:**
   ```sh
   poetry run python osint_bot.py
   ```

## Usage

- Use `/start` to view available commands.
- Use `/phone <number>` for phone OSINT lookups.

## Contributing

Pull requests are welcome! Please add tests for new features.

## License

MIT
