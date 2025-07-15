# OSINT Bot 🤖

A Telegram bot for Open Source Intelligence (OSINT) operations with automated GitHub Actions deployment.

## Features

🔍 **IP Address Lookup**
- Geolocation information
- ISP and organization details
- ASN information
- Timezone and coordinates

🌐 **Domain Information**
- DNS resolution
- IP address mapping
- Domain status checking

📋 **WHOIS Lookup**
- Domain registration information
- Extensible for full WHOIS integration

⚡ **Real-time Operations**
- Interactive Telegram interface
- Inline keyboards for easy navigation
- Auto-detection of IPs and domains in messages

## Setup Instructions

### Prerequisites

1. **Telegram Bot Token**
   - Create a bot using [@BotFather](https://t.me/BotFather)
   - Get your bot token
   - Note your chat ID (use [@userinfobot](https://t.me/userinfobot) to get it)

2. **GitHub Repository Secrets**
   - Go to your repository settings
   - Navigate to "Secrets and variables" → "Actions"
   - Add the following secrets:
     - `TELEGRAM_BOT_TOKEN`: Your bot token from BotFather
     - `CHAT_ID`: Your Telegram chat ID for admin notifications

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/n81-com/osint-bot.git
   cd osint-bot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   export TELEGRAM_BOT_TOKEN="your_bot_token_here"
   export CHAT_ID="your_chat_id_here"
   ```

4. **Run the bot**
   ```bash
   python osint_bot.py
   ```

### GitHub Actions Deployment

The bot is automatically deployed using GitHub Actions when you push to the `main` or `master` branch.

#### Workflow Features

- ✅ **Automated Testing**: Syntax checking and validation
- 🔧 **Dependency Management**: Automatic pip installation
- 🚀 **Process Management**: Uses PM2 for keeping the bot alive
- 🔒 **Secrets Management**: Secure handling of sensitive tokens
- 📊 **Health Checks**: Deployment verification

#### Setting Up Deployment

1. **Add Repository Secrets**
   - Go to your repository → Settings → Secrets and variables → Actions
   - Add these secrets:
     ```
     TELEGRAM_BOT_TOKEN: your_telegram_bot_token
     CHAT_ID: your_telegram_chat_id
     ```

2. **Push to Main Branch**
   ```bash
   git push origin main
   ```

3. **Monitor Deployment**
   - Check the "Actions" tab in your repository
   - View logs and deployment status
   - The bot will start automatically upon successful deployment

## Usage

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/start` | Initialize the bot and show welcome message | `/start` |
| `/help` | Show all available commands | `/help` |
| `/ip <ip_address>` | Get detailed IP information | `/ip 8.8.8.8` |
| `/domain <domain>` | Get domain information | `/domain google.com` |
| `/whois <domain>` | Get WHOIS information | `/whois example.com` |
| `/status` | Check bot status | `/status` |

### Interactive Features

- **Auto-detection**: Send an IP or domain directly, and the bot will suggest the appropriate command
- **Inline Keyboards**: Use buttons for quick access to different features
- **Error Handling**: Clear error messages for invalid inputs

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `TELEGRAM_BOT_TOKEN` | Token from @BotFather | Yes |
| `CHAT_ID` | Admin chat ID for notifications | Yes |

### Extending the Bot

The bot is designed to be easily extensible. You can add new OSINT features by:

1. **Adding new command handlers** in the `setup_handlers()` method
2. **Creating new lookup functions** following the existing pattern
3. **Integrating additional APIs** for more comprehensive OSINT capabilities

#### Example: Adding a new command

```python
async def new_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle new lookup command"""
    if not context.args:
        await update.message.reply_text("Usage: `/newlookup <input>`", parse_mode='Markdown')
        return
    
    # Your lookup logic here
    # ...
    
    await update.message.reply_text(result, parse_mode='Markdown')

# Add to setup_handlers():
self.application.add_handler(CommandHandler("newlookup", self.new_lookup))
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Never commit secrets** to the repository
2. **Use environment variables** for sensitive information
3. **Validate all inputs** to prevent injection attacks
4. **Rate limiting** should be implemented for production use
5. **This bot is for educational and legitimate OSINT purposes only**

## Troubleshooting

### Health Check Tool 🔧

Before reporting issues, please run the health check script to diagnose common problems:

```bash
python health_check.py
```

This tool will check:
- Environment variables configuration
- Python dependencies
- Database connectivity
- Network access to OSINT APIs
- Bot token validity

### Common Issues

1. **Bot not responding**
   - Run `python health_check.py` first
   - Check if `TELEGRAM_BOT_TOKEN` is correct
   - Verify the bot is added to the chat
   - Check GitHub Actions logs for deployment errors

2. **IP lookup failing**
   - Ensure internet connectivity (use health check tool)
   - Check if the IP format is valid
   - API rate limits may apply
   - Some countries may block certain OSINT APIs

3. **GitHub Actions deployment failing**
   - Verify all secrets are properly set
   - Check the workflow logs in the Actions tab
   - Ensure Python dependencies are correctly specified

### Reporting Issues 📝

When reporting issues, please:

1. **Run the health check first**: `python health_check.py`
2. **Use the appropriate issue template**:
   - [Bug Report](https://github.com/iRUssii/osint-bot/issues/new?template=bug_report.md) - For general bugs
   - [OSINT Command Issue](https://github.com/iRUssii/osint-bot/issues/new?template=osint_command_issue.md) - For command-specific problems
   - [Feature Request](https://github.com/iRUssii/osint-bot/issues/new?template=feature_request.md) - For new features
3. **Include the health check output** in your issue
4. **Provide specific examples** of what you tried and what went wrong

### Logs

The bot generates logs in two locations:
- Console output (visible in GitHub Actions)
- `osint_bot.log` file (when running locally)

For debugging, you can increase log verbosity by setting the `DEBUG` environment variable:
```bash
export DEBUG=1
python osint_bot.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source and available under the [MIT License](LICENSE).

## Disclaimer

This bot is intended for educational and legitimate OSINT research purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## Support

For questions or issues:
- Open an issue on GitHub
- Check the troubleshooting section
- Review the GitHub Actions logs for deployment issues

---

**Built with ❤️ for the OSINT community**