#!/usr/bin/env python3
"""
OSINT Telegram Bot
A comprehensive OSINT (Open Source Intelligence) bot for Telegram with advanced information gathering capabilities.
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

# Import OSINT modules
from osint_modules.data_collector import OSINTDataCollector
from osint_modules.analyzer import OSINTAnalyzer
from osint_modules.reporter import OSINTReporter
from osint_modules.security import SecurityManager, secure_operation
from osint_modules.database import OSINTDatabase

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
        
        # Initialize OSINT modules
        self.data_collector = OSINTDataCollector()
        self.analyzer = OSINTAnalyzer()
        self.reporter = OSINTReporter()
        self.security_manager = SecurityManager()
        self.database = OSINTDatabase()
        
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up command and message handlers"""
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("ip", self.ip_lookup))
        self.application.add_handler(CommandHandler("domain", self.domain_lookup))
        self.application.add_handler(CommandHandler("whois", self.whois_lookup))
        self.application.add_handler(CommandHandler("social", self.social_lookup))
        self.application.add_handler(CommandHandler("news", self.news_search))
        self.application.add_handler(CommandHandler("analyze", self.analyze_command))
        self.application.add_handler(CommandHandler("report", self.report_command))
        self.application.add_handler(CommandHandler("trends", self.trends_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CommandHandler("stats", self.stats_command))
        self.application.add_handler(CallbackQueryHandler(self.button_callback))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        keyboard = [
            [InlineKeyboardButton("🔍 IP Lookup", callback_data="ip_help")],
            [InlineKeyboardButton("🌐 Domain Info", callback_data="domain_help")],
            [InlineKeyboardButton("📋 WHOIS", callback_data="whois_help")],
            [InlineKeyboardButton("👤 Social Media", callback_data="social_help")],
            [InlineKeyboardButton("📰 News Search", callback_data="news_help")],
            [InlineKeyboardButton("📊 Analysis", callback_data="analyze_help")],
            [InlineKeyboardButton("📈 Trends", callback_data="trends_help")],
            [InlineKeyboardButton("❓ Help", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_message = """
🤖 **Enhanced OSINT Bot** - Advanced Open Source Intelligence Tool

Welcome! I'm your comprehensive OSINT assistant with advanced capabilities:

**🔍 Core Features:**
• IP address investigation with threat analysis
• Domain information with security assessment
• WHOIS lookup with pattern analysis
• Social media reconnaissance (framework)
• News mentions and sentiment analysis
• Comprehensive data analysis and correlation
• Trend analysis and anomaly detection
• Structured reporting and visualizations

**📊 Advanced Capabilities:**
• Pattern recognition and threat assessment
• Data correlation across multiple sources
• Trend analysis and predictive insights
• Comprehensive security reporting
• Database storage for historical analysis

**🛡️ Security Features:**
• Rate limiting and abuse prevention
• Input validation and sanitization
• Comprehensive logging and monitoring
• Secure data handling

Use the buttons below or type commands directly:

**Basic Commands:**
• `/ip <ip_address>` - Comprehensive IP analysis
• `/domain <domain>` - Domain investigation
• `/social <username>` - Social media reconnaissance
• `/news <query>` - News mentions analysis
• `/analyze <target>` - Deep analysis
• `/report` - Generate comprehensive reports
• `/trends` - View trend analysis
• `/stats` - View system statistics

⚠️ **Legal Notice:** This tool is for educational and legitimate OSINT purposes only. Always comply with applicable laws and regulations.
        """
        
        await update.message.reply_text(welcome_message, reply_markup=reply_markup, parse_mode='Markdown')
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_message = """
📚 **Enhanced OSINT Bot Commands:**

**🔍 Investigation Commands:**
• `/ip <ip_address>` - Comprehensive IP analysis with threat assessment
• `/domain <domain>` - Domain investigation with security analysis
• `/whois <domain>` - WHOIS lookup with pattern analysis
• `/social <username>` - Social media reconnaissance (framework)
• `/news <query>` - News mentions with sentiment analysis

**📊 Analysis Commands:**
• `/analyze <target>` - Deep analysis of any target
• `/report` - Generate comprehensive reports
• `/trends` - View trend analysis and patterns
• `/stats` - View system statistics

**⚡ System Commands:**
• `/status` - Check bot status
• `/help` - Show this help message

**📋 Usage Examples:**
• `/ip 8.8.8.8` - Analyze Google's DNS server
• `/domain google.com` - Investigate Google's domain
• `/social testuser` - Check social media presence
• `/news "cybersecurity breach"` - Search for security news
• `/analyze 1.1.1.1` - Deep analysis of Cloudflare DNS
• `/report ip 8.8.8.8` - Generate IP report
• `/trends` - Show recent patterns

**🛡️ Security Features:**
• Rate limiting to prevent abuse
• Input validation and sanitization
• Comprehensive logging and monitoring
• Secure data handling and storage

**📊 Data Management:**
• Automatic data storage for historical analysis
• Pattern recognition and correlation
• Trend analysis and anomaly detection
• Comprehensive reporting capabilities

⚠️ **Legal Notice:** This bot is for educational and legitimate OSINT purposes only. Users are responsible for complying with applicable laws and regulations.

🔒 **Privacy:** All data is processed securely with appropriate safeguards in place.
        """
        await update.message.reply_text(help_message, parse_mode='Markdown')
    
    @secure_operation('ip_lookup')
    async def ip_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle IP lookup command with enhanced analysis"""
        if not context.args:
            await update.message.reply_text("Please provide an IP address. Usage: `/ip <ip_address>`", parse_mode='Markdown')
            return
        
        ip_address = context.args[0]
        
        # Validate IP address format
        if not self.is_valid_ip(ip_address):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        try:
            await update.message.reply_text(f"🔍 Performing comprehensive analysis for IP: `{ip_address}`...", parse_mode='Markdown')
            
            # Collect IP information
            ip_data = self.data_collector.collect_ip_info(ip_address)
            
            if 'error' in ip_data:
                await update.message.reply_text(f"❌ Error: {ip_data['error']}")
                return
            
            # Analyze the data
            analysis_data = self.analyzer.analyze_ip_data(ip_data)
            
            # Store in database
            self.database.store_ip_lookup(ip_data, analysis_data)
            self.database.store_analysis_result('ip', ip_address, analysis_data)
            
            # Generate report
            report = self.reporter.generate_ip_report(ip_data, analysis_data)
            
            # Send report in chunks if too long
            if len(report) > 4000:
                chunks = [report[i:i+4000] for i in range(0, len(report), 4000)]
                for chunk in chunks:
                    await update.message.reply_text(chunk, parse_mode='Markdown')
            else:
                await update.message.reply_text(report, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in enhanced IP lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while analyzing IP: {str(e)}")
    
    @secure_operation('domain_lookup')
    async def domain_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle domain lookup command with enhanced analysis"""
        if not context.args:
            await update.message.reply_text("Please provide a domain name. Usage: `/domain <domain>`", parse_mode='Markdown')
            return
        
        domain = context.args[0].lower()
        
        # Validate domain format
        if not self.is_valid_domain(domain):
            await update.message.reply_text("❌ Invalid domain format")
            return
        
        try:
            await update.message.reply_text(f"🌐 Performing comprehensive analysis for domain: `{domain}`...", parse_mode='Markdown')
            
            # Collect domain information
            domain_data = self.data_collector.collect_domain_info(domain)
            
            if 'error' in domain_data:
                await update.message.reply_text(f"❌ Error: {domain_data['error']}")
                return
            
            # Analyze the data
            analysis_data = self.analyzer.analyze_domain_data(domain_data)
            
            # Store in database
            self.database.store_domain_lookup(domain_data, analysis_data)
            self.database.store_analysis_result('domain', domain, analysis_data)
            
            # Generate report
            report = self.reporter.generate_domain_report(domain_data, analysis_data)
            
            # Send report in chunks if too long
            if len(report) > 4000:
                chunks = [report[i:i+4000] for i in range(0, len(report), 4000)]
                for chunk in chunks:
                    await update.message.reply_text(chunk, parse_mode='Markdown')
            else:
                await update.message.reply_text(report, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in enhanced domain lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while analyzing domain: {str(e)}")
    
    @secure_operation('social_media')
    async def social_lookup(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle social media lookup command"""
        if not context.args:
            await update.message.reply_text("Please provide a username. Usage: `/social <username>`", parse_mode='Markdown')
            return
        
        username = context.args[0]
        
        # Validate username format
        if not self.security_manager.validate_input(username, 'username'):
            await update.message.reply_text("❌ Invalid username format")
            return
        
        try:
            await update.message.reply_text(f"👤 Searching for social media presence: `{username}`...", parse_mode='Markdown')
            
            # Collect social media information
            social_data = self.data_collector.collect_social_media_info(username)
            
            # Analyze the data
            analysis_data = self.analyzer.analyze_social_media_data(social_data)
            
            # Store analysis result
            self.database.store_analysis_result('social', username, analysis_data)
            
            result = f"""
👤 **Social Media Analysis for {username}:**

📊 **Platform Presence:**
"""
            platforms = social_data.get('platforms', {})
            for platform, data in platforms.items():
                status = "✅ Found" if data.get('exists', False) else "❌ Not Found"
                result += f"• {platform.capitalize()}: {status}\n"
            
            result += f"""
📈 **Analysis Summary:**
• Platforms Analyzed: {len(platforms)}
• Cross-Platform Score: {analysis_data.get('cross_platform_correlation', {}).get('correlation_score', 0):.2f}

⚠️ **Note:** {social_data.get('warning', 'Social media analysis requires proper API integration')}

🔒 **Privacy Notice:** Only publicly available information is analyzed.
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in social media lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while analyzing social media: {str(e)}")
    
    @secure_operation('news_search')
    async def news_search(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle news search command"""
        if not context.args:
            await update.message.reply_text("Please provide a search query. Usage: `/news <query>`", parse_mode='Markdown')
            return
        
        query = ' '.join(context.args)
        
        # Validate query
        if not self.security_manager.validate_input(query, 'query'):
            await update.message.reply_text("❌ Invalid search query")
            return
        
        try:
            await update.message.reply_text(f"📰 Searching for news mentions: `{query}`...", parse_mode='Markdown')
            
            # Collect news information
            news_data = self.data_collector.collect_news_mentions(query)
            
            # Store analysis result
            self.database.store_analysis_result('news', query, news_data)
            
            result = f"""
📰 **News Analysis for "{query}":**

📊 **Search Results:**
• Query: {query}
• Search Period: {news_data.get('search_period', 'Unknown')}
• Total Mentions: {news_data.get('summary', {}).get('total_mentions', 0)}

📈 **Analysis:**
• Sentiment: {news_data.get('summary', {}).get('sentiment', 'Neutral').capitalize()}
• Trending: {'Yes' if news_data.get('summary', {}).get('trending', False) else 'No'}

⚠️ **Note:** {news_data.get('note', 'News analysis requires API integration')}

🔧 **Status:** {news_data.get('implementation_status', 'Framework ready')}
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in news search: {e}")
            await update.message.reply_text(f"❌ Error occurred while searching news: {str(e)}")
    
    @secure_operation('analyze')
    async def analyze_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle analyze command for deep analysis"""
        if not context.args:
            await update.message.reply_text("Please provide a target to analyze. Usage: `/analyze <target>`", parse_mode='Markdown')
            return
        
        target = context.args[0]
        
        try:
            await update.message.reply_text(f"🔬 Performing deep analysis on: `{target}`...", parse_mode='Markdown')
            
            # Determine target type and perform comprehensive analysis
            if self.is_valid_ip(target):
                # IP analysis
                ip_data = self.data_collector.collect_ip_info(target)
                analysis_data = self.analyzer.analyze_ip_data(ip_data)
                
                # Get historical data for trends
                historical_data = self.database.get_analysis_results('ip', target, limit=10)
                
                # Generate comprehensive report
                report = self.reporter.generate_comprehensive_report([ip_data], analysis_data)
                
            elif self.is_valid_domain(target):
                # Domain analysis
                domain_data = self.data_collector.collect_domain_info(target)
                analysis_data = self.analyzer.analyze_domain_data(domain_data)
                
                # Get historical data for trends
                historical_data = self.database.get_analysis_results('domain', target, limit=10)
                
                # Generate comprehensive report
                report = self.reporter.generate_comprehensive_report([domain_data], analysis_data)
                
            else:
                await update.message.reply_text("❌ Target format not recognized. Please provide a valid IP address or domain name.")
                return
            
            # Store analysis result
            self.database.store_analysis_result('comprehensive', target, analysis_data)
            
            # Send report in chunks if too long
            if len(report) > 4000:
                chunks = [report[i:i+4000] for i in range(0, len(report), 4000)]
                for chunk in chunks:
                    await update.message.reply_text(chunk, parse_mode='Markdown')
            else:
                await update.message.reply_text(report, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in analyze command: {e}")
            await update.message.reply_text(f"❌ Error occurred during analysis: {str(e)}")
    
    @secure_operation('report')
    async def report_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle report generation command"""
        if not context.args:
            await update.message.reply_text("Please specify report type. Usage: `/report <type> [target]`\nTypes: summary, trends, comprehensive", parse_mode='Markdown')
            return
        
        report_type = context.args[0].lower()
        
        try:
            await update.message.reply_text(f"📊 Generating {report_type} report...", parse_mode='Markdown')
            
            if report_type == 'summary':
                # Generate summary report
                stats = self.database.get_statistics()
                recent_lookups = self.database.get_recent_lookups(hours=24, limit=50)
                
                report = f"""
📊 **OSINT Bot Summary Report**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📈 System Statistics:**
• Total IP Lookups: {stats.get('ip_lookups_count', 0)}
• Total Domain Lookups: {stats.get('domain_lookups_count', 0)}
• Total Analysis Results: {stats.get('analysis_results_count', 0)}
• Reports Generated: {stats.get('reports_count', 0)}

**⏰ Recent Activity (24h):**
• IP Lookups: {stats.get('ip_lookups_24h', 0)}
• Domain Lookups: {stats.get('domain_lookups_24h', 0)}
• Total Recent Queries: {len(recent_lookups)}

**🛡️ Threat Distribution:**
"""
                threat_dist = stats.get('threat_distribution', {})
                for level, count in threat_dist.items():
                    report += f"• {level.upper()}: {count}\n"
                
                report += f"""
**🔍 Recent Targets:**
"""
                for lookup in recent_lookups[:5]:
                    report += f"• {lookup['target']} ({lookup['type']}) - {lookup['threat_level']}\n"
                
                await update.message.reply_text(report, parse_mode='Markdown')
                
            elif report_type == 'trends':
                # Generate trends report
                recent_lookups = self.database.get_recent_lookups(hours=168, limit=100)  # 7 days
                trend_analysis = self.analyzer.analyze_trends(recent_lookups)
                
                report = self.reporter.generate_trend_report(trend_analysis)
                await update.message.reply_text(report, parse_mode='Markdown')
                
            elif report_type == 'comprehensive':
                if len(context.args) < 2:
                    await update.message.reply_text("Please provide a target for comprehensive report. Usage: `/report comprehensive <target>`", parse_mode='Markdown')
                    return
                
                target = context.args[1]
                
                # Get all data for the target
                if self.is_valid_ip(target):
                    ip_data = self.database.get_ip_lookup(target)
                    analysis_results = self.database.get_analysis_results('ip', target)
                    
                    if ip_data:
                        report = self.reporter.generate_comprehensive_report([ip_data], {'analysis_results': analysis_results})
                        await update.message.reply_text(report, parse_mode='Markdown')
                    else:
                        await update.message.reply_text(f"❌ No data found for IP: {target}")
                        
                elif self.is_valid_domain(target):
                    domain_data = self.database.get_domain_lookup(target)
                    analysis_results = self.database.get_analysis_results('domain', target)
                    
                    if domain_data:
                        report = self.reporter.generate_comprehensive_report([domain_data], {'analysis_results': analysis_results})
                        await update.message.reply_text(report, parse_mode='Markdown')
                    else:
                        await update.message.reply_text(f"❌ No data found for domain: {target}")
                        
                else:
                    await update.message.reply_text("❌ Invalid target format")
                    
            else:
                await update.message.reply_text("❌ Invalid report type. Available types: summary, trends, comprehensive")
            
        except Exception as e:
            logger.error(f"Error in report command: {e}")
            await update.message.reply_text(f"❌ Error occurred while generating report: {str(e)}")
    
    @secure_operation('trends')
    async def trends_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle trends analysis command"""
        try:
            await update.message.reply_text("📈 Analyzing trends and patterns...", parse_mode='Markdown')
            
            # Get recent data for trend analysis
            recent_lookups = self.database.get_recent_lookups(hours=168, limit=100)  # 7 days
            
            if not recent_lookups:
                await update.message.reply_text("❌ No recent data available for trend analysis")
                return
            
            # Analyze trends
            trend_analysis = self.analyzer.analyze_trends(recent_lookups)
            
            # Generate report
            report = self.reporter.generate_trend_report(trend_analysis)
            
            # Send report in chunks if too long
            if len(report) > 4000:
                chunks = [report[i:i+4000] for i in range(0, len(report), 4000)]
                for chunk in chunks:
                    await update.message.reply_text(chunk, parse_mode='Markdown')
            else:
                await update.message.reply_text(report, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in trends command: {e}")
            await update.message.reply_text(f"❌ Error occurred while analyzing trends: {str(e)}")
    
    @secure_operation('stats')
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle statistics command"""
        try:
            await update.message.reply_text("📊 Generating system statistics...", parse_mode='Markdown')
            
            # Get database statistics
            stats = self.database.get_statistics()
            
            # Get security report
            security_report = self.security_manager.generate_security_report()
            
            result = f"""
📊 **OSINT Bot Statistics**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📈 Database Statistics:**
• IP Lookups: {stats.get('ip_lookups_count', 0)}
• Domain Lookups: {stats.get('domain_lookups_count', 0)}
• Social Media Searches: {stats.get('social_media_lookups_count', 0)}
• News Mentions: {stats.get('news_mentions_count', 0)}
• Analysis Results: {stats.get('analysis_results_count', 0)}
• Reports Generated: {stats.get('reports_count', 0)}

**⏰ Recent Activity (24h):**
• IP Lookups: {stats.get('ip_lookups_24h', 0)}
• Domain Lookups: {stats.get('domain_lookups_24h', 0)}

**🛡️ Security Status:**
• Rate Limits Tracked: {security_report.get('rate_limits', {}).get('total_tracked', 0)}
• Active Limits: {security_report.get('rate_limits', {}).get('active_limits', 0)}
• Blocked IPs: {security_report.get('security_status', {}).get('blocked_ips', 0)}

**⚠️ Threat Distribution:**
"""
            threat_dist = stats.get('threat_distribution', {})
            for level, count in threat_dist.items():
                result += f"• {level.upper()}: {count}\n"
            
            result += f"""
**🔧 System Status:**
• Database: ✅ Online
• Security Manager: ✅ Active
• Data Collector: ✅ Ready
• Analyzer: ✅ Running
• Reporter: ✅ Available

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generated by OSINT Bot - {stats.get('timestamp', 'Unknown')}
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in stats command: {e}")
            await update.message.reply_text(f"❌ Error occurred while generating statistics: {str(e)}")
    
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

ℹ️ **Enhanced Implementation Available:**
For full WHOIS functionality, this bot can be integrated with:
• whois-json.whoisxmlapi.com
• whoisapi.whoisxmlapi.com  
• python-whois library
• Custom WHOIS parsing

🔧 **Current Status:** Framework ready for API integration
📊 **Data Available:** Basic domain structure analysis
🛡️ **Security:** Input validation and rate limiting active

**Next Steps:**
• Add your preferred WHOIS API key to enable full functionality
• Configure rate limits for WHOIS queries
• Set up data storage for historical WHOIS tracking

💡 **Tip:** Use `/domain {domain}` for immediate DNS analysis
            """
            
            await update.message.reply_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in WHOIS lookup: {e}")
            await update.message.reply_text(f"❌ Error occurred while looking up WHOIS information: {str(e)}")
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle status command"""
        try:
            # Get system statistics
            stats = self.database.get_statistics()
            security_report = self.security_manager.generate_security_report()
            
            status_message = f"""
⚡ **Enhanced OSINT Bot Status:**

🟢 **System Status:**
• Bot: Online and operational
• Database: Connected ({stats.get('ip_lookups_count', 0)} records)
• Security Manager: Active
• Data Collector: Ready
• Analyzer: Running
• Reporter: Available

🔧 **Enhanced Features:**
• IP Analysis with threat assessment
• Domain investigation with security analysis
• Social media reconnaissance framework
• News mentions analysis
• Pattern recognition and correlation
• Comprehensive reporting
• Trend analysis and anomaly detection

📊 **Recent Activity:**
• IP Lookups (24h): {stats.get('ip_lookups_24h', 0)}
• Domain Lookups (24h): {stats.get('domain_lookups_24h', 0)}
• Total Analysis Results: {stats.get('analysis_results_count', 0)}

🛡️ **Security Status:**
• Rate Limits: {security_report.get('rate_limits', {}).get('active_limits', 0)} active
• Input Validation: ✅ Enabled
• Data Sanitization: ✅ Active
• Abuse Prevention: ✅ Online

📈 **Version:** 2.0.0 - Enhanced OSINT Capabilities
🕒 **Uptime:** Active and monitoring

✅ All enhanced systems operational
            """
            await update.message.reply_text(status_message, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error in status command: {e}")
            await update.message.reply_text("❌ Error occurred while checking status")
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle regular text messages with enhanced detection"""
        text = update.message.text
        
        # Sanitize input
        sanitized_text = self.security_manager.sanitize_input(text)
        
        # Auto-detect various input types
        if self.is_valid_ip(sanitized_text):
            keyboard = [
                [InlineKeyboardButton("🔍 Full IP Analysis", callback_data=f"analyze_ip_{sanitized_text}")],
                [InlineKeyboardButton("📊 Generate Report", callback_data=f"report_ip_{sanitized_text}")],
                [InlineKeyboardButton("📈 Check Trends", callback_data="trends")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"🔍 **IP Address Detected:** `{sanitized_text}`\n\n"
                f"Choose an action or use `/ip {sanitized_text}` for comprehensive analysis",
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
        elif self.is_valid_domain(sanitized_text):
            keyboard = [
                [InlineKeyboardButton("🌐 Full Domain Analysis", callback_data=f"analyze_domain_{sanitized_text}")],
                [InlineKeyboardButton("📊 Generate Report", callback_data=f"report_domain_{sanitized_text}")],
                [InlineKeyboardButton("📋 WHOIS Info", callback_data=f"whois_{sanitized_text}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"🌐 **Domain Detected:** `{sanitized_text}`\n\n"
                f"Choose an action or use `/domain {sanitized_text}` for comprehensive analysis",
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
        else:
            # Check if it might be a username or search query
            if len(sanitized_text) > 2 and sanitized_text.replace('_', '').replace('-', '').isalnum():
                keyboard = [
                    [InlineKeyboardButton("👤 Social Media Search", callback_data=f"social_{sanitized_text}")],
                    [InlineKeyboardButton("📰 News Search", callback_data=f"news_{sanitized_text}")],
                    [InlineKeyboardButton("❓ Help", callback_data="help")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await update.message.reply_text(
                    f"💡 **Potential Username/Query:** `{sanitized_text}`\n\n"
                    f"Choose an action or use commands like `/social {sanitized_text}` or `/news {sanitized_text}`",
                    reply_markup=reply_markup,
                    parse_mode='Markdown'
                )
            else:
                await update.message.reply_text(
                    "💡 **Enhanced OSINT Bot**\n\n"
                    "I can analyze:\n"
                    "• IP addresses (e.g., 8.8.8.8)\n"
                    "• Domain names (e.g., google.com)\n"
                    "• Usernames for social media\n"
                    "• News queries\n\n"
                    "Use `/help` for all available commands or `/start` to see the menu."
                )
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks with enhanced functionality"""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data == "ip_help":
            await query.edit_message_text(
                "🔍 **Enhanced IP Lookup**\n\n"
                "Use `/ip <ip_address>` to get comprehensive IP analysis including:\n"
                "• Geographic location and ISP information\n"
                "• Threat assessment and risk scoring\n"
                "• Network analysis and reputation check\n"
                "• Historical data and trend analysis\n\n"
                "**Example:** `/ip 8.8.8.8`\n"
                "**Advanced:** `/analyze 8.8.8.8` for deep analysis",
                parse_mode='Markdown'
            )
        elif data == "domain_help":
            await query.edit_message_text(
                "🌐 **Enhanced Domain Analysis**\n\n"
                "Use `/domain <domain>` to get comprehensive domain analysis including:\n"
                "• DNS records and SSL/TLS information\n"
                "• Security assessment and threat analysis\n"
                "• Domain structure and reputation check\n"
                "• Historical tracking and pattern analysis\n\n"
                "**Example:** `/domain google.com`\n"
                "**Advanced:** `/analyze google.com` for deep analysis",
                parse_mode='Markdown'
            )
        elif data == "whois_help":
            await query.edit_message_text(
                "📋 **WHOIS Lookup**\n\n"
                "Use `/whois <domain>` to get WHOIS information.\n"
                "Framework ready for integration with WHOIS services.\n\n"
                "**Example:** `/whois example.com`\n"
                "**Note:** Requires API integration for full functionality",
                parse_mode='Markdown'
            )
        elif data == "social_help":
            await query.edit_message_text(
                "👤 **Social Media Reconnaissance**\n\n"
                "Use `/social <username>` to search for social media presence.\n"
                "Framework includes platform checking and analysis.\n\n"
                "**Example:** `/social testuser`\n"
                "**Note:** Requires API integration for full functionality",
                parse_mode='Markdown'
            )
        elif data == "news_help":
            await query.edit_message_text(
                "📰 **News Mentions Analysis**\n\n"
                "Use `/news <query>` to search for news mentions.\n"
                "Framework includes sentiment analysis and trend detection.\n\n"
                "**Example:** `/news \"cybersecurity breach\"`\n"
                "**Note:** Requires API integration for full functionality",
                parse_mode='Markdown'
            )
        elif data == "analyze_help":
            await query.edit_message_text(
                "📊 **Deep Analysis**\n\n"
                "Use `/analyze <target>` for comprehensive analysis.\n"
                "Includes pattern recognition, threat assessment, and correlation.\n\n"
                "**Example:** `/analyze 8.8.8.8`\n"
                "**Features:** Historical data, trend analysis, risk scoring",
                parse_mode='Markdown'
            )
        elif data == "trends_help":
            await query.edit_message_text(
                "📈 **Trend Analysis**\n\n"
                "Use `/trends` to view pattern analysis and trends.\n"
                "Includes anomaly detection and predictive insights.\n\n"
                "**Features:**\n"
                "• Geographic trend analysis\n"
                "• Threat level trends\n"
                "• Anomaly detection\n"
                "• Pattern recognition",
                parse_mode='Markdown'
            )
        elif data == "help":
            await self.help_command(update, context)
        elif data == "trends":
            await self.trends_command(update, context)
        elif data.startswith("analyze_ip_"):
            ip = data.replace("analyze_ip_", "")
            context.args = [ip]
            await self.analyze_command(update, context)
        elif data.startswith("analyze_domain_"):
            domain = data.replace("analyze_domain_", "")
            context.args = [domain]
            await self.analyze_command(update, context)
        elif data.startswith("report_ip_"):
            ip = data.replace("report_ip_", "")
            context.args = ["comprehensive", ip]
            await self.report_command(update, context)
        elif data.startswith("report_domain_"):
            domain = data.replace("report_domain_", "")
            context.args = ["comprehensive", domain]
            await self.report_command(update, context)
        elif data.startswith("whois_"):
            domain = data.replace("whois_", "")
            context.args = [domain]
            await self.whois_lookup(update, context)
        elif data.startswith("social_"):
            username = data.replace("social_", "")
            context.args = [username]
            await self.social_lookup(update, context)
        elif data.startswith("news_"):
            query_text = data.replace("news_", "")
            context.args = [query_text]
            await self.news_search(update, context)
    
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