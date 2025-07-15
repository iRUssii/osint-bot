#!/usr/bin/env python3
"""
OSINT Bot Health Check Script
Quick diagnostic tool to help users verify bot functionality before reporting issues.
"""

import sys
import os
import json
import time
from datetime import datetime

def print_header():
    print("🔍 OSINT Bot Health Check")
    print("=" * 50)
    print()

def check_environment():
    """Check if required environment variables are set"""
    print("📋 Checking Environment Variables...")
    
    required_vars = ['TELEGRAM_BOT_TOKEN']
    optional_vars = ['CHAT_ID', 'WHOIS_API_KEY']
    
    env_status = {}
    
    for var in required_vars:
        if os.getenv(var):
            print(f"✅ {var}: Set")
            env_status[var] = True
        else:
            print(f"❌ {var}: Not set (REQUIRED)")
            env_status[var] = False
    
    for var in optional_vars:
        if os.getenv(var):
            print(f"✅ {var}: Set")
            env_status[var] = True
        else:
            print(f"⚠️  {var}: Not set (optional)")
            env_status[var] = False
    
    print()
    return env_status

def check_dependencies():
    """Check if required Python packages are installed"""
    print("📦 Checking Dependencies...")
    
    required_packages = [
        'telebot',
        'requests',
        'sqlite3'
    ]
    
    dependency_status = {}
    
    for package in required_packages:
        try:
            if package == 'telebot':
                import telebot
                print(f"✅ {package}: Installed")
                dependency_status[package] = True
            elif package == 'requests':
                import requests
                print(f"✅ {package}: Installed")
                dependency_status[package] = True
            elif package == 'sqlite3':
                import sqlite3
                print(f"✅ {package}: Available")
                dependency_status[package] = True
        except ImportError:
            print(f"❌ {package}: Not installed")
            dependency_status[package] = False
    
    print()
    return dependency_status

def check_database():
    """Check if database can be created and accessed"""
    print("🗄️  Checking Database...")
    
    try:
        import sqlite3
        from pathlib import Path
        
        # Try to create a test database
        test_db_path = Path("./data/health_check.db")
        test_db_path.parent.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(str(test_db_path))
        cursor = conn.cursor()
        
        # Test table creation
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS health_check (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Test data insertion
        cursor.execute("INSERT INTO health_check (id) VALUES (1)")
        
        # Test data retrieval
        cursor.execute("SELECT * FROM health_check")
        result = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
        # Clean up
        if test_db_path.exists():
            test_db_path.unlink()
        
        print("✅ Database: Working")
        return True
        
    except Exception as e:
        print(f"❌ Database: Error - {e}")
        return False

def check_network():
    """Check if network requests are working"""
    print("🌐 Checking Network Connectivity...")
    
    try:
        import requests
        
        # Test basic connectivity
        response = requests.get("https://httpbin.org/ip", timeout=5)
        if response.status_code == 200:
            print("✅ Basic connectivity: Working")
        else:
            print(f"⚠️  Basic connectivity: HTTP {response.status_code}")
            
        # Test OSINT APIs
        apis_to_test = [
            ("ipapi.co", "https://ipapi.co/8.8.8.8/json/"),
            ("httpbin.org", "https://httpbin.org/headers")
        ]
        
        for name, url in apis_to_test:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"✅ {name}: Accessible")
                else:
                    print(f"⚠️  {name}: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ {name}: Error - {e}")
        
        print()
        return True
        
    except Exception as e:
        print(f"❌ Network: Error - {e}")
        print()
        return False

def check_bot_token():
    """Check if bot token is valid"""
    print("🤖 Checking Bot Token...")
    
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        print("❌ Bot token not set")
        return False
    
    try:
        import telebot
        bot = telebot.TeleBot(token)
        bot_info = bot.get_me()
        print(f"✅ Bot token: Valid (@{bot_info.username})")
        return True
    except Exception as e:
        print(f"❌ Bot token: Invalid - {e}")
        return False

def generate_report(results):
    """Generate a health check report"""
    print("📊 Health Check Report")
    print("=" * 50)
    
    total_checks = len(results)
    passed_checks = sum(1 for result in results.values() if result)
    
    print(f"Overall Status: {passed_checks}/{total_checks} checks passed")
    print()
    
    if passed_checks == total_checks:
        print("🎉 All checks passed! Your bot should be working correctly.")
        print("   If you're still experiencing issues, please include this report")
        print("   when creating a GitHub issue.")
    else:
        print("⚠️  Some checks failed. Please address these issues before")
        print("   reporting bugs:")
        print()
        
        for check, status in results.items():
            status_icon = "✅" if status else "❌"
            print(f"   {status_icon} {check}")
    
    print()
    print("For help with setup, visit:")
    print("https://github.com/iRUssii/osint-bot/blob/main/README.md")

def main():
    print_header()
    
    # Run all checks
    results = {}
    
    env_status = check_environment()
    results['Environment'] = all(env_status.values())
    
    dep_status = check_dependencies()
    results['Dependencies'] = all(dep_status.values())
    
    results['Database'] = check_database()
    results['Network'] = check_network()
    
    if os.getenv('TELEGRAM_BOT_TOKEN'):
        results['Bot Token'] = check_bot_token()
    
    # Generate report
    generate_report(results)
    
    # Exit with appropriate code
    if all(results.values()):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()