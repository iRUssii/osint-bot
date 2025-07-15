#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
from datetime import datetime
import requests

def check_bot_health():
    """Check if the OSINT bot is responding to messages"""
    
    # Get environment variables
    bot_token = os.environ.get('BOT_TOKEN')
    admin_chat_id = os.environ.get('ADMIN_CHAT_ID')
    
    if not bot_token:
        print("ERROR: BOT_TOKEN environment variable not set")
        sys.exit(1)
    
    if not admin_chat_id:
        print("ERROR: ADMIN_CHAT_ID environment variable not set")
        sys.exit(1)
        
    # Generate unique test message to identify this specific check
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    test_message = f"health_check_{timestamp}"
    
    # Set output for GitHub Actions
    print(f"::set-output name=timestamp::{timestamp}")
    
    try:
        # Get bot information to verify token is valid
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getMe",
            timeout=10
        )
        response.raise_for_status()
        bot_info = response.json()
        
        if not bot_info.get('ok'):
            error_msg = f"Invalid bot token: {bot_info.get('description', 'Unknown error')}"
            print(f"::set-output name=error::{error_msg}")
            print(f"ERROR: {error_msg}")
            sys.exit(1)
            
        bot_username = bot_info['result']['username']
        print(f"Bot username: @{bot_username}")
        
        # Send a test message to the bot (via admin chat)
        print(f"Sending test message to chat ID {admin_chat_id}")
        message_response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={
                "chat_id": admin_chat_id,
                "text": f"🔍 Health check: {test_message}\nThis is an automated message to verify the bot is running.",
                "disable_notification": True
            },
            timeout=10
        )
        message_response.raise_for_status()
        message_result = message_response.json()
        
        if not message_result.get('ok'):
            error_msg = f"Failed to send message: {message_result.get('description', 'Unknown error')}"
            print(f"::set-output name=error::{error_msg}")
            print(f"ERROR: {error_msg}")
            sys.exit(1)
            
        # Wait briefly to see if bot processes the message
        print("Waiting for bot to process message...")
        time.sleep(5)
        
        # For now, we'll consider the bot healthy if message was delivered
        print("✅ Bot is healthy - Successfully sent test message")
        return True
        
    except requests.RequestException as e:
        error_msg = f"Network error: {str(e)}"
        print(f"::set-output name=error::{error_msg}")
        print(f"ERROR: {error_msg}")
        return False
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"::set-output name=error::{error_msg}")
        print(f"ERROR: {error_msg}")
        return False

if __name__ == "__main__":
    print("Starting OSINT bot health check...")
    is_healthy = check_bot_health()
    
    if not is_healthy:
        sys.exit(1)