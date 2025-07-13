"""
Security Module for OSINT Bot
Handles authentication, rate limiting, and security measures
"""

import logging
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Callable
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict, deque
import re

logger = logging.getLogger(__name__)

class SecurityManager:
    """Manages security aspects of the OSINT bot"""
    
    def __init__(self):
        self.rate_limits = defaultdict(deque)
        self.blocked_ips = set()
        self.api_keys = {}
        self.session_tokens = {}
        self.failed_attempts = defaultdict(int)
        self.security_config = self._load_security_config()
    
    def _load_security_config(self) -> Dict[str, Any]:
        """Load security configuration"""
        return {
            'rate_limits': {
                'ip_lookup': {'requests': 10, 'window': 60},  # 10 requests per minute
                'domain_lookup': {'requests': 15, 'window': 60},
                'whois_lookup': {'requests': 5, 'window': 60},
                'social_media': {'requests': 3, 'window': 300},  # 3 requests per 5 minutes
                'news_search': {'requests': 20, 'window': 300},
                'default': {'requests': 5, 'window': 60}
            },
            'blocked_patterns': [
                r'\.\./',  # Directory traversal
                r'<script',  # XSS attempts
                r'union\s+select',  # SQL injection
                r'exec\s*\(',  # Code execution
                r'eval\s*\(',  # Code evaluation
            ],
            'max_failed_attempts': 5,
            'lockout_duration': 300,  # 5 minutes
            'min_query_length': 3,
            'max_query_length': 100,
            'allowed_domains': [
                'ipapi.co',
                'news.google.com',
                'api.github.com',
                'whois.whoisxmlapi.com'
            ]
        }
    
    def rate_limit(self, operation: str, identifier: str) -> bool:
        """Check if operation is within rate limits"""
        try:
            now = time.time()
            config = self.security_config['rate_limits'].get(operation, 
                                                           self.security_config['rate_limits']['default'])
            
            window = config['window']
            max_requests = config['requests']
            
            # Clean old entries
            while (self.rate_limits[f"{operation}:{identifier}"] and 
                   self.rate_limits[f"{operation}:{identifier}"][0] < now - window):
                self.rate_limits[f"{operation}:{identifier}"].popleft()
            
            # Check if within limits
            if len(self.rate_limits[f"{operation}:{identifier}"]) >= max_requests:
                logger.warning(f"Rate limit exceeded for {operation} by {identifier}")
                return False
            
            # Add current request
            self.rate_limits[f"{operation}:{identifier}"].append(now)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return False
    
    def validate_input(self, input_data: str, input_type: str) -> bool:
        """Validate input data for security"""
        try:
            # Check length
            if len(input_data) < self.security_config['min_query_length']:
                logger.warning(f"Input too short: {len(input_data)} characters")
                return False
            
            if len(input_data) > self.security_config['max_query_length']:
                logger.warning(f"Input too long: {len(input_data)} characters")
                return False
            
            # Check for malicious patterns
            for pattern in self.security_config['blocked_patterns']:
                if re.search(pattern, input_data, re.IGNORECASE):
                    logger.warning(f"Blocked pattern detected: {pattern}")
                    return False
            
            # Type-specific validation
            if input_type == 'ip':
                return self._validate_ip(input_data)
            elif input_type == 'domain':
                return self._validate_domain(input_data)
            elif input_type == 'username':
                return self._validate_username(input_data)
            elif input_type == 'query':
                return self._validate_query(input_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating input: {e}")
            return False
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            
            # Check if it's a private IP
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                logger.info(f"Private IP address detected: {ip}")
                # Allow private IPs but log them
            
            return True
            
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name"""
        try:
            # Basic domain validation
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            )
            
            if not domain_pattern.match(domain):
                logger.warning(f"Invalid domain format: {domain}")
                return False
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    logger.info(f"Domain with suspicious TLD: {domain}")
                    # Allow but log suspicious TLDs
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating domain: {e}")
            return False
    
    def _validate_username(self, username: str) -> bool:
        """Validate username"""
        try:
            # Basic username validation
            username_pattern = re.compile(r'^[a-zA-Z0-9_.-]+$')
            
            if not username_pattern.match(username):
                logger.warning(f"Invalid username format: {username}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating username: {e}")
            return False
    
    def _validate_query(self, query: str) -> bool:
        """Validate search query"""
        try:
            # Remove potentially dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '&', '|', ';', '`']
            for char in dangerous_chars:
                if char in query:
                    logger.warning(f"Dangerous character detected in query: {char}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating query: {e}")
            return False
    
    def sanitize_input(self, input_data: str) -> str:
        """Sanitize input data"""
        try:
            # Remove control characters
            sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_data)
            
            # Remove excessive whitespace
            sanitized = re.sub(r'\s+', ' ', sanitized).strip()
            
            # Escape special characters for logging
            sanitized = sanitized.replace('\\', '\\\\').replace('"', '\\"')
            
            return sanitized
            
        except Exception as e:
            logger.error(f"Error sanitizing input: {e}")
            return input_data
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security-related events"""
        try:
            timestamp = datetime.now().isoformat()
            event_id = secrets.token_hex(8)
            
            log_entry = {
                'event_id': event_id,
                'timestamp': timestamp,
                'event_type': event_type,
                'details': details
            }
            
            logger.warning(f"Security Event: {event_type} - {details}")
            
            # In production, you might want to send this to a SIEM system
            # or security monitoring platform
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation (basic implementation)"""
        try:
            import ipaddress
            
            reputation = {
                'ip': ip,
                'reputation': 'unknown',
                'risk_level': 'low',
                'findings': []
            }
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IPs
            if ip_obj.is_private:
                reputation['reputation'] = 'private'
                reputation['findings'].append('Private IP address')
            
            # Check for loopback
            if ip_obj.is_loopback:
                reputation['reputation'] = 'loopback'
                reputation['findings'].append('Loopback address')
            
            # Check for multicast
            if ip_obj.is_multicast:
                reputation['reputation'] = 'multicast'
                reputation['findings'].append('Multicast address')
            
            # Check against known bad IP ranges (basic example)
            # In production, integrate with threat intelligence feeds
            
            return reputation
            
        except Exception as e:
            logger.error(f"Error checking IP reputation: {e}")
            return {'error': str(e)}
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate security status report"""
        try:
            now = time.time()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'rate_limits': {
                    'total_tracked': len(self.rate_limits),
                    'active_limits': sum(1 for deque_obj in self.rate_limits.values() 
                                      if deque_obj and deque_obj[-1] > now - 3600)  # Active in last hour
                },
                'security_status': {
                    'blocked_ips': len(self.blocked_ips),
                    'failed_attempts': len(self.failed_attempts),
                    'active_sessions': len(self.session_tokens)
                },
                'recent_events': self._get_recent_security_events()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return {'error': str(e)}
    
    def _get_recent_security_events(self) -> List[Dict[str, Any]]:
        """Get recent security events"""
        # In a real implementation, this would query a security event database
        return [
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'rate_limit_exceeded',
                'count': 3
            },
            {
                'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(),
                'event_type': 'suspicious_input',
                'count': 1
            }
        ]
    
    def authenticate_user(self, user_id: str, chat_id: str) -> bool:
        """Authenticate user (basic implementation)"""
        try:
            # In production, implement proper authentication
            # For now, just check if user_id matches chat_id
            return True  # Allow all users for basic implementation
            
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return False
    
    def authorize_operation(self, user_id: str, operation: str) -> bool:
        """Authorize user for specific operation"""
        try:
            # Basic authorization - in production, implement role-based access
            authorized_operations = {
                'ip_lookup': True,
                'domain_lookup': True,
                'whois_lookup': True,
                'social_media': True,
                'news_search': True,
                'admin_functions': False  # Restrict admin functions
            }
            
            return authorized_operations.get(operation, False)
            
        except Exception as e:
            logger.error(f"Error authorizing operation: {e}")
            return False
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            # Simple base64 encoding for demo - use proper encryption in production
            import base64
            encoded = base64.b64encode(data.encode()).decode()
            return encoded
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return data
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            # Simple base64 decoding for demo
            import base64
            decoded = base64.b64decode(encrypted_data.encode()).decode()
            return decoded
            
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return encrypted_data
    
    def create_secure_session(self, user_id: str) -> str:
        """Create secure session token"""
        try:
            session_token = secrets.token_urlsafe(32)
            
            self.session_tokens[session_token] = {
                'user_id': user_id,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=24)
            }
            
            return session_token
            
        except Exception as e:
            logger.error(f"Error creating secure session: {e}")
            return None
    
    def validate_session(self, session_token: str) -> bool:
        """Validate session token"""
        try:
            if session_token not in self.session_tokens:
                return False
            
            session_data = self.session_tokens[session_token]
            
            # Check if session is expired
            if datetime.now() > session_data['expires_at']:
                del self.session_tokens[session_token]
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return False

def secure_operation(operation_type: str):
    """Decorator for securing operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, update, context, *args, **kwargs):
            try:
                # Get user identifier
                user_id = str(update.effective_user.id)
                
                # Check rate limits
                if hasattr(self, 'security_manager'):
                    if not self.security_manager.rate_limit(operation_type, user_id):
                        await update.message.reply_text(
                            "⚠️ Rate limit exceeded. Please wait before making another request."
                        )
                        return
                
                # Validate input if arguments are provided
                if context.args and hasattr(self, 'security_manager'):
                    for arg in context.args:
                        if not self.security_manager.validate_input(arg, 'query'):
                            await update.message.reply_text(
                                "❌ Invalid input detected. Please check your query."
                            )
                            return
                
                # Log the operation
                logger.info(f"User {user_id} performing {operation_type}")
                
                # Execute the original function
                return await func(self, update, context, *args, **kwargs)
                
            except Exception as e:
                logger.error(f"Error in secure operation {operation_type}: {e}")
                await update.message.reply_text(
                    "❌ An error occurred while processing your request."
                )
        
        return wrapper
    return decorator