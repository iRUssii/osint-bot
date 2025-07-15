"""
Data Collection Module for OSINT Bot
Handles gathering information from various public sources
"""

import asyncio
import logging
import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import time

logger = logging.getLogger(__name__)

class OSINTDataCollector:
    """Enhanced data collection for OSINT operations"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.rate_limit_delay = 1  # seconds between requests
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Simple rate limiting to prevent abuse"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()
    
    def collect_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """Enhanced IP information collection"""
        self._rate_limit()
        
        try:
            # Primary source: ipapi.co
            response = self.session.get(f"https://ipapi.co/{ip_address}/json/", timeout=10)
            data = response.json()
            
            if 'error' in data:
                return {'error': data['reason']}
            
            # Additional security information
            result = {
                'ip': ip_address,
                'country': data.get('country_name', 'Unknown'),
                'country_code': data.get('country_code', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'isp': data.get('org', 'Unknown'),
                'asn': data.get('asn', 'Unknown'),
                'latitude': data.get('latitude', 'Unknown'),
                'longitude': data.get('longitude', 'Unknown'),
                'is_eu': data.get('in_eu', False),
                'postal': data.get('postal', 'Unknown'),
                'threat_level': self._assess_threat_level(data),
                'collection_time': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error collecting IP info: {e}")
            return {'error': f"Failed to collect IP information: {str(e)}"}
    
    def collect_domain_info(self, domain: str) -> Dict[str, Any]:
        """Enhanced domain information collection"""
        self._rate_limit()
        
        try:
            import socket
            import dns.resolver
            
            result = {
                'domain': domain,
                'collection_time': datetime.now().isoformat()
            }
            
            # Basic DNS resolution
            try:
                ip_address = socket.gethostbyname(domain)
                result['ip_address'] = ip_address
                result['status'] = 'active'
                
                # Get additional DNS records
                dns_info = self._get_dns_records(domain)
                result.update(dns_info)
                
            except socket.gaierror:
                result['status'] = 'inactive'
                result['error'] = 'Domain does not resolve'
            
            # SSL/TLS information
            ssl_info = self._get_ssl_info(domain)
            result.update(ssl_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error collecting domain info: {e}")
            return {'error': f"Failed to collect domain information: {str(e)}"}
    
    def collect_social_media_info(self, username: str) -> Dict[str, Any]:
        """Collect publicly available social media information"""
        self._rate_limit()
        
        try:
            # This is a basic implementation - in production, you'd use official APIs
            # For educational purposes, we'll provide a framework
            
            result = {
                'username': username,
                'collection_time': datetime.now().isoformat(),
                'platforms': {}
            }
            
            # Common platforms to check (placeholder implementation)
            platforms = ['twitter', 'github', 'linkedin', 'instagram']
            
            for platform in platforms:
                result['platforms'][platform] = {
                    'exists': False,
                    'public_info': None,
                    'note': 'This is a placeholder implementation'
                }
            
            result['warning'] = 'Social media collection requires proper API access and compliance with platform terms'
            
            return result
            
        except Exception as e:
            logger.error(f"Error collecting social media info: {e}")
            return {'error': f"Failed to collect social media information: {str(e)}"}
    
    def collect_news_mentions(self, query: str, days_back: int = 7) -> Dict[str, Any]:
        """Collect news mentions from public sources"""
        self._rate_limit()
        
        try:
            # This would integrate with news APIs like NewsAPI, Google News, etc.
            # For now, providing a framework
            
            result = {
                'query': query,
                'search_period': f"{days_back} days",
                'collection_time': datetime.now().isoformat(),
                'articles': [],
                'summary': {
                    'total_mentions': 0,
                    'sentiment': 'neutral',
                    'trending': False
                }
            }
            
            # Placeholder implementation
            result['note'] = 'News collection requires API keys for services like NewsAPI, Google News, etc.'
            result['implementation_status'] = 'Framework ready for API integration'
            
            return result
            
        except Exception as e:
            logger.error(f"Error collecting news mentions: {e}")
            return {'error': f"Failed to collect news mentions: {str(e)}"}
    
    def collect_public_records(self, identifier: str) -> Dict[str, Any]:
        """Collect information from public records databases"""
        self._rate_limit()
        
        try:
            # This would integrate with public records APIs
            # For educational purposes, providing a framework
            
            result = {
                'identifier': identifier,
                'collection_time': datetime.now().isoformat(),
                'records': [],
                'sources': []
            }
            
            # Placeholder implementation
            result['note'] = 'Public records collection requires integration with legitimate databases'
            result['legal_notice'] = 'Always comply with local laws and regulations'
            result['implementation_status'] = 'Framework ready for API integration'
            
            return result
            
        except Exception as e:
            logger.error(f"Error collecting public records: {e}")
            return {'error': f"Failed to collect public records: {str(e)}"}
    
    def _assess_threat_level(self, ip_data: Dict[str, Any]) -> str:
        """Assess basic threat level based on IP information"""
        # Simple threat assessment - in production, integrate with threat intelligence
        country = ip_data.get('country_code', '').upper()
        
        # This is a very basic example - real threat assessment would be more sophisticated
        high_risk_countries = ['CN', 'RU', 'IR', 'KP']  # Example only
        
        if country in high_risk_countries:
            return 'medium'
        else:
            return 'low'
    
    def _get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for a domain"""
        try:
            import dns.resolver
            
            dns_info = {
                'mx_records': [],
                'ns_records': [],
                'txt_records': []
            }
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    dns_info['mx_records'].append(str(mx))
            except:
                pass
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    dns_info['ns_records'].append(str(ns))
            except:
                pass
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for txt in txt_records:
                    dns_info['txt_records'].append(str(txt))
            except:
                pass
            
            return dns_info
            
        except Exception as e:
            logger.error(f"Error getting DNS records: {e}")
            return {'dns_error': str(e)}
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'ssl_enabled': True,
                        'ssl_issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'ssl_subject': dict(x[0] for x in cert.get('subject', [])),
                        'ssl_version': ssock.version(),
                        'ssl_expires': cert.get('notAfter', 'Unknown')
                    }
                    
                    return ssl_info
                    
        except Exception as e:
            logger.error(f"Error getting SSL info: {e}")
            return {'ssl_enabled': False, 'ssl_error': str(e)}
    
    def get_threat_intelligence(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Get threat intelligence information"""
        try:
            # This would integrate with threat intelligence APIs
            # For now, providing a framework
            
            result = {
                'indicator': indicator,
                'indicator_type': indicator_type,
                'collection_time': datetime.now().isoformat(),
                'threat_score': 0,
                'malicious': False,
                'sources': []
            }
            
            # Placeholder implementation
            result['note'] = 'Threat intelligence requires API integration with services like VirusTotal, OTX, etc.'
            result['implementation_status'] = 'Framework ready for API integration'
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence: {e}")
            return {'error': f"Failed to get threat intelligence: {str(e)}"}