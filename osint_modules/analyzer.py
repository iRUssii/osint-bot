"""
Data Analysis Module for OSINT Bot
Analyzes collected data for patterns, trends, and insights
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import statistics

logger = logging.getLogger(__name__)

class OSINTAnalyzer:
    """Analyzes OSINT data for patterns and insights"""
    
    def __init__(self):
        self.analysis_cache = {}
        self.pattern_rules = self._load_pattern_rules()
    
    def _load_pattern_rules(self) -> Dict[str, Any]:
        """Load pattern recognition rules"""
        return {
            'suspicious_patterns': {
                'tor_exit_nodes': r'\.onion$',
                'suspicious_tlds': r'\.(tk|ml|ga|cf|top|click|download)$',
                'ip_patterns': {
                    'private_ranges': ['10.', '192.168.', '172.16.', '127.'],
                    'cloud_providers': ['aws', 'azure', 'google', 'digitalocean']
                }
            },
            'geolocation_risks': {
                'high_risk_countries': ['CN', 'RU', 'IR', 'KP'],
                'medium_risk_countries': ['BY', 'SY', 'AF']
            }
        }
    
    def analyze_ip_data(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IP address data for patterns and threats"""
        try:
            analysis = {
                'ip_address': ip_data.get('ip', 'Unknown'),
                'analysis_time': datetime.now().isoformat(),
                'risk_score': 0,
                'findings': [],
                'recommendations': []
            }
            
            # Geographic analysis
            geo_analysis = self._analyze_geography(ip_data)
            analysis['geographic_analysis'] = geo_analysis
            analysis['risk_score'] += geo_analysis.get('risk_score', 0)
            
            # ISP/Organization analysis
            isp_analysis = self._analyze_isp(ip_data)
            analysis['isp_analysis'] = isp_analysis
            analysis['risk_score'] += isp_analysis.get('risk_score', 0)
            
            # Network analysis
            network_analysis = self._analyze_network(ip_data)
            analysis['network_analysis'] = network_analysis
            analysis['risk_score'] += network_analysis.get('risk_score', 0)
            
            # Overall risk assessment
            analysis['risk_level'] = self._calculate_risk_level(analysis['risk_score'])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing IP data: {e}")
            return {'error': f"Failed to analyze IP data: {str(e)}"}
    
    def analyze_domain_data(self, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze domain data for suspicious patterns"""
        try:
            analysis = {
                'domain': domain_data.get('domain', 'Unknown'),
                'analysis_time': datetime.now().isoformat(),
                'risk_score': 0,
                'findings': [],
                'recommendations': []
            }
            
            # Domain structure analysis
            domain_analysis = self._analyze_domain_structure(domain_data)
            analysis['domain_structure'] = domain_analysis
            analysis['risk_score'] += domain_analysis.get('risk_score', 0)
            
            # DNS analysis
            dns_analysis = self._analyze_dns_records(domain_data)
            analysis['dns_analysis'] = dns_analysis
            analysis['risk_score'] += dns_analysis.get('risk_score', 0)
            
            # SSL/TLS analysis
            ssl_analysis = self._analyze_ssl_configuration(domain_data)
            analysis['ssl_analysis'] = ssl_analysis
            analysis['risk_score'] += ssl_analysis.get('risk_score', 0)
            
            # Overall risk assessment
            analysis['risk_level'] = self._calculate_risk_level(analysis['risk_score'])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing domain data: {e}")
            return {'error': f"Failed to analyze domain data: {str(e)}"}
    
    def analyze_social_media_data(self, social_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze social media data for patterns"""
        try:
            analysis = {
                'username': social_data.get('username', 'Unknown'),
                'analysis_time': datetime.now().isoformat(),
                'findings': [],
                'platforms_analysis': {}
            }
            
            # Platform presence analysis
            platforms = social_data.get('platforms', {})
            for platform, data in platforms.items():
                platform_analysis = self._analyze_platform_presence(platform, data)
                analysis['platforms_analysis'][platform] = platform_analysis
            
            # Cross-platform correlation
            correlation = self._analyze_cross_platform_correlation(platforms)
            analysis['cross_platform_correlation'] = correlation
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing social media data: {e}")
            return {'error': f"Failed to analyze social media data: {str(e)}"}
    
    def analyze_trends(self, data_points: List[Dict[str, Any]], time_window: str = '7d') -> Dict[str, Any]:
        """Analyze trends in collected data"""
        try:
            analysis = {
                'time_window': time_window,
                'analysis_time': datetime.now().isoformat(),
                'trends': {},
                'anomalies': [],
                'insights': []
            }
            
            # Geographic trends
            geo_trends = self._analyze_geographic_trends(data_points)
            analysis['trends']['geographic'] = geo_trends
            
            # Temporal trends
            temporal_trends = self._analyze_temporal_trends(data_points)
            analysis['trends']['temporal'] = temporal_trends
            
            # Threat trends
            threat_trends = self._analyze_threat_trends(data_points)
            analysis['trends']['threat'] = threat_trends
            
            # Anomaly detection
            anomalies = self._detect_anomalies(data_points)
            analysis['anomalies'] = anomalies
            
            # Generate insights
            insights = self._generate_insights(analysis)
            analysis['insights'] = insights
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")
            return {'error': f"Failed to analyze trends: {str(e)}"}
    
    def correlate_data(self, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate data from multiple sources"""
        try:
            correlation = {
                'analysis_time': datetime.now().isoformat(),
                'datasets_analyzed': len(datasets),
                'correlations': {},
                'patterns': [],
                'confidence_score': 0
            }
            
            # IP-Domain correlations
            ip_domain_corr = self._correlate_ip_domain(datasets)
            correlation['correlations']['ip_domain'] = ip_domain_corr
            
            # Temporal correlations
            temporal_corr = self._correlate_temporal_patterns(datasets)
            correlation['correlations']['temporal'] = temporal_corr
            
            # Geographic correlations
            geo_corr = self._correlate_geographic_patterns(datasets)
            correlation['correlations']['geographic'] = geo_corr
            
            # Calculate overall confidence
            correlation['confidence_score'] = self._calculate_confidence_score(correlation)
            
            return correlation
            
        except Exception as e:
            logger.error(f"Error correlating data: {e}")
            return {'error': f"Failed to correlate data: {str(e)}"}
    
    def _analyze_geography(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic information"""
        geo_analysis = {
            'country_risk': 'low',
            'region_analysis': {},
            'risk_score': 0,
            'findings': []
        }
        
        country_code = ip_data.get('country_code', '').upper()
        
        # Check against risk lists
        if country_code in self.pattern_rules['geolocation_risks']['high_risk_countries']:
            geo_analysis['country_risk'] = 'high'
            geo_analysis['risk_score'] += 30
            geo_analysis['findings'].append(f"IP from high-risk country: {country_code}")
        elif country_code in self.pattern_rules['geolocation_risks']['medium_risk_countries']:
            geo_analysis['country_risk'] = 'medium'
            geo_analysis['risk_score'] += 15
            geo_analysis['findings'].append(f"IP from medium-risk country: {country_code}")
        
        return geo_analysis
    
    def _analyze_isp(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze ISP/Organization information"""
        isp_analysis = {
            'isp_type': 'unknown',
            'risk_score': 0,
            'findings': []
        }
        
        isp = ip_data.get('isp', '').lower()
        
        # Check for cloud providers
        for provider in self.pattern_rules['suspicious_patterns']['ip_patterns']['cloud_providers']:
            if provider in isp:
                isp_analysis['isp_type'] = 'cloud_provider'
                isp_analysis['findings'].append(f"IP hosted by cloud provider: {provider}")
                break
        
        # Check for hosting providers
        hosting_keywords = ['hosting', 'server', 'datacenter', 'cloud']
        for keyword in hosting_keywords:
            if keyword in isp:
                isp_analysis['isp_type'] = 'hosting'
                isp_analysis['findings'].append(f"IP appears to be from hosting provider")
                break
        
        return isp_analysis
    
    def _analyze_network(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network-related information"""
        network_analysis = {
            'network_type': 'public',
            'risk_score': 0,
            'findings': []
        }
        
        ip = ip_data.get('ip', '')
        
        # Check for private IP ranges
        for private_range in self.pattern_rules['suspicious_patterns']['ip_patterns']['private_ranges']:
            if ip.startswith(private_range):
                network_analysis['network_type'] = 'private'
                network_analysis['findings'].append(f"Private IP address detected: {ip}")
                break
        
        return network_analysis
    
    def _analyze_domain_structure(self, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze domain structure for suspicious patterns"""
        domain_analysis = {
            'domain_age': 'unknown',
            'suspicious_tld': False,
            'risk_score': 0,
            'findings': []
        }
        
        domain = domain_data.get('domain', '')
        
        # Check for suspicious TLDs
        for pattern in [r'\.(tk|ml|ga|cf|top|click|download)$']:
            if re.search(pattern, domain):
                domain_analysis['suspicious_tld'] = True
                domain_analysis['risk_score'] += 20
                domain_analysis['findings'].append(f"Domain uses suspicious TLD")
                break
        
        # Check domain length and complexity
        if len(domain) > 50:
            domain_analysis['risk_score'] += 10
            domain_analysis['findings'].append("Unusually long domain name")
        
        return domain_analysis
    
    def _analyze_dns_records(self, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS records for suspicious patterns"""
        dns_analysis = {
            'mx_records_count': 0,
            'ns_records_count': 0,
            'txt_records_count': 0,
            'risk_score': 0,
            'findings': []
        }
        
        # Count DNS records
        mx_records = domain_data.get('mx_records', [])
        ns_records = domain_data.get('ns_records', [])
        txt_records = domain_data.get('txt_records', [])
        
        dns_analysis['mx_records_count'] = len(mx_records)
        dns_analysis['ns_records_count'] = len(ns_records)
        dns_analysis['txt_records_count'] = len(txt_records)
        
        # Analyze patterns
        if len(mx_records) == 0:
            dns_analysis['findings'].append("No MX records found - domain may not receive email")
        
        if len(ns_records) < 2:
            dns_analysis['risk_score'] += 5
            dns_analysis['findings'].append("Insufficient name servers")
        
        return dns_analysis
    
    def _analyze_ssl_configuration(self, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_analysis = {
            'ssl_enabled': False,
            'certificate_valid': False,
            'risk_score': 0,
            'findings': []
        }
        
        ssl_enabled = domain_data.get('ssl_enabled', False)
        ssl_analysis['ssl_enabled'] = ssl_enabled
        
        if not ssl_enabled:
            ssl_analysis['risk_score'] += 15
            ssl_analysis['findings'].append("SSL/TLS not enabled")
        else:
            ssl_analysis['certificate_valid'] = True
            ssl_analysis['findings'].append("SSL/TLS enabled")
        
        return ssl_analysis
    
    def _analyze_platform_presence(self, platform: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze presence on a specific platform"""
        return {
            'platform': platform,
            'exists': data.get('exists', False),
            'analysis': 'Basic presence check completed',
            'risk_indicators': []
        }
    
    def _analyze_cross_platform_correlation(self, platforms: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze correlations across platforms"""
        return {
            'platforms_found': len([p for p in platforms.values() if p.get('exists', False)]),
            'correlation_score': 0.5,
            'patterns': []
        }
    
    def _analyze_geographic_trends(self, data_points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze geographic trends in the data"""
        countries = [dp.get('country_code', 'Unknown') for dp in data_points if 'country_code' in dp]
        country_counts = Counter(countries)
        
        return {
            'top_countries': dict(country_counts.most_common(5)),
            'total_countries': len(set(countries)),
            'geographic_diversity': len(set(countries)) / len(countries) if countries else 0
        }
    
    def _analyze_temporal_trends(self, data_points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal trends in the data"""
        timestamps = [dp.get('collection_time') for dp in data_points if 'collection_time' in dp]
        
        return {
            'data_points': len(data_points),
            'time_span': f"{len(timestamps)} collections",
            'collection_frequency': 'Regular' if len(timestamps) > 1 else 'Single'
        }
    
    def _analyze_threat_trends(self, data_points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat-related trends"""
        threat_levels = [dp.get('threat_level', 'low') for dp in data_points if 'threat_level' in dp]
        threat_counts = Counter(threat_levels)
        
        return {
            'threat_distribution': dict(threat_counts),
            'high_threat_percentage': (threat_counts.get('high', 0) / len(threat_levels)) * 100 if threat_levels else 0
        }
    
    def _detect_anomalies(self, data_points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in the data"""
        anomalies = []
        
        # Simple anomaly detection based on geographic distribution
        countries = [dp.get('country_code') for dp in data_points if 'country_code' in dp]
        if len(set(countries)) > len(countries) * 0.8:  # High diversity
            anomalies.append({
                'type': 'geographic_anomaly',
                'description': 'Unusually high geographic diversity',
                'severity': 'medium'
            })
        
        return anomalies
    
    def _generate_insights(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate insights from the analysis"""
        insights = []
        
        # Geographic insights
        geo_trends = analysis.get('trends', {}).get('geographic', {})
        if geo_trends.get('geographic_diversity', 0) > 0.7:
            insights.append("High geographic diversity detected - possible distributed infrastructure")
        
        # Threat insights
        threat_trends = analysis.get('trends', {}).get('threat', {})
        if threat_trends.get('high_threat_percentage', 0) > 30:
            insights.append("High percentage of threats detected - increased vigilance recommended")
        
        return insights
    
    def _correlate_ip_domain(self, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate IP and domain data"""
        ip_domains = []
        for dataset in datasets:
            if 'ip' in dataset and 'domain' in dataset:
                ip_domains.append((dataset['ip'], dataset['domain']))
        
        return {
            'ip_domain_pairs': len(ip_domains),
            'unique_ips': len(set(ip for ip, domain in ip_domains)),
            'unique_domains': len(set(domain for ip, domain in ip_domains))
        }
    
    def _correlate_temporal_patterns(self, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find temporal correlations"""
        return {
            'temporal_clustering': 'low',
            'time_based_patterns': []
        }
    
    def _correlate_geographic_patterns(self, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find geographic correlations"""
        return {
            'geographic_clustering': 'medium',
            'location_based_patterns': []
        }
    
    def _calculate_confidence_score(self, correlation: Dict[str, Any]) -> float:
        """Calculate confidence score for correlations"""
        base_score = 0.5
        datasets_count = correlation.get('datasets_analyzed', 0)
        
        if datasets_count > 5:
            base_score += 0.2
        if datasets_count > 10:
            base_score += 0.2
        
        return min(base_score, 1.0)
    
    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate risk level based on score"""
        if risk_score >= 50:
            return 'high'
        elif risk_score >= 25:
            return 'medium'
        else:
            return 'low'