"""
Unit tests for OSINT Bot modules
"""

import unittest
import sys
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint_modules.data_collector import OSINTDataCollector
from osint_modules.analyzer import OSINTAnalyzer
from osint_modules.reporter import OSINTReporter
from osint_modules.security import SecurityManager
from osint_modules.database import OSINTDatabase

class TestOSINTDataCollector(unittest.TestCase):
    """Test cases for OSINTDataCollector"""
    
    def setUp(self):
        self.collector = OSINTDataCollector()
    
    def test_init(self):
        """Test collector initialization"""
        self.assertIsNotNone(self.collector.session)
        self.assertEqual(self.collector.rate_limit_delay, 1)
        self.assertEqual(self.collector.last_request_time, 0)
    
    def test_rate_limit(self):
        """Test rate limiting functionality"""
        # First call should not be rate limited
        self.collector._rate_limit()
        
        # Second call should be rate limited
        start_time = self.collector.last_request_time
        self.collector._rate_limit()
        
        # Should have waited
        self.assertGreater(self.collector.last_request_time, start_time)
    
    @patch('requests.Session.get')
    def test_collect_ip_info_success(self, mock_get):
        """Test successful IP information collection"""
        mock_response = Mock()
        mock_response.json.return_value = {
            'ip': '8.8.8.8',
            'country_name': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'Mountain View',
            'org': 'Google LLC',
            'asn': 'AS15169',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'timezone': 'America/Los_Angeles',
            'in_eu': False,
            'postal': '94043'
        }
        mock_get.return_value = mock_response
        
        result = self.collector.collect_ip_info('8.8.8.8')
        
        self.assertEqual(result['ip'], '8.8.8.8')
        self.assertEqual(result['country'], 'United States')
        self.assertEqual(result['country_code'], 'US')
        self.assertIn('collection_time', result)
        self.assertIn('threat_level', result)
    
    @patch('requests.Session.get')
    def test_collect_ip_info_error(self, mock_get):
        """Test IP information collection with error"""
        mock_response = Mock()
        mock_response.json.return_value = {'error': True, 'reason': 'Invalid IP'}
        mock_get.return_value = mock_response
        
        result = self.collector.collect_ip_info('invalid_ip')
        
        self.assertIn('error', result)
        self.assertEqual(result['error'], 'Invalid IP')
    
    @patch('socket.gethostbyname')
    def test_collect_domain_info_success(self, mock_gethostbyname):
        """Test successful domain information collection"""
        mock_gethostbyname.return_value = '8.8.8.8'
        
        result = self.collector.collect_domain_info('google.com')
        
        self.assertEqual(result['domain'], 'google.com')
        self.assertEqual(result['ip_address'], '8.8.8.8')
        self.assertEqual(result['status'], 'active')
        self.assertIn('collection_time', result)
    
    @patch('socket.gethostbyname')
    def test_collect_domain_info_failure(self, mock_gethostbyname):
        """Test domain information collection with DNS failure"""
        mock_gethostbyname.side_effect = Exception('DNS resolution failed')
        
        result = self.collector.collect_domain_info('nonexistent.domain')
        
        self.assertEqual(result['domain'], 'nonexistent.domain')
        self.assertEqual(result['status'], 'inactive')
        self.assertIn('error', result)
    
    def test_collect_social_media_info(self):
        """Test social media information collection"""
        result = self.collector.collect_social_media_info('testuser')
        
        self.assertEqual(result['username'], 'testuser')
        self.assertIn('collection_time', result)
        self.assertIn('platforms', result)
        self.assertIn('warning', result)
    
    def test_collect_news_mentions(self):
        """Test news mentions collection"""
        result = self.collector.collect_news_mentions('test query')
        
        self.assertEqual(result['query'], 'test query')
        self.assertIn('collection_time', result)
        self.assertIn('articles', result)
        self.assertIn('summary', result)
    
    def test_assess_threat_level(self):
        """Test threat level assessment"""
        # Test high-risk country
        high_risk_data = {'country_code': 'CN'}
        threat_level = self.collector._assess_threat_level(high_risk_data)
        self.assertEqual(threat_level, 'medium')
        
        # Test low-risk country
        low_risk_data = {'country_code': 'US'}
        threat_level = self.collector._assess_threat_level(low_risk_data)
        self.assertEqual(threat_level, 'low')

class TestOSINTAnalyzer(unittest.TestCase):
    """Test cases for OSINTAnalyzer"""
    
    def setUp(self):
        self.analyzer = OSINTAnalyzer()
    
    def test_init(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.pattern_rules)
        self.assertIn('suspicious_patterns', self.analyzer.pattern_rules)
        self.assertIn('geolocation_risks', self.analyzer.pattern_rules)
    
    def test_analyze_ip_data(self):
        """Test IP data analysis"""
        ip_data = {
            'ip': '8.8.8.8',
            'country_code': 'US',
            'country_name': 'United States',
            'isp': 'Google LLC',
            'asn': 'AS15169'
        }
        
        result = self.analyzer.analyze_ip_data(ip_data)
        
        self.assertEqual(result['ip_address'], '8.8.8.8')
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertIn('geographic_analysis', result)
        self.assertIn('isp_analysis', result)
        self.assertIn('network_analysis', result)
    
    def test_analyze_domain_data(self):
        """Test domain data analysis"""
        domain_data = {
            'domain': 'google.com',
            'ip_address': '8.8.8.8',
            'status': 'active',
            'ssl_enabled': True,
            'mx_records': ['mx1.google.com', 'mx2.google.com'],
            'ns_records': ['ns1.google.com', 'ns2.google.com']
        }
        
        result = self.analyzer.analyze_domain_data(domain_data)
        
        self.assertEqual(result['domain'], 'google.com')
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertIn('domain_structure', result)
        self.assertIn('dns_analysis', result)
        self.assertIn('ssl_analysis', result)
    
    def test_analyze_trends(self):
        """Test trend analysis"""
        data_points = [
            {'country_code': 'US', 'collection_time': '2023-01-01T00:00:00'},
            {'country_code': 'US', 'collection_time': '2023-01-01T01:00:00'},
            {'country_code': 'GB', 'collection_time': '2023-01-01T02:00:00'},
        ]
        
        result = self.analyzer.analyze_trends(data_points)
        
        self.assertIn('trends', result)
        self.assertIn('anomalies', result)
        self.assertIn('insights', result)
        self.assertIn('geographic', result['trends'])
        self.assertIn('temporal', result['trends'])
    
    def test_calculate_risk_level(self):
        """Test risk level calculation"""
        # Test low risk
        low_risk = self.analyzer._calculate_risk_level(10)
        self.assertEqual(low_risk, 'low')
        
        # Test medium risk
        medium_risk = self.analyzer._calculate_risk_level(30)
        self.assertEqual(medium_risk, 'medium')
        
        # Test high risk
        high_risk = self.analyzer._calculate_risk_level(60)
        self.assertEqual(high_risk, 'high')

class TestOSINTReporter(unittest.TestCase):
    """Test cases for OSINTReporter"""
    
    def setUp(self):
        self.reporter = OSINTReporter()
    
    def test_init(self):
        """Test reporter initialization"""
        self.assertIsNotNone(self.reporter.report_templates)
        self.assertIn('ip_report', self.reporter.report_templates)
        self.assertIn('domain_report', self.reporter.report_templates)
        self.assertIn('comprehensive_report', self.reporter.report_templates)
    
    def test_generate_ip_report(self):
        """Test IP report generation"""
        ip_data = {
            'ip': '8.8.8.8',
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'Mountain View',
            'isp': 'Google LLC',
            'asn': 'AS15169',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'timezone': 'America/Los_Angeles',
            'threat_level': 'low'
        }
        
        analysis_data = {
            'risk_level': 'low',
            'risk_score': 15,
            'findings': ['Low risk IP address'],
            'recommendations': ['Continue monitoring'],
            'network_analysis': {'network_type': 'public'}
        }
        
        report = self.reporter.generate_ip_report(ip_data, analysis_data)
        
        self.assertIn('8.8.8.8', report)
        self.assertIn('United States', report)
        self.assertIn('Google LLC', report)
        self.assertIn('LOW', report)
    
    def test_generate_domain_report(self):
        """Test domain report generation"""
        domain_data = {
            'domain': 'google.com',
            'ip_address': '8.8.8.8',
            'status': 'active',
            'ssl_enabled': True,
            'ssl_version': 'TLSv1.3',
            'mx_records': ['mx1.google.com'],
            'ns_records': ['ns1.google.com'],
            'txt_records': ['v=spf1 include:_spf.google.com ~all']
        }
        
        analysis_data = {
            'risk_level': 'low',
            'risk_score': 10,
            'findings': ['Domain appears legitimate'],
            'recommendations': ['Regular monitoring'],
            'domain_structure': {'suspicious_tld': False},
            'ssl_analysis': {'certificate_valid': True}
        }
        
        report = self.reporter.generate_domain_report(domain_data, analysis_data)
        
        self.assertIn('google.com', report)
        self.assertIn('8.8.8.8', report)
        self.assertIn('active', report)
        self.assertIn('True', report)
    
    def test_generate_json_report(self):
        """Test JSON report generation"""
        data = {'test': 'data', 'number': 123}
        
        report = self.reporter.generate_json_report(data, 'test_report')
        
        # Should be valid JSON
        parsed = json.loads(report)
        self.assertEqual(parsed['report_type'], 'test_report')
        self.assertEqual(parsed['data'], data)
        self.assertIn('generated_at', parsed)
    
    def test_generate_csv_report(self):
        """Test CSV report generation"""
        datasets = [
            {'ip': '8.8.8.8', 'country': 'US', 'risk_level': 'low'},
            {'ip': '1.1.1.1', 'country': 'US', 'risk_level': 'low'}
        ]
        
        report = self.reporter.generate_csv_report(datasets)
        
        lines = report.split('\n')
        self.assertGreater(len(lines), 1)
        self.assertIn('country', lines[0])  # Header
        self.assertIn('8.8.8.8', report)
        self.assertIn('1.1.1.1', report)

class TestSecurityManager(unittest.TestCase):
    """Test cases for SecurityManager"""
    
    def setUp(self):
        self.security_manager = SecurityManager()
    
    def test_init(self):
        """Test security manager initialization"""
        self.assertIsNotNone(self.security_manager.security_config)
        self.assertIsNotNone(self.security_manager.rate_limits)
        self.assertIsNotNone(self.security_manager.blocked_ips)
    
    def test_rate_limit(self):
        """Test rate limiting"""
        # First request should be allowed
        allowed = self.security_manager.rate_limit('ip_lookup', 'test_user')
        self.assertTrue(allowed)
        
        # Many requests should eventually be blocked
        for i in range(20):
            self.security_manager.rate_limit('ip_lookup', 'test_user')
        
        # Should be rate limited now
        blocked = self.security_manager.rate_limit('ip_lookup', 'test_user')
        self.assertFalse(blocked)
    
    def test_validate_input(self):
        """Test input validation"""
        # Valid IP
        valid_ip = self.security_manager.validate_input('8.8.8.8', 'ip')
        self.assertTrue(valid_ip)
        
        # Invalid IP
        invalid_ip = self.security_manager.validate_input('invalid_ip', 'ip')
        self.assertFalse(invalid_ip)
        
        # Valid domain
        valid_domain = self.security_manager.validate_input('google.com', 'domain')
        self.assertTrue(valid_domain)
        
        # Invalid domain
        invalid_domain = self.security_manager.validate_input('invalid..domain', 'domain')
        self.assertFalse(invalid_domain)
        
        # Malicious input
        malicious_input = self.security_manager.validate_input('<script>alert("xss")</script>', 'query')
        self.assertFalse(malicious_input)
    
    def test_sanitize_input(self):
        """Test input sanitization"""
        dirty_input = '  test\x00input\x1f  '
        clean_input = self.security_manager.sanitize_input(dirty_input)
        
        self.assertEqual(clean_input, 'testinput')
        self.assertNotIn('\x00', clean_input)
        self.assertNotIn('\x1f', clean_input)
    
    def test_check_ip_reputation(self):
        """Test IP reputation checking"""
        # Test public IP
        public_ip = self.security_manager.check_ip_reputation('8.8.8.8')
        self.assertEqual(public_ip['ip'], '8.8.8.8')
        self.assertIn('reputation', public_ip)
        
        # Test private IP
        private_ip = self.security_manager.check_ip_reputation('192.168.1.1')
        self.assertEqual(private_ip['ip'], '192.168.1.1')
        self.assertEqual(private_ip['reputation'], 'private')
    
    def test_generate_security_report(self):
        """Test security report generation"""
        report = self.security_manager.generate_security_report()
        
        self.assertIn('timestamp', report)
        self.assertIn('rate_limits', report)
        self.assertIn('security_status', report)
        self.assertIn('recent_events', report)

class TestOSINTDatabase(unittest.TestCase):
    """Test cases for OSINTDatabase"""
    
    def setUp(self):
        # Use temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        self.db = OSINTDatabase(self.temp_db.name)
    
    def tearDown(self):
        self.db.close()
        os.unlink(self.temp_db.name)
    
    def test_init(self):
        """Test database initialization"""
        self.assertEqual(self.db.db_path, self.temp_db.name)
        self.assertIsNotNone(self.db.lock)
    
    def test_store_and_get_ip_lookup(self):
        """Test storing and retrieving IP lookup"""
        ip_data = {
            'ip': '8.8.8.8',
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'Mountain View',
            'isp': 'Google LLC',
            'asn': 'AS15169',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'threat_level': 'low'
        }
        
        analysis_data = {
            'risk_score': 15,
            'risk_level': 'low'
        }
        
        # Store IP lookup
        record_id = self.db.store_ip_lookup(ip_data, analysis_data)
        self.assertIsNotNone(record_id)
        
        # Retrieve IP lookup
        retrieved = self.db.get_ip_lookup('8.8.8.8')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['ip_address'], '8.8.8.8')
        self.assertEqual(retrieved['country'], 'United States')
        self.assertEqual(retrieved['risk_score'], 15)
    
    def test_store_and_get_domain_lookup(self):
        """Test storing and retrieving domain lookup"""
        domain_data = {
            'domain': 'google.com',
            'ip_address': '8.8.8.8',
            'status': 'active',
            'ssl_enabled': True,
            'ssl_version': 'TLSv1.3',
            'mx_records': ['mx1.google.com'],
            'ns_records': ['ns1.google.com'],
            'txt_records': ['v=spf1 include:_spf.google.com ~all']
        }
        
        analysis_data = {
            'risk_score': 10,
            'risk_level': 'low'
        }
        
        # Store domain lookup
        record_id = self.db.store_domain_lookup(domain_data, analysis_data)
        self.assertIsNotNone(record_id)
        
        # Retrieve domain lookup
        retrieved = self.db.get_domain_lookup('google.com')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['domain'], 'google.com')
        self.assertEqual(retrieved['ip_address'], '8.8.8.8')
        self.assertEqual(retrieved['risk_score'], 10)
    
    def test_store_analysis_result(self):
        """Test storing analysis results"""
        analysis_data = {
            'analysis_type': 'comprehensive',
            'risk_level': 'low',
            'confidence_score': 0.85,
            'findings': ['No threats detected'],
            'recommendations': ['Continue monitoring']
        }
        
        record_id = self.db.store_analysis_result('ip', '8.8.8.8', analysis_data)
        self.assertIsNotNone(record_id)
        
        # Retrieve analysis results
        results = self.db.get_analysis_results('ip', '8.8.8.8')
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]['target_value'], '8.8.8.8')
        self.assertEqual(results[0]['risk_level'], 'low')
    
    def test_get_statistics(self):
        """Test getting database statistics"""
        stats = self.db.get_statistics()
        
        self.assertIsNotNone(stats)
        self.assertIn('ip_lookups_count', stats)
        self.assertIn('domain_lookups_count', stats)
        self.assertIn('analysis_results_count', stats)
    
    def test_backup_and_restore(self):
        """Test database backup and restore"""
        backup_path = self.temp_db.name + '.backup'
        
        # Create backup
        success = self.db.backup_database(backup_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(backup_path))
        
        # Restore from backup
        success = self.db.restore_database(backup_path)
        self.assertTrue(success)
        
        # Cleanup
        os.unlink(backup_path)

if __name__ == '__main__':
    unittest.main()