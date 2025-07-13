"""
Database Module for OSINT Bot
Handles data storage and retrieval for scalability
"""

import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import os
from contextlib import contextmanager
import threading

logger = logging.getLogger(__name__)

class OSINTDatabase:
    """Database manager for OSINT bot data"""
    
    def __init__(self, db_path: str = "osint_bot.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # IP lookups table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_lookups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        country TEXT,
                        country_code TEXT,
                        region TEXT,
                        city TEXT,
                        isp TEXT,
                        asn TEXT,
                        latitude REAL,
                        longitude REAL,
                        threat_level TEXT,
                        risk_score INTEGER,
                        raw_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Domain lookups table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS domain_lookups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        ip_address TEXT,
                        status TEXT,
                        mx_records TEXT,
                        ns_records TEXT,
                        txt_records TEXT,
                        ssl_enabled BOOLEAN,
                        ssl_version TEXT,
                        risk_score INTEGER,
                        raw_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Social media lookups table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS social_media_lookups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        platform TEXT,
                        profile_exists BOOLEAN,
                        profile_data TEXT,
                        analysis_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # News mentions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS news_mentions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        query TEXT NOT NULL,
                        title TEXT,
                        url TEXT,
                        source TEXT,
                        published_date TIMESTAMP,
                        sentiment TEXT,
                        raw_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Analysis results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_type TEXT NOT NULL,
                        target_value TEXT NOT NULL,
                        analysis_type TEXT,
                        risk_level TEXT,
                        confidence_score REAL,
                        findings TEXT,
                        recommendations TEXT,
                        raw_analysis TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_type TEXT NOT NULL,
                        report_name TEXT,
                        targets TEXT,
                        content TEXT,
                        format TEXT,
                        file_path TEXT,
                        created_by TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Security events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        user_id TEXT,
                        ip_address TEXT,
                        details TEXT,
                        severity TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Rate limiting table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rate_limits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        identifier TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        request_count INTEGER DEFAULT 1,
                        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_lookups(ip_address)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domain_lookups(domain)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON social_media_lookups(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_target ON analysis_results(target_type, target_value)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, operation)')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get database connection with proper error handling"""
        conn = None
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path, timeout=30.0)
                conn.row_factory = sqlite3.Row
                yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def store_ip_lookup(self, ip_data: Dict[str, Any], analysis_data: Dict[str, Any] = None) -> int:
        """Store IP lookup results"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if IP already exists
                cursor.execute('SELECT id FROM ip_lookups WHERE ip_address = ?', (ip_data.get('ip'),))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing record
                    cursor.execute('''
                        UPDATE ip_lookups SET
                            country = ?, country_code = ?, region = ?, city = ?,
                            isp = ?, asn = ?, latitude = ?, longitude = ?,
                            threat_level = ?, risk_score = ?, raw_data = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE ip_address = ?
                    ''', (
                        ip_data.get('country'),
                        ip_data.get('country_code'),
                        ip_data.get('region'),
                        ip_data.get('city'),
                        ip_data.get('isp'),
                        ip_data.get('asn'),
                        ip_data.get('latitude'),
                        ip_data.get('longitude'),
                        ip_data.get('threat_level'),
                        analysis_data.get('risk_score', 0) if analysis_data else 0,
                        json.dumps(ip_data),
                        ip_data.get('ip')
                    ))
                    record_id = existing['id']
                else:
                    # Insert new record
                    cursor.execute('''
                        INSERT INTO ip_lookups (
                            ip_address, country, country_code, region, city,
                            isp, asn, latitude, longitude, threat_level,
                            risk_score, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ip_data.get('ip'),
                        ip_data.get('country'),
                        ip_data.get('country_code'),
                        ip_data.get('region'),
                        ip_data.get('city'),
                        ip_data.get('isp'),
                        ip_data.get('asn'),
                        ip_data.get('latitude'),
                        ip_data.get('longitude'),
                        ip_data.get('threat_level'),
                        analysis_data.get('risk_score', 0) if analysis_data else 0,
                        json.dumps(ip_data)
                    ))
                    record_id = cursor.lastrowid
                
                conn.commit()
                logger.info(f"Stored IP lookup for {ip_data.get('ip')} with ID {record_id}")
                return record_id
                
        except Exception as e:
            logger.error(f"Error storing IP lookup: {e}")
            raise
    
    def store_domain_lookup(self, domain_data: Dict[str, Any], analysis_data: Dict[str, Any] = None) -> int:
        """Store domain lookup results"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if domain already exists
                cursor.execute('SELECT id FROM domain_lookups WHERE domain = ?', (domain_data.get('domain'),))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing record
                    cursor.execute('''
                        UPDATE domain_lookups SET
                            ip_address = ?, status = ?, mx_records = ?,
                            ns_records = ?, txt_records = ?, ssl_enabled = ?,
                            ssl_version = ?, risk_score = ?, raw_data = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE domain = ?
                    ''', (
                        domain_data.get('ip_address'),
                        domain_data.get('status'),
                        json.dumps(domain_data.get('mx_records', [])),
                        json.dumps(domain_data.get('ns_records', [])),
                        json.dumps(domain_data.get('txt_records', [])),
                        domain_data.get('ssl_enabled', False),
                        domain_data.get('ssl_version'),
                        analysis_data.get('risk_score', 0) if analysis_data else 0,
                        json.dumps(domain_data),
                        domain_data.get('domain')
                    ))
                    record_id = existing['id']
                else:
                    # Insert new record
                    cursor.execute('''
                        INSERT INTO domain_lookups (
                            domain, ip_address, status, mx_records, ns_records,
                            txt_records, ssl_enabled, ssl_version, risk_score, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        domain_data.get('domain'),
                        domain_data.get('ip_address'),
                        domain_data.get('status'),
                        json.dumps(domain_data.get('mx_records', [])),
                        json.dumps(domain_data.get('ns_records', [])),
                        json.dumps(domain_data.get('txt_records', [])),
                        domain_data.get('ssl_enabled', False),
                        domain_data.get('ssl_version'),
                        analysis_data.get('risk_score', 0) if analysis_data else 0,
                        json.dumps(domain_data)
                    ))
                    record_id = cursor.lastrowid
                
                conn.commit()
                logger.info(f"Stored domain lookup for {domain_data.get('domain')} with ID {record_id}")
                return record_id
                
        except Exception as e:
            logger.error(f"Error storing domain lookup: {e}")
            raise
    
    def store_analysis_result(self, target_type: str, target_value: str, analysis_data: Dict[str, Any]) -> int:
        """Store analysis results"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO analysis_results (
                        target_type, target_value, analysis_type, risk_level,
                        confidence_score, findings, recommendations, raw_analysis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    target_type,
                    target_value,
                    analysis_data.get('analysis_type', 'general'),
                    analysis_data.get('risk_level'),
                    analysis_data.get('confidence_score', 0.0),
                    json.dumps(analysis_data.get('findings', [])),
                    json.dumps(analysis_data.get('recommendations', [])),
                    json.dumps(analysis_data)
                ))
                
                record_id = cursor.lastrowid
                conn.commit()
                logger.info(f"Stored analysis result for {target_type}:{target_value} with ID {record_id}")
                return record_id
                
        except Exception as e:
            logger.error(f"Error storing analysis result: {e}")
            raise
    
    def store_report(self, report_type: str, report_name: str, content: str, 
                    format: str = 'markdown', created_by: str = 'system') -> int:
        """Store generated report"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO reports (
                        report_type, report_name, content, format, created_by
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (report_type, report_name, content, format, created_by))
                
                record_id = cursor.lastrowid
                conn.commit()
                logger.info(f"Stored report {report_name} with ID {record_id}")
                return record_id
                
        except Exception as e:
            logger.error(f"Error storing report: {e}")
            raise
    
    def get_ip_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get IP lookup from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ip_lookups WHERE ip_address = ?', (ip_address,))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting IP lookup: {e}")
            return None
    
    def get_domain_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain lookup from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM domain_lookups WHERE domain = ?', (domain,))
                row = cursor.fetchone()
                
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting domain lookup: {e}")
            return None
    
    def get_analysis_results(self, target_type: str, target_value: str, 
                           limit: int = 10) -> List[Dict[str, Any]]:
        """Get analysis results from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM analysis_results 
                    WHERE target_type = ? AND target_value = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (target_type, target_value, limit))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting analysis results: {e}")
            return []
    
    def get_recent_lookups(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent lookups from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get recent IP lookups
                cursor.execute('''
                    SELECT 'ip' as type, ip_address as target, threat_level, risk_score, created_at
                    FROM ip_lookups
                    WHERE created_at > datetime('now', '-{} hours')
                    ORDER BY created_at DESC
                    LIMIT ?
                '''.format(hours), (limit,))
                
                ip_results = cursor.fetchall()
                
                # Get recent domain lookups
                cursor.execute('''
                    SELECT 'domain' as type, domain as target, 'low' as threat_level, risk_score, created_at
                    FROM domain_lookups
                    WHERE created_at > datetime('now', '-{} hours')
                    ORDER BY created_at DESC
                    LIMIT ?
                '''.format(hours), (limit,))
                
                domain_results = cursor.fetchall()
                
                # Combine and sort results
                all_results = list(ip_results) + list(domain_results)
                all_results.sort(key=lambda x: x['created_at'], reverse=True)
                
                return [dict(row) for row in all_results[:limit]]
                
        except Exception as e:
            logger.error(f"Error getting recent lookups: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Count records in each table
                tables = ['ip_lookups', 'domain_lookups', 'social_media_lookups', 
                         'news_mentions', 'analysis_results', 'reports', 'security_events']
                
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    count = cursor.fetchone()[0]
                    stats[f'{table}_count'] = count
                
                # Get recent activity (last 24 hours)
                cursor.execute('''
                    SELECT COUNT(*) FROM ip_lookups 
                    WHERE created_at > datetime('now', '-24 hours')
                ''')
                stats['ip_lookups_24h'] = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM domain_lookups 
                    WHERE created_at > datetime('now', '-24 hours')
                ''')
                stats['domain_lookups_24h'] = cursor.fetchone()[0]
                
                # Get risk distribution
                cursor.execute('''
                    SELECT threat_level, COUNT(*) FROM ip_lookups 
                    GROUP BY threat_level
                ''')
                threat_dist = dict(cursor.fetchall())
                stats['threat_distribution'] = threat_dist
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def cleanup_old_records(self, days: int = 30) -> int:
        """Clean up old records"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old rate limit records
                cursor.execute('''
                    DELETE FROM rate_limits 
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                
                deleted_count = cursor.rowcount
                
                # Clean up old security events
                cursor.execute('''
                    DELETE FROM security_events 
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                
                deleted_count += cursor.rowcount
                
                conn.commit()
                logger.info(f"Cleaned up {deleted_count} old records")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up old records: {e}")
            return 0
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            import shutil
            
            with self.lock:
                shutil.copy2(self.db_path, backup_path)
            
            logger.info(f"Database backed up to {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error backing up database: {e}")
            return False
    
    def restore_database(self, backup_path: str) -> bool:
        """Restore database from backup"""
        try:
            import shutil
            
            if not os.path.exists(backup_path):
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            with self.lock:
                shutil.copy2(backup_path, self.db_path)
            
            logger.info(f"Database restored from {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring database: {e}")
            return False
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute custom query (for advanced users)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                if query.strip().upper().startswith('SELECT'):
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows]
                else:
                    conn.commit()
                    return [{'affected_rows': cursor.rowcount}]
                    
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        # SQLite connections are closed automatically with context manager
        logger.info("Database connections closed")