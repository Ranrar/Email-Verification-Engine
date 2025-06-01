"""
Email Verification Engine - cache Module
====================================================
3-Level Cache System:

1. CACHE HIERARCHY EXPLAINED:

   ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
   │ Memory Cache  │ →   │  Disk Cache   │ →   │  PostgreSQL   │
   │ (TTLCache)    │     │  (SQLite3)    │     │  Database     │
   └───────────────┘     └───────────────┘     └───────────────┘
         RAM               Local Files          Network Database
   Non-persistent       Persists Restarts      Primary Data Store
   
2. DATABASE TYPES:

   A. POSTGRESQL DATABASE:
      - Primary application database
      - Network-based, accessed through sync_db
      - Used for configuration settings and long-term cache storage
      
   B. DISKCACHE (SQLITE3):
      - Local file-based cache using SQLite3 under the hood
      - Intermediate storage between memory and PostgreSQL
      - Located at settings["DISK_CACHE_DIR"] (./.cache by default)
      - Persists between application restarts

3. RAM NON-PRESISTENT
    - The memory cache is implemented using `cachetools.TTLCache`.
    - It is the fastest layer in the cache hierarchy, residing in RAM.
    - Stores frequently accessed data with a Time-To-Live (TTL) to ensure freshness.
    - Non-persistent: data is lost when the application restarts.
    - Used for quick lookups to reduce latency and offload requests from slower layers.
        
client  ──► mem_cache ──► disk_cache ─► PostgreSQL
           │               │
           │◄── refill ◄───┘
"""
import sqlite3
import threading
import pickle
import time
import json
import os
from datetime import datetime, timezone, timedelta
from cachetools import TTLCache
from src.helpers.dbh import sync_db
from src.managers.log import Axe
from src.managers.time import now_utc, normalize_datetime

# Initialize logging
logger = Axe()

class CacheKeys:
    """
    CacheKeys provides standardized cache key formats for all cacheable entities,
    based on the database schema (e.g., MX records, WHOIS, SPF, DKIM, etc).
    """
    # Cache key
    MX_RECORDS = "mx_records:{domain}"
    WHOIS_INFO = "whois_info:{domain}"
    SPF_RECORD = "spf:{domain}"
    DKIM_RECORD = "dkim:{domain}"
    DMARC_RECORD = "dmarc:{domain}"
    REVERSE_DNS = "reverse_dns:{ip}"
    SMTP_BANNER = "smtp_banner:{domain}"
    SMTP_RESULT = "smtp_result:{email}"
    DISPOSABLE = "disposable:{domain}"
    BLACKLIST = "blacklist:{domain}"
    DNS_RECORDS = "dns:{record_type}:{domain}"
    RATE_LIMIT_STATE = "rate_limit:{category}:{resource_id}"
    VALIDATION_QUEUE_CONFIG = "validation_queue:config"
    FORMAT_VALIDATION = "format_validation:{email}"
    # New keys needed for MX functionality
    A_RECORDS = "a_records:{domain}"
    IP_ADDRESS = "ip_address:{host}:{ip_type}"
    GEO_INFO = "geo_info:{ip}"
    PTR_RECORD = "ptr_record:{ip}"
    VALIDATION_RESULT = "validation_result:{email}"
    SMTP_BLOCKED = "smtp_blocked:{domain}"
    
    # ...add more as needed...

    @staticmethod
    def mx_records(domain): return CacheKeys.MX_RECORDS.format(domain=domain)
    @staticmethod
    def whois_info(domain): return CacheKeys.WHOIS_INFO.format(domain=domain)
    @staticmethod
    def spf(domain): return CacheKeys.SPF_RECORD.format(domain=domain)
    @staticmethod
    def dkim(domain): return CacheKeys.DKIM_RECORD.format(domain=domain)
    @staticmethod
    def dmarc(domain): return CacheKeys.DMARC_RECORD.format(domain=domain)
    @staticmethod
    def reverse_dns(ip): return CacheKeys.REVERSE_DNS.format(ip=ip)
    @staticmethod
    def smtp_banner(domain): return CacheKeys.SMTP_BANNER.format(domain=domain)
    @staticmethod
    def smtp_result(email): return CacheKeys.SMTP_RESULT.format(email=email)
    @staticmethod
    def disposable(domain): return CacheKeys.DISPOSABLE.format(domain=domain)
    @staticmethod
    def blacklist(domain): return CacheKeys.BLACKLIST.format(domain=domain)
    @staticmethod
    def dns_records_key(record_type, domain):
        """Generate cache key for DNS records by type and domain"""
        return CacheKeys.DNS_RECORDS.format(record_type=record_type, domain=domain)
    @staticmethod
    def rate_limit_state_key(category, resource_id):
        """Generate cache key for rate limit state tracking"""
        return CacheKeys.RATE_LIMIT_STATE.format(
            category=category,
            resource_id=resource_id
        )
    @staticmethod
    def get_ttl_from_db(cache_type):
        """
        Get TTL value from database settings based on cache type
        Used by DNS and rate limit systems
        
        Args:
            cache_type: Type of cache (e.g., 'DNS_RECORDS', 'MX_RECORDS')
            
        Returns:
            int: TTL value in seconds or None if not found
        """
        # This would typically call into rate_limit_manager to get the TTL
        # But we need to avoid circular imports
        from src.helpers.dbh import sync_db
        try:
            # Try to get from rate_limit table
            query = """
                SELECT value FROM rate_limit 
                WHERE category = 'cache' AND name = %s AND enabled = TRUE
            """
            ttl = sync_db.fetchval(query, f"{cache_type.lower()}_ttl")
            if ttl:
                return int(ttl)
            return 3600  # Default 1 hour
        except Exception as e:
            logger.warning(f"Failed to get TTL for {cache_type}: {e}")
            return 3600  # Default fallback
    @staticmethod
    def validation_queue_config():
        """Static key for validation queue configuration"""
        return CacheKeys.VALIDATION_QUEUE_CONFIG
        # ...add more as needed...
    @staticmethod
    def a_records(domain): return CacheKeys.A_RECORDS.format(domain=domain)
    
    @staticmethod
    def ip_address(host, ip_type=None): 
        if ip_type:
            return CacheKeys.IP_ADDRESS.format(host=host, ip_type=ip_type)
        else:
            return CacheKeys.IP_ADDRESS.format(host=host, ip_type="all")
    
    @staticmethod
    def geo_info(ip): return CacheKeys.GEO_INFO.format(ip=ip)
    
    @staticmethod
    def ptr_record(ip): return CacheKeys.PTR_RECORD.format(ip=ip)
    
    @staticmethod
    def validation_result(email): return CacheKeys.VALIDATION_RESULT.format(email=email)
    
    @staticmethod
    def smtp_blocked(domain): return CacheKeys.SMTP_BLOCKED.format(domain=domain)

    @staticmethod
    def format_validation(email):
        """Generate cache key for format validation by email"""
        return CacheKeys.FORMAT_VALIDATION.format(email=email)

class CacheManager:
    """
    3-Level Cache Manager:
        - Level 1: Memory (TTLCache, RAM, fastest, non-persistent)
        - Level 2: Disk (SQLite3, persistent, local)
        - Level 3: PostgreSQL (primary DB, network)
    On startup: loads disk cache into memory. On miss: refills lower levels.
    """

    def __init__(self, settings, db_conn=None):
        """
        Initialize the 3-level cache system.
        
        Args:
            settings: dict with at least 'DISK_CACHE_DIR', 'MEM_CACHE_SIZE', 'MEM_CACHE_TTL'
            db_conn: PostgreSQL connection or sync_db interface
        """
        self.settings = settings
        self.db_conn = db_conn
        self.lock = threading.Lock()
        self.time_offset = timedelta(seconds=0)  # Time offset between local and DB
        
        # Add processing items tracking
        self.processing_items = {}
        self.processing_lock = threading.Lock()
        
        # Transaction management
        self.transaction_active = False
        self.transaction_log = []
        self.transaction_savepoints = {}
        
        # Level 1: RAM NON-PERSISTENT
        self.mem_cache = TTLCache(
            maxsize=settings.get("MEM_CACHE_SIZE", 10000),
            ttl=settings.get("MEM_CACHE_TTL", 3600)
        )
        
        # Memory expiry tracking
        self.mem_expiry = {}
        
        # Level 2: DISKCACHE (SQLITE3)
        disk_cache_dir = settings.get("DISK_CACHE_DIR", "./.cache")
        # Ensure directory exists
        os.makedirs(disk_cache_dir, exist_ok=True)
        self.disk_cache_path = os.path.join(disk_cache_dir, "cache.db")
        self.disk_conn = sqlite3.connect(self.disk_cache_path, check_same_thread=False)
        self._init_disk_cache()
        
        # Level 3: POSTGRESQL - Network Database
        if self.db_conn:
            self._init_postgresql_cache()
        
        # Load disk cache into memory on startup
        self._load_disk_to_mem()
        
        # Clean up expired entries on startup
        self.cleanup_expired()
        
        # Start recurring cleanup timer
        self._setup_recurring_cleanup()

    def _init_disk_cache(self):
        """
        Initialize the disk cache (DISKCACHE - SQLITE3) table.
        """
        try:
            with self.disk_conn:
                self.disk_conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        value BLOB,
                        expires_at INTEGER
                    )
                """)
            logger.debug("Disk cache (SQLite3) initialized")
        except Exception as e:
            logger.error(f"Error initializing disk cache: {e}")
            raise

    def _init_postgresql_cache(self):
        """
        Initialize connection to PostgreSQL cache (POSTGRESQL) and synchronize time.
        Uses existing cache_entries table from schema.sql.
        """
        if not self.db_conn:
            error_msg = "PostgreSQL database connection not provided"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        try:
            # Ensure DB is initialized
            if not self.db_conn.is_initialized():
                try:
                    self.db_conn.initialize()
                except Exception as e:
                    error_msg = f"Failed to initialize PostgreSQL database: {e}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg) from e
            
            # Check if cache_entries table exists
            table_exists = self.db_conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'cache_entries'
                )
            """)
            
            if not table_exists:
                error_msg = "PostgreSQL cache_entries table not found in database"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
                
            # Synchronize time with database
            self._sync_time_with_db()
            
            logger.info("PostgreSQL cache connection initialized successfully")
            
        except Exception as e:
            error_msg = f"Failed to connect to PostgreSQL database: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def _sync_time_with_db(self):
        """
        Synchronize local time with PostgreSQL database time.
        Calculates time offset between local system and database server.
        """
        try:
            # Get current local time
            local_time = now_utc()
            
            # Get database time if db_conn is available
            if self.db_conn is not None:
                db_time_str = self.db_conn.fetchval("SELECT NOW()")
                db_time = normalize_datetime(db_time_str)
            else:
                db_time = None

            if db_time:
                # Calculate time difference
                self.time_offset = db_time - local_time
                logger.info(f"Time offset between local and database: {self.time_offset}")
            else:
                logger.warning("Failed to sync time with database, using local time")
                
        except Exception as e:
            logger.warning(f"Time sync with database failed: {e}. Using local time.")

    def _get_db_time(self):
        """
        Get current time adjusted to match database server time.
        Uses the calculated offset between local and database time.
        
        Returns:
            datetime: Current time adjusted to database server time
        """
        return now_utc() + self.time_offset

    def _load_disk_to_mem(self):
        """
        Load valid cache entries from disk to memory on startup.
        Transfers data from DISKCACHE (SQLITE3) to RAM NON-PERSISTENT.
        """
        now = int(time.time())
        count = 0
        try:
            with self.lock, self.disk_conn:
                cursor = self.disk_conn.execute(
                    "SELECT key, value, expires_at FROM cache WHERE expires_at > ?", (now,)
                )
                for key, value, expires_at in cursor.fetchall():
                    try:
                        # Use a safe unpickler or skip problematic entries
                        try:
                            obj = pickle.loads(value)
                            ttl = expires_at - now
                            if ttl > 0:
                                self.mem_cache[key] = obj
                                count += 1
                        except (ImportError, ModuleNotFoundError) as e:
                            # Skip entries that cause circular imports
                            logger.debug(f"Skipped cache entry {key} due to import issue: {e}")
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to load cache entry {key}: {str(e)}")
                        continue
            logger.info(f"Loaded {count} entries from disk cache into memory")
        except Exception as e:
            logger.error(f"Error loading disk cache: {str(e)}")

    def get(self, key, category="DEFAULT"):
        """
        Get value from cache hierarchy.
        
        Args:
            key: Cache key string
            category: Optional category for PostgreSQL organization
            
        Returns:
            Cached value or None if not found
            
        Cache Hierarchy:
        1. RAM NON-PERSISTENT - Memory Cache (fastest)
        2. DISKCACHE (SQLITE3) - Disk Cache (medium)
        3. POSTGRESQL - Network Database (slowest)
        """
        with self.lock:
            # Level 1: RAM NON-PERSISTENT
            if key in self.mem_cache:
                logger.debug(f"Cache hit (L1-Memory): {key}")
                return self.mem_cache[key]

            # Level 2: DISKCACHE (SQLITE3)
            now = int(time.time())
            row = self.disk_conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ? AND expires_at > ?", (key, now)
            ).fetchone()
            
            if row:
                value, expires_at = row
                try:
                    obj = pickle.loads(value)
                    ttl = expires_at - now
                    if ttl > 0:
                        # Refill Level 1: RAM NON-PERSISTENT from disk
                        self.mem_cache[key] = obj
                        logger.debug(f"Cache hit (L2-Disk): {key}")
                    return obj
                except Exception as e:
                    logger.warning(f"Failed to deserialize disk cache entry {key}: {str(e)}")

            # Level 3: POSTGRESQL
            if self.db_conn:
                try:
                    # Use the cache_entries table from schema.sql
                    pg_query = """
                        SELECT value, created_at, ttl 
                        FROM cache_entries 
                        WHERE key = $1 AND category = $2 
                        AND (ttl <= 0 OR created_at + (ttl * interval '1 second') > NOW())
                    """
                    row = self.db_conn.fetchrow(pg_query, key, category) 
                    
                    if row:
                        try:
                            # Get JSONB value from PostgreSQL
                            value_data = row['value']
                            created_at = row['created_at']
                            ttl = row['ttl']
                            
                            # Calculate remaining TTL for memory cache
                            if ttl > 0:
                                now = self._get_db_time()
                                elapsed = (now - created_at).total_seconds()
                                remaining_ttl = max(1, ttl - int(elapsed))
                            else:
                                # Use default TTL for permanent entries
                                remaining_ttl = self.settings.get("MEM_CACHE_TTL", 3600)
                            

                            # Check if this is binary serialized data
                            if isinstance(value_data, dict) and value_data.get('_binary') == True:
                                try:
                                    # Deserialize binary data
                                    import base64
                                    binary_data = base64.b64decode(value_data['data'])
                                    obj = pickle.loads(binary_data)
                                except Exception as e:
                                    logger.warning(f"Failed to deserialize binary PostgreSQL data: {e}")
                                    return None
                            else:
                                # Use the JSONB value directly
                                obj = value_data
                            
                            # Store in lower cache levels with calculated TTL
                            self._store_in_lower_caches(key, obj, remaining_ttl)
                            
                            logger.debug(f"Cache hit (L3-PostgreSQL): {key}")
                            return obj
                        except Exception as e:
                            logger.warning(f"Failed to process PostgreSQL cache entry: {e}")
                except Exception as e:
                    logger.warning(f"PostgreSQL cache query failed: {e}")

            logger.debug(f"Cache miss: {key}")
            return None

    def _store_in_lower_caches(self, key, value, ttl):
        """
        Store value in memory and disk cache only (for refilling from PostgreSQL).
        Used internally for cache misses at lower levels.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        try:
            expires_at = int(time.time()) + ttl
            
            # Level 1: RAM NON-PERSISTENT - Memory Cache
            self.mem_cache[key] = value
            
            # Level 2: DISKCACHE (SQLITE3) - Disk Cache
            blob = pickle.dumps(value)
            with self.disk_conn:
                self.disk_conn.execute(
                    "REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                    (key, blob, expires_at)
                )
        except Exception as e:
            logger.warning(f"Failed to store in lower caches: {e}")

    def _is_json_serializable(self, obj):
        """
        Check if object is JSON serializable for PostgreSQL JSONB storage.
        """
        try:
            json.dumps(obj)
            return True
        except (TypeError, OverflowError):
            return False

    def set_no_transaction(self, key, value, ttl=None, category="DEFAULT"):
        """
        Set value in all cache levels (no transaction support).
        
        Args:
            key: Cache key string
            value: Value to cache
            ttl: Time-to-live in seconds (None uses default)
            category: Category for PostgreSQL organization
            
        Returns:
            bool: Success status
            
        Cache Hierarchy:
        1. RAM NON-PERSISTENT - Memory Cache (fastest)
        2. DISKCACHE (SQLITE3) - Disk Cache (medium)
        3. POSTGRESQL - Network Database (slowest)
        """
        ttl = ttl or self.settings.get("MEM_CACHE_TTL", 3600)
        expires_at = int(time.time()) + ttl
        
        try:
            # Serialize value for disk cache
            blob = pickle.dumps(value)
            
            with self.lock:
                # Level 1: RAM NON-PERSISTENT
                self.mem_cache[key] = value
                
                # Level 2: DISKCACHE (SQLITE3)
                with self.disk_conn:
                    self.disk_conn.execute(
                        "REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                        (key, blob, expires_at)
                    )
                
                # Level 3: POSTGRESQL
                if self.db_conn:
                    try:
                        # Check if value is JSON serializable for PostgreSQL JSONB
                        if self._is_json_serializable(value):
                            # Store directly as JSONB
                            pg_query = """
                                INSERT INTO cache_entries (key, category, value, ttl)
                                VALUES ($1, $2, $3, $4)
                                ON CONFLICT (key, category) 
                                DO UPDATE SET value = EXCLUDED.value, 
                                            created_at = CURRENT_TIMESTAMP,
                                            ttl = EXCLUDED.ttl
                            """
                            self.db_conn.execute(pg_query, key, category, json.dumps(value), ttl)
                        else:
                            # For non-JSON serializable objects, store as base64 encoded binary
                            import base64
                            binary_data = base64.b64encode(blob).decode('utf-8')
                            json_value = {
                                "_binary": True,
                                "data": binary_data,
                                "format": "pickle_base64"
                            }
                            pg_query = """
                                INSERT INTO cache_entries (key, category, value, ttl)
                                VALUES ($1, $2, $3, $4)
                                ON CONFLICT (key, category) 
                                DO UPDATE SET value = EXCLUDED.value, 
                                            created_at = CURRENT_TIMESTAMP,
                                            ttl = EXCLUDED.ttl
                            """
                            self.db_conn.execute(pg_query, key, category, json.dumps(json_value), ttl)
                    except Exception as e:
                        logger.warning(f"Failed to set PostgreSQL cache: {e}")
            
            return True
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False

    def set_with_ttl(self, key, value, ttl):
        """
        Explicitly set a value with a specific TTL.
        This is an alias for the set method used by dns.py and rate_limit.py.
        
        Args:
            key: Cache key
            value: Value to store
            ttl: Time-to-live in seconds
        """
        return self.set(key, value, ttl)

    def delete(self, key, category="DEFAULT"):
        """
        Alias for invalidate, for compatibility with FormatCheck.py.
        """
        self.invalidate(key, category)

    def cleanup_expired(self):
        """
        Remove expired entries from all cache levels.
        
        Cache Cleanup:
        1. RAM NON-PERSISTENT - Auto-managed by TTLCache
        2. DISKCACHE (SQLITE3) - Manual deletion based on expires_at
        3. POSTGRESQL - Trigger-based cleanup via schema.sql
        
        Returns:
            dict: Counts of items removed from each cache level
        """
        now = int(time.time())
        results = {"disk": 0, "postgres": 0, "skipped": 0}
        
        try:
            with self.lock:
                # Level 2: DISKCACHE (SQLITE3) - Disk Cache
                with self.disk_conn:
                    # Get expired keys first
                    cursor = self.disk_conn.execute(
                        "SELECT key, expires_at FROM cache WHERE expires_at < ?", (now,)
                    )
                    keys_to_delete = []
                    skipped_keys = []
                    
                    # Check each key against processing status
                    for key, _ in cursor.fetchall():
                        if self.is_processing(key):
                            skipped_keys.append(key)
                            results["skipped"] += 1
                        else:
                            keys_to_delete.append(key)
                    
                    # Delete the non-processing expired keys
                    for key in keys_to_delete:
                        self.disk_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                        results["disk"] += 1
                    
                    if keys_to_delete:
                        logger.debug(f"Removed {len(keys_to_delete)} expired entries from disk cache")
                    if skipped_keys:
                        logger.debug(f"Skipped cleanup of {len(skipped_keys)} items that are being processed")
                
                # Level 3: PostgreSQL cleanup (with protection)
                if self.db_conn:
                    try:
                        # Get keys that would be cleaned up
                        pg_keys = self.db_conn.fetch("""
                            SELECT key FROM cache_entries 
                            WHERE ttl > 0 AND created_at + (ttl * interval '1 second') < NOW()
                        """)
                        
                        # Filter out processing keys
                        keys_to_delete = []
                        skipped_pg_keys = []
                        
                        for row in pg_keys:
                            key = row['key']
                            if self.is_processing(key):
                                skipped_pg_keys.append(key)
                                results["skipped"] += 1
                            else:
                                keys_to_delete.append(key)
                        
                        # Delete non-processing expired keys
                        if keys_to_delete:
                            placeholders = ', '.join([f"${i+1}" for i in range(len(keys_to_delete))])
                            query = f"DELETE FROM cache_entries WHERE key IN ({placeholders})"
                            self.db_conn.execute(query, *keys_to_delete)
                            results["postgres"] = len(keys_to_delete)
                            logger.debug(f"Removed {len(keys_to_delete)} expired entries from PostgreSQL cache")
                        
                        if skipped_pg_keys:
                            logger.debug(f"Skipped cleanup of {len(skipped_pg_keys)} items in PostgreSQL that are being processed")
                            
                    except Exception as e:
                        logger.debug(f"PostgreSQL cache cleanup error: {e}")
            
        except Exception as e:
            logger.warning(f"Error during cache cleanup: {e}")
            return {"error": str(e)}
        return results

    def close(self):
        """Close connections and clean up resources."""
        try:
            # Stop the cleanup timer if it exists
            if hasattr(self, '_cleanup_timer'):
                self._cleanup_timer.cancel()
                logger.debug("Stopped cache cleanup timer")
                
            self.disk_conn.close()
            logger.info("Disk cache connection closed")
        except Exception as e:
            logger.error(f"Error closing cache resources: {e}")

    # === TRANSACTION MANAGEMENT ===
    
    def begin_transaction(self):
        """
        Start a transaction across all cache levels.
        All operations between begin_transaction and commit_transaction will be atomic.
        
        Returns:
            bool: True if transaction started successfully
        """
        with self.lock:
            if self.transaction_active:
                logger.warning("Transaction already in progress")
                return False
                
            self.transaction_active = True
            self.transaction_log = []
            
            # Create savepoints for all cache levels
            self._create_savepoints()
            
            logger.debug("Cache transaction started")
            return True
    
    def commit_transaction(self):
        """
        Commit the current transaction.
        All changes will be permanently stored in all cache levels.
        
        Returns:
            bool: True if transaction committed successfully
        """
        with self.lock:
            if not self.transaction_active:
                logger.warning("No transaction in progress to commit")
                return False
            
            # PostgreSQL commit if using database
            if self.db_conn:
                try:
                    self.db_conn.commit()
                except Exception as e:
                    logger.error(f"Failed to commit PostgreSQL transaction: {e}")
                    self.rollback_transaction()
                    return False
            
            # Disk cache commit (already handled by context managers in set/invalidate)
            
            # Clear transaction state
            self.transaction_active = False
            self.transaction_log = []
            self.transaction_savepoints = {}
            
            logger.debug("Cache transaction committed")
            return True
    
    def rollback_transaction(self):
        """
        Roll back all changes made during the current transaction.
        
        Returns:
            bool: True if rollback was successful
        """
        with self.lock:
            if not self.transaction_active:
                logger.warning("No transaction in progress to roll back")
                return False
                
            # Process operations in reverse order
            for op in reversed(self.transaction_log):
                self._rollback_operation(op)
                
            # Restore savepoints
            self._restore_savepoints()
            
            # PostgreSQL rollback if using database
            if self.db_conn:
                try:
                    self.db_conn.rollback()
                except Exception as e:
                    logger.error(f"Failed to rollback PostgreSQL transaction: {e}")
            
            # Clear transaction state
            self.transaction_active = False
            self.transaction_log = []
            self.transaction_savepoints = {}
            
            logger.debug("Cache transaction rolled back")
            return True
    
    def _create_savepoints(self):
        """Create savepoints for all cache levels."""
        # Memory cache savepoint (shallow copy of keys)
        mem_keys = set(self.mem_cache.keys())
        mem_values = {k: self.mem_cache[k] for k in mem_keys if k in self.mem_cache}
        self.transaction_savepoints['memory'] = mem_values
        
        # We don't create disk or PostgreSQL savepoints here
        # Instead, we'll track operations and reverse them during rollback
    
    def _restore_savepoints(self):
        """Restore cache state from savepoints."""
        # Restore memory cache
        if 'memory' in self.transaction_savepoints:
            # Clear current memory cache
            keys_to_remove = list(self.mem_cache.keys())
            for key in keys_to_remove:
                self.mem_cache.pop(key, None)
            
            # Restore saved values
            for key, value in self.transaction_savepoints['memory'].items():
                self.mem_cache[key] = value
    
    def _track_operation(self, operation_type, key, value=None, category="DEFAULT", ttl=None):
        """Track an operation in the transaction log."""
        if self.transaction_active:
            op = {
                'type': operation_type,
                'key': key,
                'category': category,
                'timestamp': time.time()
            }
            
            # Include value and TTL for set operations
            if operation_type == 'set':
                op['value'] = value
                op['ttl'] = ttl
                
            self.transaction_log.append(op)
    
    def _rollback_operation(self, op):
        """Rollback a single operation."""
        try:
            if op['type'] == 'set':
                # Remove the key that was set
                key = op['key']
                category = op['category']
                
                # Remove from memory
                self.mem_cache.pop(key, None)
                
                # Remove from disk
                with self.disk_conn:
                    self.disk_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                
                # Remove from PostgreSQL if available
                if self.db_conn:
                    try:
                        self.db_conn.execute(
                            "DELETE FROM cache_entries WHERE key = $1 AND category = $2", 
                            key, category
                        )
                    except Exception as e:
                        logger.warning(f"Failed to rollback PostgreSQL operation: {e}")
                        
            elif op['type'] == 'invalidate':
                # The key was already in the savepoint if it existed before
                # It will be restored via _restore_savepoints()
                pass
                
        except Exception as e:
            logger.error(f"Error during operation rollback: {e}")

    # === MODIFIED CACHE OPERATIONS TO SUPPORT TRANSACTIONS ===
    
    def set(self, key, value, ttl=None, category="DEFAULT"):
        """Set value in all cache levels with transaction support."""
        ttl = ttl or self.settings.get("MEM_CACHE_TTL", 3600)
        expires_at = int(time.time()) + ttl
        
        try:
            # Track operation if in transaction
            if self.transaction_active:
                self._track_operation('set', key, value, category, ttl)
                
            # Serialize value for disk cache
            blob = pickle.dumps(value)
            
            with self.lock:
                # Level 1: RAM NON-PERSISTENT
                self.mem_cache[key] = value
                
                # Store expiry info
                self.mem_expiry[key] = {
                    'created_at': time.time(),
                    'expires_at': expires_at,
                    'ttl': ttl
                }
                
                # Level 2: DISKCACHE (SQLITE3)
                with self.disk_conn:
                    self.disk_conn.execute(
                        "REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                        (key, blob, expires_at)
                    )
                
                # Level 3: POSTGRESQL
                if self.db_conn:
                    try:
                        # Check if value is JSON serializable for PostgreSQL JSONB
                        if self._is_json_serializable(value):
                            # Store directly as JSONB
                            pg_query = """
                                INSERT INTO cache_entries (key, category, value, ttl)
                                VALUES ($1, $2, $3, $4)
                                ON CONFLICT (key, category) 
                                DO UPDATE SET value = EXCLUDED.value, 
                                            created_at = CURRENT_TIMESTAMP,
                                            ttl = EXCLUDED.ttl
                            """
                            self.db_conn.execute(pg_query, key, category, json.dumps(value), ttl)
                        else:
                            # For non-JSON serializable objects, store as base64 encoded binary
                            import base64
                            binary_data = base64.b64encode(blob).decode('utf-8')
                            json_value = {
                                "_binary": True,
                                "data": binary_data,
                                "format": "pickle_base64"
                            }
                            pg_query = """
                                INSERT INTO cache_entries (key, category, value, ttl)
                                VALUES ($1, $2, $3, $4)
                                ON CONFLICT (key, category) 
                                DO UPDATE SET value = EXCLUDED.value, 
                                            created_at = CURRENT_TIMESTAMP,
                                            ttl = EXCLUDED.ttl
                            """
                            # Fix: Use json_value instead of value for binary data
                            self.db_conn.execute(pg_query, key, category, json.dumps(json_value), ttl)
                    except Exception as e:
                        logger.warning(f"Failed to set PostgreSQL cache: {e}")
                        if self.transaction_active:
                            self.rollback_transaction()
                            return False
            
            return True
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            if self.transaction_active:
                self.rollback_transaction()
            return False

    def invalidate(self, key, category="DEFAULT"):
        """Remove key from all cache levels with transaction support."""
        try:
            # Track operation if in transaction
            if self.transaction_active:
                self._track_operation('invalidate', key, None, category)
                
            with self.lock:
                # Level 1: RAM NON-PERSISTENT - Memory Cache
                self.mem_cache.pop(key, None)
                self.mem_expiry.pop(key, None)  # remove expiry data
                
                # Level 2: DISKCACHE (SQLITE3) - Disk Cache
                with self.disk_conn:
                    self.disk_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                
                # Level 3: POSTGRESQL - Network Database
                if self.db_conn:
                    try:
                        self.db_conn.execute(
                            "DELETE FROM cache_entries WHERE key = $1 AND category = $2", 
                            key, category
                        )
                    except Exception as e:
                        logger.warning(f"PostgreSQL cache invalidate failed: {e}")
                        if self.transaction_active:
                            self.rollback_transaction()
                            return False
                            
            return True
        except Exception as e:
            logger.error(f"Cache invalidate error for key {key}: {e}")
            if self.transaction_active:
                self.rollback_transaction()
            return False

    def get_with_expiry(self, key, category="DEFAULT"):
        """
        Get value from cache hierarchy along with expiry information.
        
        Args:
            key: Cache key string
            category: Optional category for PostgreSQL organization
            
        Returns:
            tuple: (cached_value, expiry_info) where expiry_info is a dict with created_at and expires_at
        """
        expiry_info = {'created_at': None, 'expires_at': None}
        
        # Check memory cache first (L1)
        if key in self.mem_cache:
            cached_value = self.mem_cache[key]
            # Try to get expiry info from memory metadata
            if hasattr(self, 'mem_expiry') and key in self.mem_expiry:
                expiry_info = {
                    'created_at': self.mem_expiry[key].get('created_at', time.time()),
                    'expires_at': self.mem_expiry[key].get('expires_at', time.time())
                }
            logger.debug(f"Cache hit (L1-Memory): {key}")
            return cached_value, expiry_info
        
        # Check disk cache next (L2)
        try:
            with self.lock, self.disk_conn:
                cursor = self.disk_conn.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
                )
                row = cursor.fetchone()
                if row:
                    value, expires_at = row
                    # Check if expired
                    if expires_at > time.time():
                        try:
                            obj = pickle.loads(value)
                            # Estimate created_at based on expires_at and default TTL
                            ttl = self.settings.get("MEM_CACHE_TTL", 3600)
                            created_at = expires_at - ttl
                            expiry_info = {
                                'created_at': created_at,
                                'expires_at': expires_at
                            }
                            # Cache in memory for faster access next time
                            self.mem_cache[key] = obj
                            if hasattr(self, 'mem_expiry'):
                                self.mem_expiry[key] = expiry_info
                            logger.debug(f"Cache hit (L2-Disk): {key}")
                            return obj, expiry_info
                        except Exception as e:
                            logger.warning(f"Failed to load disk cache entry {key}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error accessing disk cache for {key}: {str(e)}")
        
        # If not found in disk cache, check database (L3)
        if self.db_conn:
            try:
                # Database cache implementation would go here
                pass
            except Exception as e:
                logger.warning(f"Error accessing database cache for {key}: {str(e)}")
        
        return None, expiry_info
    
    def _setup_recurring_cleanup(self):
        """Set up recurring timer to clean up expired cache entries."""
        # Get purge interval from database or use default (30 seconds)
        try:
            if self.db_conn:
                purge_interval = self.db_conn.fetchval("""
                    SELECT value::integer 
                    FROM app_settings 
                    WHERE category = 'Settings' 
                    AND sub_category = 'Cache' 
                    AND name = 'cache purge'
                """)
            else:
                purge_interval = None
        except Exception as e:
            logger.warning(f"Failed to get cache purge interval from database: {e}")
            purge_interval = None
        
        # Use default if not found in database
        if purge_interval is None:
            purge_interval = 30  # Default: 30 seconds
        
        logger.info(f"Setting up recurring cache cleanup every {purge_interval} seconds")
        
        def _cleanup_and_reschedule():
            """Internal function to perform cleanup and reschedule itself."""
            try:
                self.cleanup_expired()
                logger.debug(f"Completed scheduled cache cleanup at {datetime.now(timezone.utc)}")
            except Exception as e:
                logger.error(f"Error during scheduled cache cleanup: {e}")
            finally:
                # Reschedule next cleanup
                self._cleanup_timer = threading.Timer(purge_interval, _cleanup_and_reschedule)
                self._cleanup_timer.daemon = True  # Allow Python to exit even if timer is running
                self._cleanup_timer.start()
        
        # Start the first timer
        self._cleanup_timer = threading.Timer(purge_interval, _cleanup_and_reschedule)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def mark_processing(self, key, timeout=300):
        """
        Mark an item as being processed to prevent cleanup.
        
        Args:
            key: Cache key to protect
            timeout: Maximum time in seconds to protect this item (default: 5 minutes)
            
        Returns:
            bool: True if successfully marked
        """
        with self.processing_lock:
            # Set expiration time
            self.processing_items[key] = time.time() + timeout
            logger.debug(f"Marked {key} as processing (protected for {timeout}s)")
            return True
        
    def unmark_processing(self, key):
        """
        Remove processing mark when done.
        
        Args:
            key: Cache key to unprotect
            
        Returns:
            bool: True if key was protected and now removed, False if not found
        """
        with self.processing_lock:
            if key in self.processing_items:
                del self.processing_items[key]
                logger.debug(f"Unmarked {key} from processing")
                return True
            return False
        
    def is_processing(self, key):
        """
        Check if a key is currently being processed.
        
        Args:
            key: Cache key to check
            
        Returns:
            bool: True if key is currently being processed
        """
        with self.processing_lock:
            if key in self.processing_items:
                # Check if the lock has expired
                if time.time() > self.processing_items[key]:
                    # Auto-cleanup expired processing marks
                    del self.processing_items[key]
                    return False
                return True
            return False

    def protect_validation_keys(self, email, timeout=300):
        """
        Mark all cache keys related to an email validation as being processed to prevent cleanup.
        """
        if '@' not in email:
            logger.warning(f"Invalid email format: {email}")
            return []
            
        domain = email.split('@')[1]
        
        # List all possible cache keys used during validation - add all relevant keys
        keys_to_protect = [
            CacheKeys.validation_result(email),  # Use proper method
            CacheKeys.smtp_result(email),
            CacheKeys.smtp_banner(domain),
            CacheKeys.mx_records(domain),
            CacheKeys.format_validation(email),
            CacheKeys.disposable(domain),
            CacheKeys.blacklist(domain),
            CacheKeys.dns_records_key("MX", domain),
            CacheKeys.dns_records_key("A", domain),
            CacheKeys.spf(domain),
            CacheKeys.dkim(domain),
            CacheKeys.dmarc(domain),
            CacheKeys.a_records(domain),
            CacheKeys.ptr_record(domain) if domain.replace('.', '').isdigit() else None,
            CacheKeys.geo_info(domain) if domain.replace('.', '').isdigit() else None
        ]
        
        # Filter out None values (for conditional keys)
        keys_to_protect = [k for k in keys_to_protect if k is not None]
        
        # Mark all keys as being processed
        with self.processing_lock:
            protection_time = time.time() + timeout
            for key in keys_to_protect:
                self.processing_items[key] = protection_time
    
        logger.debug(f"Protected {len(keys_to_protect)} cache keys for {email} validation")
        return keys_to_protect

# Default settings
DEFAULT_CACHE_SETTINGS = {
    "DISK_CACHE_DIR": "./.cache",
    "MEM_CACHE_SIZE": 10000,
    "MEM_CACHE_TTL": 3600  # 1 hour default TTL
}

# Create singleton instance
try:
    cache_manager = CacheManager(DEFAULT_CACHE_SETTINGS, sync_db)
    logger.info("Cache manager initialized successfully")
except Exception as e:
    error_msg = f"Failed to load main database: {e}"
    logger.error(error_msg)
    # Create cache without PostgreSQL
    cache_manager = CacheManager(DEFAULT_CACHE_SETTINGS, None)
    logger.warning("Cache operating in local mode only (no PostgreSQL)")

def initialize_cache(settings=None):
    """
    Initialize cache with settings and database connection.
    
    Args:
        settings: Optional dictionary with cache settings
        
    Returns:
        Initialized cache_manager
    """
    global cache_manager
    
    # Use provided settings or defaults
    cache_settings = settings or DEFAULT_CACHE_SETTINGS
    
    # Check if sync_db is initialized
    if not sync_db.is_initialized():
        try:
            logger.info("Initializing database connection for cache")
            sync_db.initialize()
        except Exception as e:
            error_msg = f"Failed to load main database: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    try:
        # Create new cache manager with database connection
        cache_manager = CacheManager(cache_settings, sync_db)
        return cache_manager
    except Exception as e:
        error_msg = f"Failed to initialize cache: {e}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e