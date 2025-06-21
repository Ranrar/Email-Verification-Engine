"""
Email Verification Engine
===================================
PostgreSQL Database Handler for Email Validation Engine.
Handles connection pooling, asynchronous queries, and multi-process thread safety.
"""

import os
import asyncpg
import dotenv
import asyncio
import functools
import threading
from typing import Dict, List, Tuple, Any, Optional, Union, Callable, TypeVar, Generic, overload, AsyncGenerator
from datetime import datetime
from contextlib import asynccontextmanager
from src.managers.time import now_utc, normalize_datetime, to_iso8601, from_iso8601
from concurrent.futures import ThreadPoolExecutor
from src.managers.log import get_logger
# Set up logging
logger = get_logger()

class TimeoutHandler:
    """Utility for tracking elapsed time with proper timezone handling"""
    
    def __init__(self, timeout_seconds=None):
        self.start_time = now_utc()
        self.timeout = timeout_seconds
    
    def elapsed(self):
        """Get elapsed seconds using normalized datetimes"""
        current = now_utc()
        return (current - self.start_time).total_seconds()
    
    def is_timed_out(self):
        """Check if operation has timed out"""
        if self.timeout is None:
            return False
        return self.elapsed() > self.timeout

def ensure_event_loop(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def determine_project_root():
    """Find the project root directory containing main.py"""
    # Get the absolute path to this file (dbh.py)
    current_file = os.path.abspath(__file__)
    
    # Go up two levels: src/helpers/dbh.py -> src/ -> project_root/
    project_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    
    # Verify we found the right directory by checking for main.py
    if os.path.isfile(os.path.join(project_dir, 'main.py')):
        return project_dir
    
    # Fallback to current working directory if structure doesn't match
    return os.getcwd()

def get_database_key_path():
    """Get the path to the database key.env file"""
    project_root = determine_project_root()
    return os.path.join(project_root, 'src', 'database', 'key.env')


class DBHandler:
    """
    Asynchronous PostgreSQL database handler for EVE.
    
    Provides connection pooling, async query execution, and helper methods
    for common database operations. Thread-safe for multi-process environments.
    """
    _instance = None
    _pool = None
    _init_lock = asyncio.Lock()
    _initialized = False
    _env_loaded = False
    
    # Connection parameters
    _host = None
    _port = None
    _database = None
    _user = None
    _password = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super(DBHandler, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize database connection parameters without creating connections.
        
        Args:
            env_file (str, optional): Path to .env file with connection details.
        """
        if DBHandler._env_loaded:
            return
            
        # Use provided env_file or determine it automatically
        env_path = env_file if env_file else get_database_key_path()
        self._load_env(env_path)
    
    def _load_env(self, env_path: str) -> None:
        """
        Load database connection parameters from .env file
        
        Args:
            env_path (str): Path to .env file
        """
        try:
            if not os.path.exists(env_path):
                logger.error(f"Environment file not found: {env_path}")
                raise FileNotFoundError(f"Environment file not found: {env_path}")
            
            dotenv.load_dotenv(env_path)
            
            # Get credentials from environment - support both PG_* and POSTGRES_* formats
            self._host = os.getenv("PG_HOST") or os.getenv("POSTGRES_HOST")
            self._port = int(os.getenv("PG_PORT") or os.getenv("POSTGRES_PORT", "5432"))
            self._database = os.getenv("PG_DATABASE") or os.getenv("POSTGRES_DB") or os.getenv("PG_DB")
            self._user = os.getenv("PG_USER") or os.getenv("POSTGRES_USER")
            self._password = os.getenv("PG_PASSWORD") or os.getenv("POSTGRES_PASSWORD")
            
            if not all([self._user, self._password]):
                logger.error("Database credentials missing in environment file")
                raise ValueError("Database credentials missing in environment file")
                
            DBHandler._env_loaded = True
            logger.info(f"Database credentials loaded successfully (host: {self._host}, db: {self._database})")
            
        except Exception as e:
            logger.error(f"Error loading environment variables: {str(e)}")
            raise
    
    def _process_row_timestamps(self, row):
        """
        Process a database row to ensure all timestamp fields are properly normalized.
        
        Args:
            row: Database row (dict or Record object)
            
        Returns:
            dict: Row with normalized timestamps
        """
        if row is None:
            return None
            
        result = dict(row)
        for key, value in result.items():
            # Check if the field contains a timestamp (common field names)
            if isinstance(value, datetime) and any(ts_name in key.lower() for ts_name in 
                                                ['time', 'date', 'created', 'updated', 'timestamp']):
                result[key] = normalize_datetime(value)
        return result

    async def initialize(self, min_size: int = 1, max_size: int = 10) -> None:
        """
        Initialize connection pool.
        
        Args:
            min_size (int): Minimum number of connections in pool
            max_size (int): Maximum number of connections in pool
        """
        if self._initialized:
            return
            
        async with self._init_lock:
            if self._initialized:  # Double-check under lock
                return
                
            try:
                logger.info(f"Initializing database connection pool (min={min_size}, max={max_size})")
                
                # Create connection pool
                self._pool = await asyncpg.create_pool(
                    host=self._host,
                    port=self._port,
                    database=self._database,
                    user=self._user,
                    password=self._password,
                    min_size=min_size,
                    max_size=max_size,
                    command_timeout=60,
                    statement_cache_size=100
                )
                
                # Test connection
                async with self._pool.acquire() as conn:
                    version = await conn.fetchval("SELECT version()")
                    logger.info(f"Connected to PostgreSQL: {version}")
                
                self._initialized = True
                logger.info("Database connection pool initialized successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize database connection pool: {str(e)}")
                raise
    
    @asynccontextmanager
    async def connection(self):
        """
        Context manager for acquiring a database connection from the pool.
        
        Raises:
            RuntimeError: If the connection pool is not initialized.
        
        Yields:
            asyncpg.Connection: Database connection from the pool
        """
        if not self._initialized:
            raise RuntimeError("Database connection pool not initialized. Call initialize() first.")
            
        conn = None
        if self._pool is None:
            raise RuntimeError("Database connection pool is not initialized. Call initialize() first.")
        try:
            conn = await self._pool.acquire()
            yield conn
        finally:
            if conn is not None:
                await self._pool.release(conn)
    
    def _normalize_params(self, params: Any) -> Any:
        """Ensure all datetime parameters are timezone-aware"""
        if params is None:
            return params
        
        if isinstance(params, datetime):
            return normalize_datetime(params)
        
        if isinstance(params, (list, tuple)):
            return [self._normalize_params(item) for item in params]
        
        if isinstance(params, dict):
            return {k: self._normalize_params(v) for k, v in params.items()}
        
        return params

    async def execute(self, query: str, *args, timeout: Optional[float] = None) -> str:
        """
        Execute a query that doesn't return rows.
        
        Args:
            query (str): SQL query to execute
            *args: Query parameters
            timeout (float, optional): Query timeout in seconds
            
        Returns:
            str: Command tag string
        """
        # Normalize all datetime parameters
        args = self._normalize_params(args)
        if args is None:
            args = ()
        elif isinstance(args, (datetime, str, int, float)):
            args = (args,)
        elif not isinstance(args, (list, tuple)):
            args = (args,)

        async with self.connection() as conn:
            return await conn.execute(query, *args, timeout=timeout)
    
    async def executemany(self, query: str, args_list: List[Tuple], timeout: Optional[float] = None) -> None:
        """
        Execute query with multiple sets of parameters.
        
        Args:
            query (str): SQL query to execute
            args_list (List[Tuple]): List of parameter tuples
            timeout (float, optional): Query timeout in seconds
        """
        args_list = [self._normalize_params(args) for args in args_list]
        
        async with self.connection() as conn:
            await conn.executemany(query, args_list, timeout=timeout)
    
    async def fetch(self, query: str, *args, timeout: Optional[float] = None) -> List[Dict]:
        """
        Execute query and return all results as dictionaries.
        
        Args:
            query (str): SQL query to execute
            *args: Query parameters
            timeout (float, optional): Query timeout in seconds
            
        Returns:
            List[Dict]: Query results as list of dictionaries
        """
        args = self._normalize_params(args)
        
        async with self.connection() as conn:
            rows = await conn.fetch(query, *args, timeout=timeout)
            return [result for row in rows if (result := self._process_row_timestamps(row)) is not None]
    
    async def fetchrow(self, query: str, *args, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Execute query and return first row as dictionary.
        
        Args:
            query (str): SQL query to execute
            *args: Query parameters
            timeout (float, optional): Query timeout in seconds
            
        Returns:
            Optional[Dict]: First row as dictionary or None
        """
        try:
            args = self._normalize_params(args)
            
            async with self.connection() as conn:
                row = await conn.fetchrow(query, *args, timeout=timeout)
                return self._process_row_timestamps(row) if row else None
        except Exception as e:
            logger.error(f"Error in fetchrow: {e}, query: {query}")
            raise
    
    async def fetchval(self, query: str, *args, column: int = 0, timeout: Optional[float] = None) -> Any:
        """
        Execute query and return a single value.
        
        Args:
            query (str): SQL query to execute
            *args: Query parameters
            column (int, optional): Column index to return. Defaults to 0.
            timeout (float, optional): Query timeout in seconds
            
        Returns:
            Any: Single value from first row and specified column
        """
        args = self._normalize_params(args)
        
        async with self.connection() as conn:
            return await conn.fetchval(query, *args, column=column, timeout=timeout)
    
    # Replace the transaction method in DBHandler class
    async def transaction(self) -> AsyncGenerator[asyncpg.Connection, None]:
        """
        Start a transaction as a context manager.
        
        Example:
            ```
            async with db.transaction() as tx:
                await tx.execute("INSERT INTO users (name) VALUES ($1)", "Alice")
                await tx.execute("UPDATE counters SET value = value + 1")
            ```
        
        Returns:
            asyncpg.transaction.Transaction: Transaction context manager
        """
        if not self._initialized:
            raise RuntimeError("Database not initialized. Call initialize() first.")
            
        if self._pool is None:
            raise RuntimeError("Database connection pool is not initialized. Call initialize() first.")
        conn = await self._pool.acquire()
        tx = conn.transaction()
        try:
            await tx.start()
            # Add transaction start time tracking
            tx._eve_start_time = now_utc()
            yield conn
            await tx.commit()
            # Add transaction timing logging
            end_time = now_utc()
            duration = (end_time - tx._eve_start_time).total_seconds()
            if duration > 1.0:  # Log slow transactions
                logger.debug(f"Slow transaction completed in {duration:.2f}s")
        except Exception:
            await tx.rollback()
            raise
        finally:
            await self._pool.release(conn)
    
    async def disconnect(self):
        """Close the database connection pool."""
        if self._pool:
            try:
                # Get the current event loop to check ownership
                current_loop = asyncio.get_running_loop()
                
                # Check if pool was created on current loop
                if hasattr(self._pool, '_loop') and self._pool._loop is current_loop:
                    # Safe to close with regular await
                    await self._pool.close()
                    self._initialized = False
                    logger.info("Database connection pool closed")
                else:
                    # Just mark as closed without awaiting problematic futures
                    self._pool = None
                    self._initialized = False
                    logger.info("Database connection pool marked as closed (different loop)")
            except Exception as e:
                logger.error(f"Error closing database pool: {e}")
                raise
    
    # Higher-level API for common operations
    
    # Add table name validation to prevent SQL injection
    def _validate_table_name(self, table: str) -> str:
        """Validate table name to prevent SQL injection"""
        if not table or not isinstance(table, str):
            raise ValueError("Table name must be a non-empty string")
            
        # Only allow alphanumeric characters and underscores
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', table):
            raise ValueError(f"Invalid table name: {table}")
        
        return table

    async def insert(self, table: str, data: Dict[str, Any], return_id: bool = False) -> Optional[int]:
        """
        Insert a single row into a table.
        
        Args:
            table (str): Table name
            data (Dict): Column names and values
            return_id (bool): Return the inserted ID
            
        Returns:
            Optional[int]: ID of new record if return_id is True
        """
        table = self._validate_table_name(table)

        columns = list(data.keys())
        values = list(data.values())
        
        placeholders = [f"${i+1}" for i in range(len(values))]
        
        query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        
        if return_id:
            query += " RETURNING id"
            return await self.fetchval(query, *values)
        else:
            await self.execute(query, *values)
            return None
    
    async def update(self, table: str, data: Dict[str, Any], condition: str, *condition_args) -> str:
        """
        Update rows in a table.
        
        Args:
            table (str): Table name
            data (Dict): Column names and values to update
            condition (str): WHERE clause
            *condition_args: Arguments for the condition
            
        Returns:
            str: Command tag showing affected rows
        """
        table = self._validate_table_name(table)

        set_clause = []
        values = []
        
        # Build SET clause with parameters
        for i, (column, value) in enumerate(data.items(), 1):
            set_clause.append(f"{column} = ${i}")
            values.append(value)
        
        # Add condition parameters
        for arg in condition_args:
            values.append(arg)
        
        # Adjust placeholder indexes for condition
        placeholder_offset = len(data)
        condition_with_placeholders = condition
        for i in range(len(condition_args)):
            placeholder_index = i + placeholder_offset + 1
            condition_with_placeholders = condition_with_placeholders.replace(f"${i+1}", f"${placeholder_index}")
        
        query = f"UPDATE {table} SET {', '.join(set_clause)} WHERE {condition_with_placeholders}"
        
        return await self.execute(query, *values)
    
    async def delete(self, table: str, condition: str, *args) -> str:
        """
        Delete rows from a table.
        
        Args:
            table (str): Table name
            condition (str): WHERE clause
            *args: Arguments for the condition
            
        Returns:
            str: Command tag showing deleted rows
        """
        table = self._validate_table_name(table)

        query = f"DELETE FROM {table} WHERE {condition}"
        return await self.execute(query, *args)
    
    async def batch_insert(self, table: str, columns: List[str], values_list: List[Tuple]) -> None:
        """
        Insert multiple rows in a single operation.
        
        Args:
            table (str): Table name
            columns (List[str]): Column names
            values_list (List[Tuple]): List of value tuples
        """
        table = self._validate_table_name(table)

        placeholders = ', '.join(f'${i+1}' for i in range(len(columns)))
        query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        
        await self.executemany(query, values_list)
    
    async def get_by_id(self, table: str, id_value: int, id_column: str = "id") -> Optional[Dict]:
        """
        Get a record by ID.
        
        Args:
            table (str): Table name
            id_value (int): ID value to look up
            id_column (str, optional): ID column name. Defaults to "id".
            
        Returns:
            Optional[Dict]: Record as dictionary or None
        """
        table = self._validate_table_name(table)

        query = f"SELECT * FROM {table} WHERE {id_column} = $1"
        return await self.fetchrow(query, id_value)
    
    async def list_records(self, 
                          table: str, 
                          conditions: Optional[Dict] = None,
                          order_by: Optional[str] = None,
                          limit: Optional[int] = None,
                          offset: Optional[int] = None) -> List[Dict]:
        """
        List records with flexible filtering.
        
        Args:
            table (str): Table name
            conditions (Dict, optional): Column:value pairs for WHERE conditions
            order_by (str, optional): ORDER BY clause
            limit (int, optional): LIMIT clause
            offset (int, optional): OFFSET clause
            
        Returns:
            List[Dict]: Query results
        """
        table = self._validate_table_name(table)

        query = f"SELECT * FROM {table}"
        params = []
        
        # Add WHERE conditions
        if conditions:
            where_clauses = []
            for i, (column, value) in enumerate(conditions.items(), 1):
                where_clauses.append(f"{column} = ${i}")
                params.append(value)
                
            query += f" WHERE {' AND '.join(where_clauses)}"
        
        # Add ORDER BY
        if order_by:
            query += f" ORDER BY {order_by}"
            
        # Add LIMIT and OFFSET
        if limit is not None:
            query += f" LIMIT ${len(params) + 1}"
            params.append(limit)
            
        if offset is not None:
            query += f" OFFSET ${len(params) + 1}"
            params.append(offset)
            
        return await self.fetch(query, *params)
    
    def is_initialized(self) -> bool:
        """Check if database connection pool is initialized"""
        return self._initialized

    def wait_until_initialized(self, timeout=10):
        """Block until the database connection pool is initialized or timeout."""
        import time
        start_time = now_utc()
        while not self._initialized:
            current_time = now_utc()
            if (current_time - start_time).total_seconds() > timeout:
                raise TimeoutError("DBHandler initialization timed out")
            time.sleep(0.05)


class SyncDBHandler:
    """Synchronous wrapper for the async DBHandler using a dedicated event loop thread."""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize the sync wrapper without creating connections"""
        self._db = DBHandler(env_file=env_file)
        self._lock = threading.Lock()
        self._executor = None
        self._last_results = []
        self._initialized = False

        # Dedicated event loop in a background thread
        self._loop = None
        self._loop_thread = threading.Thread(target=self._start_loop, daemon=True)
        self._loop_started = threading.Event()
        self._loop_thread.start()
        self._loop_started.wait(timeout=10)
        if not self._loop or not self._loop.is_running():
            raise RuntimeError("Failed to start background event loop for SyncDBHandler")

    def _start_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop_started.set()
        self._loop.run_forever()

    def _run_async(self, coro):
        """Submit coroutine to the dedicated event loop and wait for result."""
        if not self._loop or not self._loop.is_running():
            raise RuntimeError("Event loop is not running")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=30)
        except asyncio.TimeoutError:
            fut.cancel()
            raise TimeoutError("Database operation timed out after 30 seconds")

    def initialize_executor(self, max_workers=8):
        """Initialize the thread pool executor - called from Initialization.py"""
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix="db_worker"
                )
                self._initialized = True
                logger.info(f"Initialized database thread pool with {max_workers} workers")
                return True
            return False

    def is_initialized(self) -> bool:
        """Check if database handler is initialized"""
        return self._initialized and self._db.is_initialized()

    def get_connection(self):
        """Return the database connection handler (self)"""
        if not self.is_initialized():
            raise RuntimeError("Database not initialized. Initialize through Initialization.py first.")
        return self

    def _get_executor(self):
        """Get the thread pool executor"""
        if self._executor is None:
            raise RuntimeError("Database executor not initialized. Call initialize_executor() first.")
        return self._executor

    def _ensure_db_initialized(self):
        """Check if database is initialized and raise a more specific error if not"""
        if not self.is_initialized():
            # Change from error to debug to reduce log noise during startup
            logger.debug("SyncDBHandler: DBHandler not initialized. Call db.initialize() first.")
            raise RuntimeError("Database connection pool not initialized. Call db.initialize() first.")

    def _normalize_params(self, args):
        """
        Normalize datetime parameters to ensure timezone awareness.
        
        Args:
            args: Query parameters
            
        Returns:
            List of normalized parameters
        """
        if not args:
            return args
            
        normalized_args = []
        for arg in args:
            if isinstance(arg, datetime) and arg.tzinfo is None:
                normalized_arg = normalize_datetime(arg)
                logger.debug(f"Auto-normalized naive datetime parameter: {arg} → {normalized_arg}")
                normalized_args.append(normalized_arg)
            else:
                normalized_args.append(arg)
                
        return normalized_args

    def fetch(self, query, *args):
        """
        Fetch multiple rows from the database with parameter normalization.
        All datetime parameters are automatically normalized to timezone-aware.
        """
        normalized_args = self._normalize_params(args)
        return self._run_async(self._db.fetch(query, *normalized_args))

    def fetchrow(self, query, *args):
        """
        Fetch a single row from the database with parameter normalization.
        All datetime parameters are automatically normalized to timezone-aware.
        """
        normalized_args = self._normalize_params(args)
        return self._run_async(self._db.fetchrow(query, *normalized_args))

    def fetchval(self, query, *args):
        """
        Fetch a single value from the database with parameter normalization.
        All datetime parameters are automatically normalized to timezone-aware.
        """
        normalized_args = self._normalize_params(args)
        return self._run_async(self._db.fetchval(query, *normalized_args))

    def execute(self, query, *args):
        """
        Execute a SQL query with parameters.
        All datetime parameters are automatically normalized to timezone-aware.
        """
        normalized_args = self._normalize_params(args)
        return self._run_async(self._db.execute(query, *normalized_args))

    def fetch_all(self, query, *args, **kwargs):
        """Alias for fetch to maintain compatibility with other code"""
        return self.fetch(query, *args, **kwargs)

    def initialize(self, min_size=2, max_size=8):
        """Initialize the database connection pool in the dedicated event loop."""
        try:
            logger.info(f"Initializing database connection pool (min={min_size}, max={max_size})")
            result = self._run_async(self._db.initialize(min_size=min_size, max_size=max_size))
            return result
        except Exception as e:
            logger.error(f"Failed to initialize sync database handler: {e}")
            raise

    def shutdown(self) -> bool:
        """Shutdown the thread pool and event loop safely"""
        try:
            if self._executor is not None:
                self._executor.shutdown(wait=True)
                self._executor = None
                logger.info("Database thread pool shut down")
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(self._loop.stop)
                logger.info("Database event loop shut down")
            return True
        except Exception as e:
            logger.error(f"Error shutting down database handler: {e}")
            return False

    def disconnect(self):
        """Disconnect the database connection pool."""
        try:
            # Check if the event loop is running before attempting to run async code
            if self._loop and self._loop.is_running():
                self._run_async(self._db.disconnect())
                logger.info("Database connection pool closed")
                return True
            else:
                # Just directly mark the pool as closed without running coroutines
                self._db._pool = None
                self._db._initialized = False
                logger.info("Database connection pool marked as closed (loop not running)")
                return True
        except Exception as e:
            logger.error(f"Error disconnecting database: {e}")
            return False

# Create singleton instance for import by other modules
sync_db = SyncDBHandler()

# If this is imported elsewhere, only one instance will be created
__all__ = ['sync_db', 'DBHandler', 'SyncDBHandler']