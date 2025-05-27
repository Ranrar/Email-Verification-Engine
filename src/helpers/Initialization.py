"""
Email Verification Engine
===================================
Eel-based initialization system for starting the applications functions
"""
import eel
import time
import traceback
from concurrent.futures.process import BrokenProcessPool
from src.managers.log import Axe
from src.managers.cache import cache_manager
from src.helpers.dbh import sync_db
from src.managers.time import time_function_call, normalize_datetime, now_utc

logger = Axe()

# Global components registry
_components = {}

class InitializationError(Exception):
    pass

class InitQueue:
    """Simple FIFO queue for initialization tasks with Eel progress reporting."""
    def __init__(self):
        self.tasks = []

    def add(self, func, name=None):
        self.tasks.append((func, name or func.__name__))

    def run(self):
        total_steps = len(self.tasks)
        
        for idx, (func, name) in enumerate(self.tasks):
            step_num = idx + 1
            percent = int((step_num / total_steps) * 100)
            
            # Update the UI via Eel
            try:
                eel.updateInitProgress(step_num, total_steps, f"Running: {name}", percent) # type: ignore
            except Exception as e:
                logger.error(f"Failed to update UI: {e}")
            
            logger.info(f"[INIT] Running: {name} ...")
            
            try:
                # Use time_function_call to get execution time
                result, elapsed_ms = time_function_call(func)
                logger.info(f"[INIT] Done: {name} in {elapsed_ms:.2f}ms")
                
                # Add a small delay for UI updates to be visible
                time.sleep(0.3)
                
            except Exception as e:
                logger.error(f"[INIT] FAILED: {name} - {e}")
                traceback.print_exc()
                
                # Update UI with error
                try:
                    eel.updateInitProgress(step_num, total_steps, f"FAILED: {name} - {str(e)}", percent) # type: ignore
                except:
                    pass
                
                raise InitializationError(f"Initialization failed at step: {name}") from e

def is_db_ready():
    """Quietly check if database is initialized without logging errors"""
    try:
        return sync_db.is_initialized()
    except Exception:
        return False

# Define all the initialization functions from the original file
def initialize_database_pool_and_executor():
    """Initialize database pool in the dedicated event loop and set up thread executor."""
    # Initialize in the dedicated event loop
    sync_db.initialize(min_size=2, max_size=8)
    
    # Initialize thread pool executor
    sync_db.initialize_executor(max_workers=8)
    
    logger.info("Database pools and executors initialized")

def load_settings_to_memory():
    logger.info("Loading settings tables into memory...")
    settings_tables = [
        "app_settings",
        "confidence_levels",
        "executor_pool_settings",
        "dns_settings",
        "email_filter_regex_settings",
        "black_white",
        "ports",
        "rate_limit",
        "validation_scoring",
        "executor_pool_presets"
    ]
    for table in settings_tables:
        try:
            logger.debug(f"Loading table: {table}")
            rows = sync_db.fetch(f"SELECT * FROM {table}")
            cache_manager.set(f"startup:{table}", rows)
            logger.info(f"Loaded {table} into memory/cache.")
        except Exception as e:
            logger.warning(f"[INIT] Warning: Failed to load {table}: {e}")

def load_settings_to_diskcache():
    """
    Load settings tables from database directly into disk cache with no TTL.
    This ensures settings persist indefinitely even after application restart.
    """
    logger.info("Loading settings tables into disk cache for long-term persistence...")
    settings_tables = [
        "app_settings",
        "confidence_levels",
        "executor_pool_settings",
        "dns_settings",
        "email_filter_regex_settings",
        "black_white",
        "ports",
        "rate_limit",
        "validation_scoring",
        "executor_pool_presets"
    ]
    
    for table in settings_tables:
        try:
            logger.debug(f"Loading table to disk cache: {table}")
            rows = sync_db.fetch(f"SELECT * FROM {table}")
            
            if rows:
                # Store in disk cache with no TTL for permanent persistence
                cache_manager.set(
                    f"diskcache:{table}",
                    rows,
                    ttl=0,  # No expiration
                    category="persistent_disk_cache"
                )
                logger.info(f"Stored {table} in disk cache with {len(rows)} rows (permanent storage)")
            else:
                logger.warning(f"No data found in {table} for disk caching")
                
        except Exception as e:
            logger.warning(f"[INIT] Warning: Failed to load {table} to disk cache: {e}")
    
    logger.info("Settings tables loaded into disk cache with permanent persistence")

def cache_blackwhite_list():
    """Cache permanent black/white list entries."""
    logger.info("Caching permanent blacklist/whitelist entries...")
    try:
        # Query the new black_white table
        rows = sync_db.fetch("SELECT * FROM black_white")
        
        # Cache each entry
        for row in rows:
            domain = row.get('domain')
            if domain:
                # Cache with the domain as part of the key
                cache_key = f"blackwhite:{domain}"
                cache_manager.set(cache_key, row)
                logger.debug(f"Cached {row.get('category', 'unknown')} entry: {domain}")
                
        logger.info(f"Successfully cached {len(rows)} black/white list entries")
    except Exception as e:
        logger.error(f"Failed to cache black/white list entries: {e}")
        # Don't raise the exception - this is non-critical functionality
        # Just log it and continue with initialization

# Keep the same benchmark functions from the original file
def benchmark_cpu_time():
    """Run the CPU benchmark directly."""
    from src.managers.executor import cpu_benchmark
    
    logger.info("Running CPU benchmark...")
    result, elapsed_ms = time_function_call(cpu_benchmark, 5.0)
    cache_manager.set("benchmark:cpu_ops", result)
    logger.info(f"CPU benchmark completed in {elapsed_ms:.2f}ms")
    return elapsed_ms

def benchmark_disk_time():
    """Run the disk benchmark directly."""
    from src.managers.executor import disk_benchmark
    
    logger.info("Running disk benchmark...")
    result, elapsed_ms = time_function_call(disk_benchmark, 5.0)
    cache_manager.set("benchmark:disk_single", result["single_thread"])
    cache_manager.set("benchmark:disk_multi", result["multi_thread"])
    logger.info(f"Disk benchmark completed in {elapsed_ms:.2f}ms")
    return elapsed_ms

def benchmark_sql_time():
    """Run the SQL benchmark directly."""
    from src.managers.executor import sql_benchmark
    
    logger.info("Running SQL benchmark...")
    result, elapsed_ms = time_function_call(sql_benchmark, 5.0)
    # Store the actual results
    cache_manager.set("benchmark:sql_single", result["single_thread"])
    cache_manager.set("benchmark:sql_multi", result["multi_thread"])
    logger.info(f"SQL benchmark completed in {elapsed_ms:.2f}ms")
    return elapsed_ms

def benchmark_net_time():
    """Run the network benchmark directly."""
    from src.managers.executor import network_benchmark
    
    logger.info("Running network benchmark...")
    result, elapsed_ms = time_function_call(network_benchmark, 5.0)
    # Store the actual results
    cache_manager.set("benchmark:network_single", result["single_thread"])
    cache_manager.set("benchmark:network_multi", result["multi_thread"])
    logger.info(f"Network benchmark completed in {elapsed_ms:.2f}ms")
    return elapsed_ms

def benchmark_process_time():
    """Run the process overhead benchmark directly with improved error handling."""
    from src.managers.executor import process_benchmark
    import multiprocessing as mp
    
    logger.info("Measuring process overhead...")
    
    try:
        # Try to import these safely
        from src.managers.executor import ProcessPoolexecutor, run_benchmark
        
        # We need to use a ProcessPoolExecutor for the process benchmark
        with ProcessPoolexecutor(
            max_workers=1,
            initializer=run_benchmark,
            mp_context=mp.get_context('spawn')
        ) as executor:
            try:
                result, elapsed_ms = time_function_call(process_benchmark, 2)
                # Store the actual result
                cache_manager.set("benchmark:process_overhead", result)
                logger.info(f"Process overhead measurement completed in {elapsed_ms:.2f}ms")
                return result
            except (RuntimeError, BrokenProcessPool) as e:
                logger.warning(f"Process benchmark failed: {e}")
                # Provide a reasonable default when benchmarking fails
                default_value = 0.2  # 200ms overhead is a conservative default
                cache_manager.set("benchmark:process_overhead", default_value)
                logger.info(f"Using default process overhead value: {default_value}")
                return default_value
    except Exception as e:
        logger.error(f"Failed to initialize process pool for benchmarking: {e}")
        # Provide a reasonable default 
        default_value = 0.2
        cache_manager.set("benchmark:process_overhead", default_value)
        logger.info(f"Using default process overhead value: {default_value}")
        return default_value

def initialize_thread_pool():
    """Initialize the thread pool with appropriate settings"""
    from src.managers.executor import thread_pool
    
    logger.info("Initializing thread pool...")
    # Initialize thread pool with settings from database
    thread_pool.get_instance(initialize_now=True)
    
    # Register in components registry
    if 'executors' not in _components:
        _components['executors'] = {}
    _components['executors']['thread_pool'] = thread_pool
    
    logger.info(f"Thread pool initialized with {thread_pool.max_workers} workers")

def initialize_time_manager():
    """Initialize time manager and create required stats categories"""
    from src.managers.time import TimeManager
    
    logger.info("Initializing time manager and required stats categories...")
    time_manager = TimeManager()
    
    # Create all required stats categories
    required_categories = [
        'format_validation', 'domain_mx', 'auth_sec', 'smtp', 
        'additional', 'total', 'basic_format', 'normalization',
        'length_limits', 'email_validation', 'cache_hits'
    ]
    
    for category in required_categories:
        time_manager.create_stats(category)
    
    # Register in components registry
    if 'managers' not in _components:
        _components['managers'] = {}
    _components['managers']['time'] = time_manager
    
    logger.info(f"Time manager initialized with {len(required_categories)} stats categories")

def initialize_dns_manager():
    """Initialize DNS manager with settings from database"""
    from src.managers.dns import DNSManager
    
    logger.info("Initializing DNS manager...")
    dns_manager = DNSManager()
    dns_manager._load_dns_settings()
    
    # Register in components registry
    if 'managers' not in _components:
        _components['managers'] = {}
    _components['managers']['dns'] = dns_manager
    
    logger.info("DNS manager initialized with settings from database")

def initialize_port_manager():
    """Initialize port manager with settings from database"""
    from src.managers.port import PortManager
    
    logger.info("Initializing port manager...")
    port_manager = PortManager()
    port_manager._load_smtp_ports()
    port_manager._load_dns_ports()
    port_manager._load_auth_ports()
    port_manager._load_mail_ports()
    
    # Register in components registry
    if 'managers' not in _components:
        _components['managers'] = {}
    _components['managers']['port'] = port_manager
    
    logger.info("Port manager initialized with settings from database")

def initialize_rate_manager():
    """Initialize rate limit manager with settings from database"""
    from src.managers.rate_limit import RateLimitManager
    
    logger.info("Initializing rate limit manager...")
    rate_manager = RateLimitManager()
    rate_manager._load_cache_limits()
    rate_manager._load_additional_limits()
    rate_manager._load_auth_security_limits()
    rate_manager._load_dom_mx_limits()
    rate_manager._load_smtp_limits()
    
    # Register in components registry
    if 'managers' not in _components:
        _components['managers'] = {}
    _components['managers']['rate'] = rate_manager
    
    logger.info("Rate limit manager initialized with settings from database")

def initialize_email_format_check():
    """Initialize email format check component directly from database"""
    from src.engine.formatcheck import EmailFormat, LoadRegexPresets, regex_factory, sanitize_regex
    from src.helpers.dbh import sync_db
    import re
    
    logger.info("Initializing email format check component from database...")
    
    # Load configuration directly from database
    config_loader = LoadRegexPresets(sync_db)
    config = config_loader.fetch_email_regex_config(refresh=True)
    
    # Pre-validate regex patterns to catch compilation errors
    custom_patterns = config.get('custom_patterns', {})
    if custom_patterns:
        logger.debug(f"Validating regex patterns: {list(custom_patterns.keys())}")
        for pattern_name, pattern_str in custom_patterns.items():
            try:
                # Try to compile each regex pattern
                test_pattern = re.compile(sanitize_regex(pattern_str))
                # Test basic patterns with sample data
                if pattern_name == 'basic':
                    sample_emails = ['user@example.com', 'test.user@domain.co.uk']
                    for email in sample_emails:
                        if not test_pattern.match(email):
                            logger.warning(f"Pattern '{pattern_name}' compiled successfully but doesn't match valid email '{email}'")
                
                logger.debug(f"Successfully compiled pattern '{pattern_name}': {pattern_str}")
            except re.error as e:
                logger.error(f"Failed to compile regex pattern '{pattern_name}': {pattern_str}")
                logger.error(f"Regex compilation error: {e}")
                
                # Try to fix common over-escaping issues using the built-in sanitize function
                fixed_pattern = sanitize_regex(pattern_str)
                if fixed_pattern != pattern_str:
                    logger.info(f"Attempting to fix pattern: {fixed_pattern}")
                    try:
                        re.compile(fixed_pattern)
                        logger.info(f"Fixed pattern compiles successfully!")
                        custom_patterns[pattern_name] = fixed_pattern
                    except re.error:
                        pass
                
                # If we couldn't fix it automatically, raise a clear error
                if pattern_name == 'basic':
                    raise InitializationError(f"Email format checking will fail - regex pattern '{pattern_name}' is invalid: {e}")
    
    # Create format checker with the loaded configuration (potentially fixed)
    # Use the factory function instead of direct instantiation
    format_checker = EmailFormat(config)
    
    # Register in components registry
    if 'formatters' not in _components:
        _components['formatters'] = {}
    _components['formatters']['email'] = format_checker
    
    # For backward compatibility with existing code
    if 'filters' not in _components:
        _components['filters'] = {}
    _components['filters']['validation'] = format_checker
    _components['validation_filter'] = format_checker
    _components['intake_filter'] = format_checker
        
    logger.info("Email format check component loaded from database")

def initialize_dynamic_queue():
    """Initialize the database-driven validation queue"""
    from src.engine.queue import DynamicQueue
    
    logger.info("Initializing dynamic validation queue...")
    queue = DynamicQueue.get_instance()
    
    # Register in components registry
    if 'engine_components' not in _components:
        _components['engine_components'] = {}
    _components['engine_components']['validation_queue'] = queue
    
    logger.info(f"Validation queue initialized with {len(queue.execution_order)} functions")
    
    return queue

def initialize_engine_components():
    """Initialize all engine components without fallbacks"""
    from src.engine.engine import validate_email
    from src.managers.executor import thread_pool
    
    logger.info("Initializing engine components...")
    
    # Get required components from registry
    dns_manager = _components.get('managers', {}).get('dns')
    port_manager = _components.get('managers', {}).get('port')
    rate_manager = _components.get('managers', {}).get('rate')
    time_manager = _components.get('managers', {}).get('time')
    
    logger.info("Engine components initialized")

def get_components():
    """Return the components registry"""
    return _components

def initialize_process_pool():
    """Initialize the process pool with benchmark initializer"""
    from src.managers.executor import process_pool
    
    logger.info("Initializing process pool with worker benchmarking...")
    # Initialize the process pool with the benchmark function
    process_pool.get_instance(initialize_now=True)
    logger.info("Process pool initialized with worker benchmarks")

def analyze_and_apply_settings(benchmark_results):
    """Apply settings to DB based on benchmark results"""
    import psutil
    from src.managers.executor import update_executor_settings
    
    logger.info("Analyzing benchmark results and calculating optimal settings...")
    
    # Get CPU information
    logical_cpus = psutil.cpu_count(logical=True) or 1
    
    # Extract relevant benchmark results with defaults to prevent NoneType errors
    cpu_ops = benchmark_results.get("cpu_ops", 0) or 0
    disk_single = benchmark_results.get("disk_single", 0) or 0
    disk_multi = benchmark_results.get("disk_multi", 0) or 0
    process_overhead = benchmark_results.get("process_overhead", 0.2) or 0.2
    
    # Debug output to see what we're working with
    logger.info(f"Benchmark results: cpu={cpu_ops}, disk_single={disk_single}, disk_multi={disk_multi}, process={process_overhead}")
    
    # Calculate recommended settings using the same logic as auto_tune
    if disk_multi > disk_single * 3:
        max_threads = logical_cpus * 8
    else:
        max_threads = logical_cpus * 4

    if process_overhead < 0.1:
        max_processes = max(2, logical_cpus)
    else:
        max_processes = max(1, logical_cpus // 2)

    min_threads = max(2, max_threads // 4)
    min_processes = max(1, max_processes // 2)

    if process_overhead > 0.3:
        max_tasks = 50
    else:
        max_tasks = 100
    
    # Prepare settings dict
    settings = {
        "max_worker_threads": max_threads,
        "min_worker_threads": min_threads,
        "max_processes": max_processes,
        "min_processes": min_processes,
        "process_timeout": 300,
        "max_tasks_per_process": max_tasks
    }
    
    # Apply settings to database
    logger.info(f"Applying calculated settings to database: {settings}")
    success = update_executor_settings(settings)
    
    if not success:
        logger.error("Failed to apply calculated settings")
    else:
        logger.info("Successfully applied settings to database")
    
    return settings

def collect_and_apply_settings():
    """Collect benchmark results, log them to DB with run_type 'startup', and apply settings"""
    from src.helpers.dbh import sync_db
    import json
    
    # Collect benchmark results
    benchmark_results = {
        "cpu_ops": cache_manager.get("benchmark:cpu_ops") or 0,
        "disk_single": cache_manager.get("benchmark:disk_single") or 0,
        "disk_multi": cache_manager.get("benchmark:disk_multi") or 0,
        "sql_single": cache_manager.get("benchmark:sql_single") or 0,
        "sql_multi": cache_manager.get("benchmark:sql_multi") or 0,
        "network_single": cache_manager.get("benchmark:network_single") or 0,
        "network_multi": cache_manager.get("benchmark:network_multi") or 0,
        "process_overhead": cache_manager.get("benchmark:process_overhead") or 0.2
    }
    
    # Log these benchmark results to the database with run_type="startup"
    try:
        logger.info("Logging benchmark results to database with run_type 'startup'")
        sync_db.execute(
            """
            INSERT INTO executor_pool_benchmark_log 
            (run_type, benchmark_results, notes) 
            VALUES ($1, $2, $3)
            """,
            "startup",
            json.dumps(benchmark_results),
            "Automatic benchmark during system startup"
        )
        logger.info("Successfully logged benchmark results to database")
    except Exception as e:
        logger.error(f"Failed to log benchmark results to database: {e}")
    
    # Analyze and apply settings
    return analyze_and_apply_settings(benchmark_results)

def start_initialization_process():
    """Main function to run initialization with Eel UI updates"""
    logger.info("Starting initialization process with Eel UI...")
    
    try:
        # Create initialization queue
        q = InitQueue()
        
        # Database connectivity
        q.add(initialize_database_pool_and_executor, "Connect to Database")
        q.add(load_settings_to_memory, "Loading Settings to Memory")
        q.add(load_settings_to_diskcache, "Loading Settings to Disk Cache")
        q.add(cache_blackwhite_list, "Caching Black/White List")
        
        # Check if benchmarking is enabled in app_settings
        enable_benchmarking = True  # Default to True if setting not found
        try:
            benchmark_settings = sync_db.fetch(
                """
                SELECT value FROM app_settings 
                WHERE category = 'Settings' AND sub_category = 'Start' AND name = 'Enable'
                """
            )
            benchmark_setting = benchmark_settings[0] if benchmark_settings else None
            if benchmark_setting and benchmark_setting.get('value') == '0':
                enable_benchmarking = False
                logger.info("Auto-benchmark during startup is disabled via settings")
        except Exception as e:
            logger.warning(f"Could not fetch benchmark setting: {e}, defaulting to enabled")
               
        # Benchmarking - only add if enabled
        if enable_benchmarking:
            q.add(benchmark_cpu_time, "Running CPU benchmark")
            q.add(benchmark_disk_time, "Running disk benchmark")
            q.add(benchmark_sql_time, "Running SQL benchmark")
            q.add(benchmark_net_time, "Running network benchmark")
            q.add(benchmark_process_time, "Measuring process overhead")
            
            # Settings analysis and application
            q.add(collect_and_apply_settings, "Applying optimal settings")
        else:
            logger.info("Skipping benchmarks during startup as per settings")
        
        # Initialize components - always needed
        q.add(initialize_process_pool, "Initializing Process Pool")
        q.add(initialize_thread_pool, "Initializing Thread Pool")
        q.add(initialize_time_manager, "Initializing Time Manager")
        q.add(initialize_dns_manager, "Initializing DNS Manager")
        q.add(initialize_port_manager, "Initializing Port Manager")
        q.add(initialize_rate_manager, "Initializing Rate Limit Manager")
        q.add(initialize_email_format_check, "Initializing Email Format Check")
        q.add(initialize_dynamic_queue, "Initializing Validation Queue")
        q.add(initialize_engine_components, "Initializing Engine Components")
        
        # Run all initialization steps
        q.run()
        
        # Signal completion to the UI
        eel.updateInitProgress(len(q.tasks), len(q.tasks), "Initialization complete!", 100) # type: ignore
        time.sleep(1)  # Short delay
        eel.initializationComplete() # type: ignore
        
        logger.info("Initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        # Update UI with the failure
        try:
            eel.updateInitProgress(0, 0, f"Fatal error: {str(e)}", 100) # type: ignore
        except:
            pass
        # Don't exit here, let the main thread handle it