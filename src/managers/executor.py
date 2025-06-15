"""
Email Verification Engine
===================================
Thread & Process Poolexecutor Module
"""
import asyncio
import functools
import os
import tempfile
import time
import json
import threading
import statistics
import argparse
import platform
from concurrent.futures import ThreadPoolExecutor as ThreadPoolexecutor, wait, as_completed
from concurrent.futures import ProcessPoolExecutor as ProcessPoolexecutor
import psutil
import requests

from src.managers.log import get_logger
from src.helpers.dbh import sync_db
from src.managers.benchmark import run_benchmark

# Add the decorator after the imports and before the logging utilities section
# ────────────────────────────── EVENT LOOP UTILITIES ──────────────────────────────
def ensure_event_loop(func):
    """Decorator to ensure an event loop exists in the current thread."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # Create and set a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return func(*args, **kwargs)
    return wrapper

# Set up logging
logger = get_logger()

# Define test paths
TEST_FILE_PATH = os.path.join(tempfile.gettempdir(), "tg_io.bin")
TEST_SQL_QUERY = "SELECT 1"

# ────────────────────────────── LOGGING UTILITIES ──────────────────────────────
def log_function_entry(func_name, **params):
    """Log function entry with parameters"""
    param_str = ', '.join(f'{k}={v}' for k, v in params.items())
    logger.debug(f"ENTER: {func_name}({param_str})")

def log_function_exit(func_name, result=None):
    """Log function exit with optional result"""
    if result is not None:
        # Don't log entire result objects for brevity
        if isinstance(result, dict) and len(result) > 3:
            result_str = f"dict with {len(result)} items"
        else:
            result_str = str(result)
        logger.debug(f"EXIT: {func_name} -> {result_str}")
    else:
        logger.debug(f"EXIT: {func_name}")

def log_benchmark_start(benchmark_name, duration):
    """Log benchmark start"""
    logger.info(f"Starting {benchmark_name} benchmark (duration: {duration}s)")

def log_benchmark_end(benchmark_name, result):
    """Log benchmark end"""
    logger.info(f"Completed {benchmark_name} benchmark: {result}")

def log_benchmark_to_db(results, run_type="manual", notes=None):
    """Log benchmark results to the database."""
    try:
        sync_db.execute(
            "INSERT INTO executor_pool_benchmark_log (run_type, benchmark_results, notes) VALUES ($1, $2, $3)",
            run_type, json.dumps(results), notes
        )
        logger.info(f"Benchmark results logged to DB (type={run_type})")
    except Exception as e:
        logger.error(f"Failed to log benchmark results: {e}")

# Helper function for empty operation (process overhead measurement)
def noop():
    """Function that does nothing, used for process overhead measurement"""
    return None

# ────────────────────────────── BENCHMARK FUNCTIONS ──────────────────────────────

def cpu_benchmark(duration=5.0):
    """Run a CPU benchmark for specified duration"""
    log_function_entry('cpu_benchmark', duration=duration)
    log_benchmark_start('CPU', duration)
    
    def cpu_task():
        sum(i*i for i in range(10000))
        
    count = 0
    end_time = time.perf_counter() + duration
    while time.perf_counter() < end_time:
        cpu_task()
        count += 1
    
    result = count / duration
    log_benchmark_end('CPU', f"{result:.1f} ops/sec")
    log_function_exit('cpu_benchmark', result)
    return result

def disk_benchmark(duration=5.0):
    """Run a disk I/O benchmark for specified duration"""
    log_function_entry('disk_benchmark', duration=duration)
    log_benchmark_start('Disk I/O', duration)
    
    # Create test file
    with open(TEST_FILE_PATH, 'wb') as f:
        f.write(os.urandom(16 * 1024 * 1024))  # 16MB test file
    
    def io_op():
        with open(TEST_FILE_PATH, 'rb') as f:
            return f.read(4096)
    
    count = 0
    end_time = time.perf_counter() + duration
    while time.perf_counter() < end_time:
        io_op()
        count += 1
    
    # Test with threads
    thread_ops = 0
    with ThreadPoolexecutor(max_workers=8) as ex:
        futures = []
        start = time.perf_counter()
        while time.perf_counter() - start < 2.0:  # 2-second test
            futures.append(ex.submit(io_op))
            if len(futures) > 100:  # Limit queue size
                # Fix: Store the result of wait() properly
                done, not_done = wait(futures, return_when="FIRST_COMPLETED")
                thread_ops += len(done)
                # Update futures to only contain not_done tasks
                futures = list(not_done)
    
    # Clean up
    try:
        os.remove(TEST_FILE_PATH)
    except Exception as e:
        logger.warning(f"Failed to remove temporary file: {e}")
    
    result = {"single_thread": count / duration, "multi_thread": thread_ops / 2.0}
    log_benchmark_end('Disk I/O', f"ST: {result['single_thread']:.1f} MT: {result['multi_thread']:.1f} ops/sec")
    log_function_exit('disk_benchmark', result)
    return result

def sql_benchmark(duration=5.0):
    """Run a SQL benchmark for specified duration"""
    log_function_entry('sql_benchmark', duration=duration)
    log_benchmark_start('SQL', duration)
    
    try:
        count = 0
        end_time = time.perf_counter() + duration
        while time.perf_counter() < end_time:
            sync_db.fetch(TEST_SQL_QUERY)
            count += 1
            
        # Test with threads
        thread_ops = 0
        with ThreadPoolexecutor(max_workers=8) as ex:
            futures = []
            start = time.perf_counter()
            while time.perf_counter() - start < 2.0:  # 2-second test
                futures.append(ex.submit(sync_db.fetch, TEST_SQL_QUERY))
                if len(futures) > 20:  # Limit connections
                    done, not_done = wait(futures, return_when="FIRST_COMPLETED")
                    thread_ops += len(done)
                    futures = list(not_done)
        
        result = {"single_thread": count / duration, "multi_thread": thread_ops / 2.0}
        log_benchmark_end('SQL', f"ST: {result['single_thread']:.1f} MT: {result['multi_thread']:.1f} queries/sec")
        log_function_exit('sql_benchmark', result)
        return result
    
    except Exception as e:
        logger.error(f"SQL benchmark error: {e}")
        log_function_exit('sql_benchmark', {"single_thread": 0, "multi_thread": 0})
        return {"single_thread": 0, "multi_thread": 0}

def network_benchmark(duration=5.0, url="https://www.google.com"):
    """Run a network benchmark for specified duration"""
    log_function_entry('network_benchmark', duration=duration, url=url)
    log_benchmark_start('Network', duration)
    
    try:
        count = 0
        end_time = time.perf_counter() + duration
        while time.perf_counter() < end_time:
            requests.get(url, timeout=5)
            count += 1
            
        # Test with threads
        thread_ops = 0
        with ThreadPoolexecutor(max_workers=8) as ex:
            futures = []
            start = time.perf_counter()
            while time.perf_counter() - start < 2.0:  # 2-second test
                futures.append(ex.submit(requests.get, url, timeout=5))
                if len(futures) > 20:  # Limit connections
                    done, not_done = wait(futures, return_when="FIRST_COMPLETED")
                    thread_ops += len(done)
                    futures = list(not_done)
        
        result = {"single_thread": count / duration, "multi_thread": thread_ops / 2.0}
        log_benchmark_end('Network', f"ST: {result['single_thread']:.1f} MT: {result['multi_thread']:.1f} reqs/sec")
        log_function_exit('network_benchmark', result)
        return result
    
    except Exception as e:
        logger.error(f"Network benchmark error: {e}")
        log_function_exit('network_benchmark', {"single_thread": 0, "multi_thread": 0})
        return {"single_thread": 0, "multi_thread": 0}

def process_benchmark(num_processes=4):
    """Measure process creation overhead"""
    log_function_entry('process_benchmark', num_processes=num_processes)
    log_benchmark_start('Process overhead', f"{num_processes} processes")
    
    start_times = []
    
    for i in range(3):  # Multiple iterations for better average
        start = time.perf_counter()
        with ProcessPoolexecutor(max_workers=num_processes) as executor:
            futures = [executor.submit(noop) for _ in range(num_processes)]
            for future in as_completed(futures):
                future.result()
        elapsed = time.perf_counter() - start
        process_time = elapsed / num_processes
        start_times.append(process_time)
        logger.debug(f"Process benchmark iteration {i+1}: {process_time:.3f}s per process")
    
    result = statistics.mean(start_times)
    log_benchmark_end('Process overhead', f"{result:.3f}s per process")
    log_function_exit('process_benchmark', result)
    return result

# ────────────────────────────── SYSTEM INFO FUNCTIONS ──────────────────────────────

def get_system_info():
    """Get basic system information"""
    log_function_entry('get_system_info')
    
    mem = psutil.virtual_memory()
    info = {
        'cpu_count': os.cpu_count() or 1,
        'logical_cpus': psutil.cpu_count(logical=True) or 1,
        'physical_cpus': psutil.cpu_count(logical=False) or 1,
        'ram_gb': mem.total / (1024**3),
        'ram_free_gb': mem.available / (1024**3),
        'os': f"{platform.system()} {platform.release()}",
        'python_version': platform.python_version()
    }
    log_function_exit('get_system_info', info)
    return info

# ────────────────────────────── SETTINGS FUNCTIONS ──────────────────────────────

def get_executor_settings():
    """Get thread and process pool settings from database"""
    log_function_entry('get_executor_settings')
    
    try:
        rows = sync_db.fetch("SELECT name, value FROM executor_pool_settings")
        settings = {row['name']: int(row['value']) for row in rows}
        logger.info(f"Retrieved {len(settings)} executor settings from database")
        log_function_exit('get_executor_settings', settings)
        return settings
    
    except Exception as e:
        logger.error(f"Error retrieving executor settings: {e}")
        log_function_exit('get_executor_settings', {})
        return {}

def update_executor_settings(settings):
    """Update thread and process pool settings in database"""
    log_function_entry('update_executor_settings', settings=settings)
    
    try:
        for name, value in settings.items():
            sync_db.execute(
                "UPDATE executor_pool_settings SET value = $1 WHERE name = $2",
                value, name
            )
        logger.info(f"Updated {len(settings)} executor settings")
        log_function_exit('update_executor_settings', True)
        return True
    
    except Exception as e:
        logger.error(f"Error updating executor settings: {e}")
        log_function_exit('update_executor_settings', False)
        return False

def apply_preset(preset_name):
    """Apply a predefined settings preset"""
    log_function_entry('apply_preset', preset_name=preset_name)
    
    if preset_name not in ['safe', 'balanced', 'performance']:
        logger.error(f"Invalid preset name: {preset_name}")
        log_function_exit('apply_preset', False)
        return False
    
    try:
        preset_row = sync_db.fetchrow(
            "SELECT settings_json, description FROM executor_pool_presets WHERE name = $1",
            preset_name
        )
        
        if not preset_row:
            logger.error(f"Preset '{preset_name}' not found")
            log_function_exit('apply_preset', False)
            return False
        
        settings = json.loads(preset_row['settings_json'])
        
        logger.info(f"Applying '{preset_name}' preset: {preset_row['description']}")
        result = update_executor_settings(settings)
        log_function_exit('apply_preset', result)
        return result
    
    except Exception as e:
        logger.error(f"Error applying preset: {e}")
        log_function_exit('apply_preset', False)
        return False

def get_thread_pool_presets():
    """Get available thread pool presets."""
    try:
        rows = sync_db.fetch("SELECT name, description, settings_json FROM executor_pool_presets")
        presets = {
            row['name']: {
                'description': row['description'],
                'settings': json.loads(row['settings_json'])
            } for row in rows
        }
        logger.info(f"Retrieved {len(presets)} thread pool presets")
        return presets
    except Exception as e:
        logger.error(f"Error retrieving thread pool presets: {e}")
        return {
            'safe': {'description': 'Safe preset (low resource usage)', 'settings': {}},
            'balanced': {'description': 'Balanced preset (recommended)', 'settings': {}},
            'performance': {'description': 'Performance preset (high throughput)', 'settings': {}}
        }

def get_current_preset():
    """Get the name of the currently active preset."""
    try:
        current_settings = get_executor_settings()
        
        # Get all presets to compare
        presets = get_thread_pool_presets()
        
        # Check if current settings match any preset
        for preset_name, preset_info in presets.items():
            preset_settings = preset_info['settings']
            
            # Check if all preset settings match the current settings
            matches = True
            for key, value in preset_settings.items():
                if key in current_settings and str(current_settings[key]) != str(value):
                    matches = False
                    break
            
            if matches:
                logger.info(f"Current settings match preset: {preset_name}")
                return preset_name
        
        # No matching preset found
        logger.info("Current settings do not match any preset (custom)")
        return "custom"
    except Exception as e:
        logger.error(f"Error determining current preset: {e}")
        return "unknown"

def auto_tune(
    apply_settings=True,
    print_output=False,
    run_type="manual",
    notes=None,
    show_results_recommended=True,
    show_results=False
):
    """Run benchmarks and determine optimal thread pool settings."""
    try:
        log_function_entry('auto_tune_thread_pool', apply_settings=apply_settings, verbose=print_output, run_type=run_type, notes=notes)
        logger.info(f"Starting full benchmark suite (duration: 5.0s)")

        sys_info = get_system_info()

        print("Running CPU benchmark...")
        cpu_ops = cpu_benchmark(5.0)

        print("Running disk benchmark...")
        disk_results = disk_benchmark(5.0)

        print("Running SQL benchmark...")
        sql_results = sql_benchmark(5.0)

        print("Running network benchmark...")
        net_results = network_benchmark(5.0)

        print("Measuring process overhead...")
        # Create ProcessPoolExecutor with initializer for short-lived benchmark operations
        with ProcessPoolexecutor(
            max_workers=min(4, sys_info['logical_cpus']),
            initializer=run_benchmark
        ) as executor:
            # Measure overhead of process management
            process_overhead = process_benchmark(min(4, sys_info['logical_cpus']))

        logical_cpus = sys_info['logical_cpus']

        if disk_results["multi_thread"] > disk_results["single_thread"] * 3:
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

        results = {
            "cpu_ops": cpu_ops,
            "disk_single": disk_results["single_thread"],
            "disk_multi": disk_results["multi_thread"],
            "sql_single": sql_results["single_thread"],
            "sql_multi": sql_results["multi_thread"],
            "network_single": net_results["single_thread"],
            "network_multi": net_results["multi_thread"],
            "process_overhead": process_overhead,
            "recommended_settings": {
                "max_worker_threads": max_threads,
                "min_worker_threads": min_threads,
                "max_processes": max_processes,
                "min_processes": min_processes,
                "process_timeout": 300,
                "max_tasks_per_process": max_tasks
            }
        }

        logger.info("Benchmark suite completed successfully")
        logger.info(f"Recommended settings: max_threads={max_threads}, max_processes={max_processes}")
        log_benchmark_to_db(results, run_type=run_type, notes=notes)

        # Show results as requested
        if print_output:
            if show_results:
                print("\n=== Benchmark Results ===")
                print(f"CPU performance: {results['cpu_ops']:.1f} ops/sec")
                print(f"Disk I/O: {results['disk_single']:.1f} ops/sec (single thread)")
                print(f"Disk I/O: {results['disk_multi']:.1f} ops/sec (multi thread)")
                print(f"SQL: {results['sql_single']:.1f} queries/sec (single thread)")
                print(f"SQL: {results['sql_multi']:.1f} queries/sec (multi thread)")
                print(f"Network: {results['network_single']:.1f} requests/sec (single thread)")
                print(f"Network: {results['network_multi']:.1f} requests/sec (multi thread)")
                print(f"Process overhead: {results['process_overhead']:.3f} seconds")
            if show_results_recommended:
                print("\n=== Recommended Settings ===")
                for name, value in results['recommended_settings'].items():
                    print(f"{name}: {value}")

        settings = results['recommended_settings']
        if apply_settings:
            success = update_executor_settings(settings)
            if not success:
                logger.error("Failed to apply auto-tuned settings")
        log_function_exit('auto_tune_thread_pool', settings)
        return settings
    except Exception as e:
        logger.error(f"Error during auto-tuning: {e}")
        return {
            "max_worker_threads": (os.cpu_count() or 2) * 2,
            "categories": {
                "smtp": {"max_concurrent": 4},
                "dns": {"max_concurrent": 8},
                "http": {"max_concurrent": 6}
            }
        }

def get_current_settings():
    """Get current executor settings, formatted for the UI."""
    try:
        settings = get_executor_settings()
        
        # Format into a more structured form
        result = {
            'preset': get_current_preset(),
            'global': {
                'max_worker_threads': settings.get('max_worker_threads', (os.cpu_count() or 2) * 2),
                'min_worker_threads': settings.get('min_worker_threads', 2)
            },
            'categories': {}
        }
        
        # Add category-specific settings
        for key, value in settings.items():
            if key.startswith('max_concurrent_'):
                category = key.replace('max_concurrent_', '')
                if category not in result['categories']:
                    result['categories'][category] = {}
                result['categories'][category]['max_concurrent'] = value
        
        logger.info(f"Retrieved formatted executor settings")
        return result
    except Exception as e:
        logger.error(f"Error getting formatted executor settings: {e}")
        return {
            'preset': 'unknown',
            'global': {
                'max_worker_threads': (os.cpu_count() or 2) * 2
            }
        }

# ────────────────────────────── MAIN BENCHMARK ──────────────────────────────

def display_results(results):
    """Display benchmark results in a readable format"""
    log_function_entry('display_results')
    
    print("\n=== Benchmark Results ===")
    print(f"CPU performance: {results['cpu_ops']:.1f} ops/sec")
    print(f"Disk I/O: {results['disk_single']:.1f} ops/sec (single thread)")
    print(f"Disk I/O: {results['disk_multi']:.1f} ops/sec (multi thread)")
    print(f"SQL: {results['sql_single']:.1f} queries/sec (single thread)")
    print(f"SQL: {results['sql_multi']:.1f} queries/sec (multi thread)")
    print(f"Network: {results['network_single']:.1f} requests/sec (single thread)")
    print(f"Network: {results['network_multi']:.1f} requests/sec (multi thread)")
    print(f"Process overhead: {results['process_overhead']:.3f} seconds")
    
    print("\n=== Recommended Settings ===")
    for name, value in results['recommended_settings'].items():
        print(f"{name}: {value}")
    
    log_function_exit('display_results')

def apply_settings(settings, prompt=True):
    """Apply settings to database, with optional user prompt"""
    log_function_entry('apply_settings', prompt=prompt)
    
    if prompt:
        print("\nApply these settings to the database? (y/n): ", end="")
        response = input().lower()
        if response != 'y':
            logger.info("User declined to apply settings")
            print("Settings not applied.")
            log_function_exit('apply_settings', False)
            return False
    
    success = update_executor_settings(settings)
    if success:
        logger.info("Successfully applied settings to database")
        print("Settings applied successfully!")
    else:
        logger.error("Failed to apply settings to database")
        print("Failed to apply settings.")
    
    log_function_exit('apply_settings', success)
    return success

# ────────────────────────────── MAIN CLI FUNCTION ──────────────────────────────

def cli():
    """Simple CLI interface for ThreadGripper Compact"""
    
    
    parser = argparse.ArgumentParser(description="ThreadGripper Compact - Thread/Process pool optimizer")
    
    # Define command groups
    run_group = parser.add_mutually_exclusive_group()
    run_group.add_argument('--run-and-set', action='store_true', help='Run benchmarks and apply settings')
    run_group.add_argument('--run-and-ask', action='store_true', help='Run benchmarks and ask before applying')
    
    preset_group = parser.add_mutually_exclusive_group()
    preset_group.add_argument('--set-preset-safe', action='store_true', help='Apply safe preset')
    preset_group.add_argument('--set-preset-balanced', action='store_true', help='Apply balanced preset')
    preset_group.add_argument('--set-preset-performance', action='store_true', help='Apply performance preset')
    
    parser.add_argument('--info', action='store_true', help='Show system information')
    parser.add_argument('--duration', type=float, default=5.0, help='Benchmark duration in seconds')
    
    args = parser.parse_args()
    
    # Show system info if requested
    if args.info:
        sys_info = get_system_info()
        print("=== System Information ===")
        for key, value in sys_info.items():
            print(f"{key}: {value}")
    
    # Run benchmarks if requested
    if args.run_and_set or args.run_and_ask:
        logger.info(f"Running benchmarks with duration={args.duration}s")
        results = auto_tune(apply_settings=args.run_and_set, print_output=args.run_and_ask, run_type="manual")
        display_results(results)
    
    # Apply preset if requested
    if args.set_preset_safe:
        logger.info("Applying 'safe' preset")
        if apply_preset('safe'):
            print("Applied 'safe' preset successfully")
        else:
            print("Failed to apply 'safe' preset")
            
    elif args.set_preset_balanced:
        logger.info("Applying 'balanced' preset")
        if apply_preset('balanced'):
            print("Applied 'balanced' preset successfully")
        else:
            print("Failed to apply 'balanced' preset")
            
    elif args.set_preset_performance:
        logger.info("Applying 'performance' preset")
        if apply_preset('performance'):
            print("Applied 'performance' preset successfully")
        else:
            print("Failed to apply 'performance' preset")
    
    # If no arguments given, show help
    if not any(vars(args).values()):
        logger.info("No arguments provided, showing help")
        parser.print_help()
    
# API functions for external use
@ensure_event_loop
def thread_gripper_run_and_set():
    """API: Run benchmarks and apply settings without prompting"""
    logger.info("API: Running benchmarks and applying settings automatically")
    results = auto_tune(apply_settings=True, print_output=False, run_type="api")
    return results

@ensure_event_loop
def thread_gripper_run_and_ask():
    """API: Run benchmarks and ask before applying settings"""
    logger.info("API: Running benchmarks and asking for confirmation")
    results = auto_tune(apply_settings=False, print_output=True, run_type="api")
    display_results(results)
    return results

@ensure_event_loop
def thread_gripper_set_preset(preset_name):
    """API: Apply a preset configuration"""
    logger.info(f"API: Applying preset '{preset_name}'")
    return apply_preset(preset_name)

if __name__ == "__main__":
    logger.info("ThreadGripper starting")
    cli()
    logger.info("ThreadGripper completed")

"""
executor Manager Implementation

Provides unified base classes and concrete implementations for:
- ThreadPoolexecutorManager 
- ProcessPoolexecutorManager
- ResourceCoordinator for dynamic resource allocation

All implementations use singleton patterns and auto-tuning capabilities.
"""

# ────────────────────────────── executor BASE CLASSES ──────────────────────────────

class BaseexecutorManager:
    """Base class for executor managers with shared functionality."""
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls, max_workers=None, initialize_now=False):
        """Get or create the singleton instance."""
        # Each subclass gets its own instance
        attr_name = f"_{cls.__name__}_instance"
        with cls._lock:
            if not hasattr(cls, attr_name):
                instance = cls(max_workers, initialize_now=initialize_now)
                setattr(cls, attr_name, instance)
            elif initialize_now and hasattr(getattr(cls, attr_name), '_initialize'):
                # Re-initialize if requested
                getattr(cls, attr_name)._initialize(max_workers)
                
        return getattr(cls, attr_name)
    
    def __init__(self, max_workers=None, initialize_now=False, executor_class=None, setting_key=None):
        """Initialize the executor manager."""
        self.executor_class = executor_class
        self.setting_key = setting_key
        self._initialized = False
        
        # Only initialize immediately if requested
        if initialize_now:
            self._initialize(max_workers)
        
        # Only register with resource coordinator if initialized
        if initialize_now and self._initialized:
            # Import here to avoid circular imports
            
            ResourceCoordinator.get_instance().register_executor(self)
    
    def _initialize(self, max_workers=None):
        """Initialize or reinitialize the executor."""
        # Auto-tune from DB or use provided value
        settings = get_executor_settings()
        self.max_workers = max_workers or settings.get(self.setting_key, self._get_default_worker_count())
        if self.executor_class is None:
            raise RuntimeError(f"executor_class must be set before initializing {self.__class__.__name__}")
        self.executor = self.executor_class(max_workers=self.max_workers)
        self._initialized = True
        logger.info(f"{self.__class__.__name__} initialized with {self.max_workers} workers")
    
    def _get_default_worker_count(self):
        """Get default worker count based on CPU count."""
        return os.cpu_count() or 2
    
    def submit(self, fn, *args, **kwargs):
        """Submit a task to the executor."""
        return self.executor.submit(fn, *args, **kwargs)
    
    def map(self, fn, iterable, chunksize=1):
        """Map a function over an iterable using the executor."""
        return self.executor.map(fn, iterable, chunksize=chunksize)
    
    def shutdown(self, wait=True):
        """Shut down the executor."""
        self.executor.shutdown(wait=wait)
        logger.info(f"{self.__class__.__name__} shutdown")
    
    def reinitialize(self, max_workers=None):
        """Reinitialize the executor with new settings."""
        self.shutdown()
        self._initialize(max_workers)
        
    def get_stats(self):
        """Get executor statistics."""
        return {
            "type": self.__class__.__name__,
            "max_workers": self.max_workers
        }


class AutoTuningexecutorBase(BaseexecutorManager):
    """Base class for auto-tuning executor managers."""
    
    def __init__(self, max_workers=None, initialize_now=False, executor_class=None, setting_key=None, tune_interval=3600):
        """Initialize the auto-tuning executor manager."""
        self.last_tune_time = time.time()
        self.tune_interval = tune_interval
        self.is_tuning = False
        super().__init__(max_workers, initialize_now=initialize_now, executor_class=executor_class, setting_key=setting_key)
    
    def maybe_tune(self):
        """Check if it's time to auto-tune and run tuner if needed."""
        if self.is_tuning:
            return
            
        current_time = time.time()
        if current_time - self.last_tune_time > self.tune_interval:
            self._run_tuner()
    
    @ensure_event_loop
    def _run_tuner(self):
        """Run auto-tuning in a separate thread."""
        def tune_thread():
            self.is_tuning = True
            try:
                logger.info(f"Starting {self.__class__.__name__} auto-tuning...")
                # Run benchmarks and apply settings
                success = thread_gripper_run_and_set()
                if success:
                    self._reload_executor()
                    logger.info(f"{self.__class__.__name__} auto-tuning completed successfully")
                else:
                    logger.warning(f"{self.__class__.__name__} auto-tuning failed")
            except Exception as e:
                logger.error(f"Error during {self.__class__.__name__} auto-tuning: {e}")
            finally:
                self.last_tune_time = time.time()
                self.is_tuning = False
        
        tuner_thread = threading.Thread(target=tune_thread)
        tuner_thread.daemon = True
        tuner_thread.start()
    
    def _reload_executor(self):
        """Reload the executor with new settings."""
        settings = get_executor_settings()
        new_max_workers = settings.get(self.setting_key, self._get_default_worker_count())
        if new_max_workers != self.max_workers:
            logger.info(f"Updating {self.__class__.__name__} from {self.max_workers} to {new_max_workers} workers")
            self.reinitialize(new_max_workers)
    
    @ensure_event_loop
    def submit(self, fn, *args, **kwargs):
        """Submit a task to the executor, with auto-tuning check."""
        if not self._initialized:
            raise RuntimeError(f"{self.__class__.__name__} not initialized. Call initialize() first.")
        
        self.maybe_tune()
        return super().submit(fn, *args, **kwargs)
    
    @ensure_event_loop
    def map(self, fn, iterable, chunksize=1):
        """Map a function over an iterable, with auto-tuning check."""
        if not self._initialized:
            raise RuntimeError(f"{self.__class__.__name__} not initialized. Call initialize() first.")
        
        self.maybe_tune()
        return super().map(fn, iterable, chunksize=chunksize)
    
    @ensure_event_loop
    def run_parallel_tasks(self, tasks, callback=None):
        """
        Run multiple tasks in parallel and collect results.
        
        Args:
            tasks: List of (fn, args, kwargs) tuples to execute
            callback: Optional function to call with results as they complete
            
        Returns:
            List of results in the same order as tasks
        """
        if not self._initialized:
            raise RuntimeError(f"{self.__class__.__name__} not initialized. Call initialize() first.")
        
        self.maybe_tune()
        futures = []
        
        # Submit all tasks
        for fn, args, kwargs in tasks:
            future = self.submit(fn, *args, **kwargs)
            futures.append(future)
            
        # Process results
        results = []
        
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                if callback:
                    callback(i, result, None)
                results.append((i, result))
            except Exception as e:
                if callback:
                    callback(i, None, e)
                results.append((i, e))
                
        # Sort results back to original order
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]


class ThreadPoolexecutorManager(AutoTuningexecutorBase):
    """Thread pool executor manager with auto-tuning."""
    
    def __init__(self, max_workers=None, initialize_now=False):
        super().__init__(
            max_workers=max_workers,
            initialize_now=initialize_now,
            executor_class=ThreadPoolexecutor,
            setting_key="max_worker_threads"
        )
    
    def _get_default_worker_count(self):
        # Threads can benefit from higher parallelism for I/O
        return (os.cpu_count() or 2) * 4


class ProcessPoolexecutorManager(AutoTuningexecutorBase):
    """Process pool executor manager with auto-tuning."""
    
    def __init__(self, max_workers=None, initialize_now=False):
        super().__init__(
            max_workers=max_workers,
            initialize_now=initialize_now,
            executor_class=ProcessPoolexecutor,
            setting_key="max_processes"
        )
    
    def _get_default_worker_count(self):
        # Processes should generally match CPU count
        return max(2, os.cpu_count() or 2)
    
    def _initialize(self, max_workers=None):
        """Initialize or reinitialize the executor with benchmark initializer."""
        # Auto-tune from DB or use provided value
        settings = get_executor_settings()
        self.max_workers = max_workers or settings.get(self.setting_key, self._get_default_worker_count())
        
        # If this is the first initialization during startup, limit workers
        first_run = not hasattr(self, 'executor')
        actual_max_workers = min(2, self.max_workers) if first_run else self.max_workers
        
        # Create the process pool with the initializer function
        self.executor = ProcessPoolexecutor(
            max_workers=actual_max_workers,
            initializer=run_benchmark
        )
        
        if first_run:
            logger.info(f"First-time {self.__class__.__name__} initialization with {actual_max_workers} workers (limited)")
        else:
            logger.info(f"{self.__class__.__name__} initialized with {self.max_workers} workers")
            
        self._initialized = True


# ────────────────────────────── RESOURCE COORDINATOR ──────────────────────────────

class ResourceCoordinator:
    """Coordinates resource allocation between thread and process pools."""
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls, start_monitoring=False):
        """Get the singleton instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(start_monitoring)
        return cls._instance
    
    def __init__(self, start_monitoring=False):
        """Initialize the resource coordinator."""
        self.executors = []
        self.monitoring = False
        self.check_interval = 30  # seconds
        
        # Start monitoring thread if requested
        if start_monitoring:
            self._start_monitoring()
    
    def register_executor(self, executor):
        """Register an executor for resource coordination."""
        if executor not in self.executors:
            self.executors.append(executor)
            logger.debug(f"Registered {executor.__class__.__name__} with ResourceCoordinator")
    
    def _start_monitoring(self):
        """Start monitoring system resources."""
        if not self.monitoring:
            self.monitoring = True
            monitor_thread = threading.Thread(target=self._monitor_resources)
            monitor_thread.daemon = True
            monitor_thread.start()
            logger.info("ResourceCoordinator monitoring started")
    
    @ensure_event_loop
    def _monitor_resources(self):
        """Monitor system resources and adjust executors as needed."""
        while True:
            try:
                self._check_and_adjust()
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                
            time.sleep(self.check_interval)
    
    @ensure_event_loop
    def _check_and_adjust(self):
        """Check resource usage and adjust executors if needed."""
        if not self.executors:
            return
            
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        logger.debug(f"System metrics - CPU: {cpu_percent}%, Memory: {memory_percent}%")
        
        # Check for high CPU usage
        if cpu_percent > 90:
            self._handle_high_cpu()
        
        # Check for high memory usage
        if memory_percent > 85:
            self._handle_high_memory()
            
        # Check for underutilization
        if cpu_percent < 20 and memory_percent < 50:
            self._handle_underutilization()
    
    def _handle_high_cpu(self):
        """Handle high CPU usage by reducing process pool size."""
        process_executors = [e for e in self.executors 
                           if isinstance(e, ProcessPoolexecutorManager)]
        
        for executor in process_executors:
            if executor.max_workers > 2:
                new_size = max(2, executor.max_workers - 1)
                logger.info(f"High CPU usage detected, reducing process pool from {executor.max_workers} to {new_size}")
                executor.reinitialize(new_size)
                
                # Update the database setting
                settings = {executor.setting_key: new_size}
                update_executor_settings(settings)
                
                # Only adjust one executor at a time
                break
    
    def _handle_high_memory(self):
        """Handle high memory usage by reducing both pool sizes."""
        for executor in self.executors:
            if executor.max_workers > 2:
                new_size = max(2, int(executor.max_workers * 0.75))
                logger.info(f"High memory usage detected, reducing {executor.__class__.__name__} from {executor.max_workers} to {new_size}")
                executor.reinitialize(new_size)
                
                # Update the database setting
                settings = {executor.setting_key: new_size}
                update_executor_settings(settings)
    
    def _handle_underutilization(self):
        """Handle resource underutilization by increasing pool sizes."""
        # Get current settings
        settings = get_executor_settings()
        
        for executor in self.executors:
            # Check if we're below the configured maximum
            setting_value = settings.get(executor.setting_key)
            if setting_value and executor.max_workers < setting_value:
                new_size = min(setting_value, executor.max_workers + 1)
                logger.info(f"Resource underutilization detected, increasing {executor.__class__.__name__} from {executor.max_workers} to {new_size}")
                executor.reinitialize(new_size)
    
    def get_stats(self):
        """Get statistics about managed executors and resources."""
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "executors": [e.get_stats() for e in self.executors]
        }


# Create singleton instances for external use - but don't initialize
thread_pool = ThreadPoolexecutorManager.get_instance(initialize_now=False)
process_pool = ProcessPoolexecutorManager.get_instance(initialize_now=False)
resource_coordinator = ResourceCoordinator.get_instance(start_monitoring=False)