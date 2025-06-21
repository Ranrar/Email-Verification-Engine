"""
Email Verification Engine
===================================
Automatically tunes thread and process pool executors by running a short benchmark
to determine optimal settings based on system capabilities.
"""
import os
import time
import statistics
from src.managers.log import get_logger
from src.helpers.dbh import sync_db

# Set up logging
logger = get_logger()

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

def noop():
    """Function that does nothing, used for process overhead measurement"""
    return None

def run_benchmark():
    """
    Run benchmark code for the current worker process.
    This function is called once per worker process when initializing a ProcessPoolExecutor.
    """
    print(f"[PID {os.getpid()}] Running benchmark for worker process...")
    
    # CPU benchmark for 1 second to get a quick measurement
    def cpu_task():
        sum(i*i for i in range(10000))
        
    count = 0
    duration = 1.0  # Short duration for worker initialization
    end_time = time.perf_counter() + duration
    while time.perf_counter() < end_time:
        cpu_task()
        count += 1
    
    result = count / duration
    print(f"[PID {os.getpid()}] Worker CPU benchmark: {result:.1f} ops/sec")
    return result