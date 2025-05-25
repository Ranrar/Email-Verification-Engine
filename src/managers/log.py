""""
Email Verification Engine
===================================
Logger modul
"""
import os
import json
import logging
import weakref
import shutil
import time
import warnings
import threading
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

# True = split logs into multiple files by log level
# False = keep all logs in one file with level info (no rotation)
K1 = True

# Define default logger name as ISO date format
NAME = datetime.now().strftime('%Y-%m-%d')  # Generates '2025-03-22' format

# Define custom log levels
EMAIL = 22      # Special level for email validation logs
SQL = 15        # Custom level for SQL logs
DEBUG = 10		# Standard levels
INFO = 20		# Standard levels
WARNING = 30	# Something unexpected happened
ERROR = 40		# Serious problem occurred
CRITICAL = 50	# Program is about to crash
STATS = 12      # Custom level for Statistics

# Register the new levels with the logging module
logging.addLevelName(EMAIL, "EMAIL")
logging.addLevelName(SQL, "SQL")
logging.addLevelName(STATS, "STATS")

# Add convenience methods to the Logger class
def _email(self, message, *args, **kwargs):
    if self.isEnabledFor(EMAIL):
        self._log(EMAIL, message, args, **kwargs)

def _sql(self, message, *args, **kwargs):
    if self.isEnabledFor(SQL):
        self._log(SQL, message, args, **kwargs)

def _STATS(self, message, *args, **kwargs):
    if self.isEnabledFor(STATS):
        self._log(STATS, message, args, **kwargs)        

# Add the methods to the Logger class
setattr(logging.Logger, "email", _email)
setattr(logging.Logger, "sql", _sql)
setattr(logging.Logger, "stats", _STATS)

# Silence warnings (optional)
warnings.filterwarnings('ignore')

# Replace the current LOGS_DIR definition
def determine_project_root():
    """Find the project root directory containing main.py"""
    # Get the absolute path to this file (log.py)
    current_file = os.path.abspath(__file__)
    
    # Go up two levels: src/managers/log.py -> src/ -> project_root/
    # This matches the structure: main.py at root, log.py in src/managers/
    project_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    
    # Verify we found the right directory by checking for main.py
    if os.path.isfile(os.path.join(project_dir, 'main.py')):
        return project_dir
    
    # Fallback to current working directory if structure doesn't match
    return os.getcwd()

# Define logs directory relative to project root
PROJECT_ROOT = determine_project_root()
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')

# Create a dedicated error logger
def setup_error_logger():
    """Set up a dedicated logger for error tracking."""
    error_logger = logging.getLogger("error_logger")
    error_logger.setLevel(logging.ERROR)

    # Create a file handler for error logs
    error_log_file = os.path.join(LOGS_DIR, 'errors.log')
    
    class LazyFileHandler(logging.FileHandler):
        def __init__(self, filename, mode='a', encoding=None, delay=True):
            super().__init__(filename, mode, encoding, delay=True)
            
        def emit(self, record):
            if not os.path.exists(os.path.dirname(self.baseFilename)):
                os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
            return super().emit(record)
    
    file_handler = LazyFileHandler(error_log_file, delay=True)
    file_handler.setLevel(logging.ERROR)

    # Use a formatter with milliseconds for error logs
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
                                 datefmt="%Y-%m-%d %H:%M:%S.%f")
    file_handler.setFormatter(formatter)

    # Add the handler to the logger
    error_logger.addHandler(file_handler)
    return error_logger

# Initialize the error logger
error_logger = setup_error_logger()

# Create a custom JSON formatter
class JsonFormatter(logging.Formatter):
    """Format log records as JSON strings"""
    def __init__(self, datefmt=None, split_by_level=False):
        super().__init__(datefmt=datefmt)
        self.split_by_level = split_by_level
    
    def formatTime(self, record, datefmt=None):
        """Override to ensure milliseconds are included"""
        ct = self.converter(record.created)
        if datefmt:
            s = datetime.fromtimestamp(record.created).strftime(datefmt)
        else:
            s = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")
        return s
    
    def format(self, record):
        # Get module and function names
        module_name = record.module if hasattr(record, 'module') else 'unknown'
        function_name = record.funcName if hasattr(record, 'funcName') else 'unknown'
        
        # For module-level code, provide better context
        if function_name == '<module>':
            # If running at module level, include filename for better context
            filename = getattr(record, 'filename', 'unknown')
            lineno = getattr(record, 'lineno', 0)
            function_name = f"Module@Line{lineno}"
        
        # Use our custom formatTime method
        time_format = "%H:%M:%S.%f" if self.datefmt is None else self.datefmt
        
        # Create log data with level near the beginning
        log_data = {
            "timestamp": self.formatTime(record, time_format),
        }
        
        # Include level near the beginning when in single file mode
        if not self.split_by_level:
            # Use brackets to make log levels visually distinct and consistent width
            log_data["level"] = f"[{record.levelname}]".ljust(10)  # [CRITICAL] is 10 chars
            
        # Continue with other fields
        log_data["module"] = module_name
        log_data["function"] = function_name
        log_data["message"] = record.getMessage()
        log_data["file"] = getattr(record, 'filename', 'unknown')
        log_data["line"] = str(getattr(record, 'lineno', 0))
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Store logger instances in a weak reference dictionary
_logger_instances = weakref.WeakValueDictionary()

# Add at module level
_logger_lock = threading.Lock()

class LazyTimedRotatingFileHandler(TimedRotatingFileHandler):
    """A file handler that creates the log file only when needed and never deletes rotated files"""
    
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding=None, 
                 delay=True, utc=False, atTime=None):
        # Set backupCount to 0 which means keep all files
        super().__init__(filename, when, interval, 0, encoding, 
                         delay=True, utc=utc, atTime=atTime)
    
    def emit(self, record):
        """Create containing directory only when emitting first record"""
        if not os.path.exists(os.path.dirname(self.baseFilename)):
            os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
        return super().emit(record)
        
    def getFilesToDelete(self):
        """Override to never delete any files"""
        return []  # Return empty list so no files are deleted

class NoRenameTimedRotatingFileHandler(LazyTimedRotatingFileHandler):
    """A file handler that creates new files at midnight without renaming the existing ones"""
    
    def rotation_filename(self, default_name):
        """Override to prevent renaming of the old log file"""
        # Just return the name that would have been used for rotation
        # but don't actually apply it to the old file
        return default_name
    
    def doRollover(self):
        """Override rollover behavior to avoid renaming the existing file"""
        if self.stream:
            self.stream.close()
        
        # Don't rename the old file, just create a new one
        self.mode = 'a'
        # Get current time for the new filename if needed
        self.stream = self._open()

def Axe(axe_name=NAME, log_level=logging.DEBUG, log_to_console=False, 
        backup_count=7, use_json=True) -> logging.Logger:
    """Configure application logging with file logging and optional console output"""
    with _logger_lock:
        # Check if logger already exists with the same name to avoid duplicates
        if axe_name in _logger_instances:
            return _logger_instances[axe_name]
        
        # Use the global LOGS_DIR instead of recalculating it
        logs_dir = LOGS_DIR
        
        # Create the logger
        logger = logging.getLogger(axe_name)
        
        # Clear any existing handlers to avoid duplicates
        if logger.handlers:
            logger.handlers = []
        
        # Set the logger level
        logger.setLevel(log_level)
        
        # Get the current date in YYYYMMDD format
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        if K1:
            # Split log mode: multiple files based on log level
            log_levels = [
                (logging.DEBUG, "debug"),
                (logging.INFO, "info"),
                (EMAIL, "email"),
                (SQL, "sql"),
                (logging.WARNING, "warning"),
                (logging.ERROR, "error"),
                (logging.CRITICAL, "critical"),
                (STATS, "stats"),
            ]
            
            for level, level_name in log_levels:
                # Skip levels below the configured log_level
                if level < log_level:
                    continue
                
                # Create level-specific log file
                level_log_file = os.path.join(logs_dir, f'{level_name}.{current_date}.log')
                
                # Create a handler for this specific level
                file_handler = LazyTimedRotatingFileHandler(
                    level_log_file,
                    when='midnight',
                    interval=1,
                    backupCount=backup_count,
                    delay=True  # Delay file creation until first log
                )
                file_handler.suffix = "%Y-%m-%d"
                
                # Filter to include only this specific level
                class LevelFilter(logging.Filter):
                    def __init__(self, level):
                        self.level = level
                        
                    def filter(self, record):
                        return record.levelno == self.level
                
                file_handler.addFilter(LevelFilter(level))
                file_handler.setLevel(level)
                
                # Use JSON formatter with time-only format if use_json is True
                if use_json:
                    file_formatter = JsonFormatter(datefmt="%H:%M:%S.%f", split_by_level=True)
                else:
                    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S.%f")
                
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
        else:
            # Single file mode: all logs in one file with level info
            log_file = os.path.join(logs_dir, f'all.{current_date}.log')
            
            # Create a single file handler for all levels
            file_handler = logging.FileHandler(
                log_file,
                mode='a',
                delay=True  # Delay file creation until first log
            )
            file_handler.setLevel(log_level)
            
            # Always include level info in single file mode
            if use_json:
                file_formatter = JsonFormatter(datefmt="%H:%M:%S.%f", split_by_level=False)
            else:
                file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S.%f")
            
            file_handler.setFormatter(file_formatter)
            
            # Create directory if it doesn't exist
            if not os.path.exists(os.path.dirname(log_file)):
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                
            logger.addHandler(file_handler)
        
        if log_to_console:
            # Add console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S.%f")
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        logger.propagate = False
        
        # Store in weak reference dictionary
        _logger_instances[axe_name] = logger
        
        return logger

def close_logger(logger):
    """Properly close all handlers attached to the logger"""
    if logger:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

class LoggerManager:
    """Context manager for logger to ensure proper cleanup"""
    
    # Month names dictionary - defined once as a class attribute
    MONTH_NAMES = {
        1: "01-January", 2: "02-February", 3: "03-March", 4: "04-April",
        5: "05-May", 6: "06-June", 7: "07-July", 8: "08-August",
        9: "09-September", 10: "10-October", 11: "11-November", 12: "12-December"
    }
    
    def __init__(self, logger_name=NAME, log_level=logging.DEBUG, 
                 log_to_console=False, backup_count=7, split_by_level=True):
        self.logger = Axe(logger_name, log_level, log_to_console, backup_count)
        
    def __enter__(self):
        return self.logger
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        close_logger(self.logger)
    
    @staticmethod
    def _ensure_dir(directory):
        """Ensure directory exists"""
        if not os.path.exists(directory):
            os.makedirs(directory)
        return directory
    
    @staticmethod
    def _get_default_dirs():
        """Get default log and archive directories"""
        # Use the global LOGS_DIR instead of calculating it again
        logs_dir = LOGS_DIR
        archive_dir = os.path.join(PROJECT_ROOT, 'logs_archive')
        return logs_dir, archive_dir
    
    @staticmethod
    def _safe_move(src_path, dest_path):
        """Safely move a file, logging any errors"""
        if not os.path.exists(dest_path):
            try:
                shutil.move(src_path, dest_path)
                return True
            except Exception as e:
                error_logger.error(f"Failed to move {src_path} to {dest_path}: {e}")
        return False
        
    @classmethod
    def auto_manage_logs(cls, logs_dir=None, archive_dir=None, max_days=7):
        """
        Move old logs to archive and organize them by date structure
        """
        # Get and ensure directories
        logs_dir, archive_dir = cls._get_default_dirs() if logs_dir is None else (logs_dir, archive_dir)
        if not os.path.exists(logs_dir):
            return False
        cls._ensure_dir(archive_dir)
            
        # Process log files
        current_time = time.time()
        max_age = max_days * 86400  # Convert days to seconds
        
        for filename in os.listdir(logs_dir):
            file_path = os.path.join(logs_dir, filename)
            
            # Skip non-log files
            if not os.path.isfile(file_path) or not filename.endswith('.log'):
                continue
                
            # Check file age
            file_age = current_time - os.path.getmtime(file_path)
            if file_age <= max_age:
                continue
                
            # Get date information and create destination folder structure
            date_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            safe_archive_dir = archive_dir if archive_dir is not None else ""
            safe_year = str(date_time.year) if date_time and hasattr(date_time, "year") else "unknown_year"
            year_dir = os.path.join(safe_archive_dir, safe_year)
            month_dir = os.path.join(year_dir, cls.MONTH_NAMES.get(date_time.month, f"{date_time.month:02d}-Unknown"))
            day_dir = os.path.join(month_dir, f"{date_time.day:02d}")
            
            # Ensure destination directories exist
            cls._ensure_dir(day_dir)
            
            # Move file to organized location
            cls._safe_move(file_path, os.path.join(day_dir, filename))
            
        return True