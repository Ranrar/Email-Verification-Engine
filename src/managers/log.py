import os
import logging
import datetime
import inspect
import colorama
from colorama import Fore, Style
import sys
import traceback
from src.helpers.dbh import sync_db

# Initialize colorama for colored console output
colorama.init(autoreset=True)

def get_log_settings():
    """Get logging settings from database"""
    try:
        # Check if database is available/initialized without making a query
        if not hasattr(sync_db, '_db') or not hasattr(sync_db._db, '_pool') or sync_db._db._pool is None:
            # Database not initialized, use defaults: DB enabled, Console DISABLED
            return True, False
            
        # Get database logging setting
        db_result = sync_db.fetchrow(
            "SELECT value FROM app_settings WHERE category = 'Settings' AND sub_category = 'Log' AND name = 'Enable' AND description = 'Enable Database log 1=True 0=False'"
        )
        db_logging_enabled = bool(int(db_result['value'])) if db_result else True
        
        # Get console logging setting  
        console_result = sync_db.fetchrow(
            "SELECT value FROM app_settings WHERE category = 'Settings' AND sub_category = 'Log' AND name = 'Enable' AND description = 'Enable console log 1=True 0=False'"
        )
        console_logging_enabled = bool(int(console_result['value'])) if console_result else True
        
        return db_logging_enabled, console_logging_enabled
    except Exception:
        # Fallback to defaults: DB enabled, Console DISABLED during startup
        return True, False

# Set up a custom LogRecord factory to capture the actual caller module
original_factory = logging.getLogRecordFactory()

def custom_record_factory(*args, **kwargs):
    record = original_factory(*args, **kwargs)
    
    # Find the actual caller by looking up the stack
    # Skip frames related to the logging system itself
    frame = inspect.currentframe()
    
    # Skip this factory function
    if frame is not None:
        frame = frame.f_back
    
    # Skip internal logging functions
    while frame:
        module_name = frame.f_globals.get('__name__', '')
        if not (module_name == __name__ or module_name.startswith('logging')):
            break
        frame = frame.f_back
    
    if frame:
        module = frame.f_globals.get('__name__', '')
        # Get just the last part of the module name
        record.moduleoverride = module.split('.')[-1]
        
        # Capture the actual filename and line number
        record.filenameoverride = os.path.basename(frame.f_code.co_filename)
        record.linenooverride = frame.f_lineno
    else:
        record.moduleoverride = record.module
        record.filenameoverride = record.filename
        record.linenooverride = record.lineno
    
    return record

# Install our custom factory
logging.setLogRecordFactory(custom_record_factory)

class ConsoleFormatter(logging.Formatter):
    """Console formatter with colors"""
    
    def format(self, record):
        # Format timestamp with milliseconds - using datetime to handle microseconds properly
        dt = datetime.datetime.fromtimestamp(record.created)
        record.timestamp = dt.strftime('%H:%M:%S') + f':{dt.microsecond//1000:03d}'
        
        # Get function name
        if not record.funcName or record.funcName == '<module>':
            record.function_name = 'main'
        else:
            record.function_name = record.funcName
        
        # Use the overridden filename and line if available
        record.filename = getattr(record, 'filenameoverride', record.filename)
        record.lineno = getattr(record, 'linenooverride', record.lineno)
        
        # Extract exception info if present
        exc_text = None
        if record.exc_info and not record.exc_text:
            exc_text = self.formatException(record.exc_info)
            record.exc_text = exc_text
        
        # Choose format based on log level
        if record.levelno <= logging.INFO:
            self._style._fmt = "%(timestamp)12s | %(moduleoverride)-15s | %(function_name)-8s | %(message)s"
        else:
            self._style._fmt = "%(timestamp)12s | %(moduleoverride)-15s | %(function_name)-8s | %(message)s | %(filename)s:%(lineno)d"
        
        # Format the message 
        formatted_message = super().format(record)
        
        # Handle exception info separately
        if record.exc_text and exc_text:
            formatted_message = formatted_message.replace('\n' + exc_text, '')
            formatted_message = f"{formatted_message}\n{exc_text}"
        
        # Apply colors based on log level
        if record.levelno == logging.INFO:
            return f"{Fore.WHITE}{formatted_message}"
        elif record.levelno == logging.DEBUG:
            return f"{Fore.WHITE}{Style.BRIGHT}{formatted_message}"
        elif record.levelno == logging.WARNING:
            return f"{Fore.YELLOW}{formatted_message}"
        elif record.levelno == logging.ERROR:
            return f"{Fore.RED}{formatted_message}"
        elif record.levelno == logging.CRITICAL:
            return f"{Fore.RED}{Style.BRIGHT}{formatted_message}"
        else:
            return formatted_message

class Logger:
    """Logger class that manages database and optional console logging"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, console_logging=None):
        """Get logger singleton instance"""
        if cls._instance is None:
            # Get settings from database if not explicitly provided
            if console_logging is None:
                _, console_logging = get_log_settings()
            cls._instance = cls(console_logging)
        elif console_logging is not None and console_logging != cls._instance.console_logging:
            if console_logging:
                cls._instance.enable_console_logging()
            else:
                cls._instance.disable_console_logging()
        return cls._instance
    
    def __init__(self, console_logging=True):
        # Create logger
        self.logger = logging.getLogger('email_verification_engine')
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent logs from propagating to the root logger
        self.logger.propagate = False
        
        # Clear any existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Set up console logging if enabled
        self.console_logging = console_logging
        if console_logging:
            self._setup_console_handler()
    
    def _setup_console_handler(self):
        """Set up console logging"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(ConsoleFormatter())
        self.logger.addHandler(console_handler)
    
    def enable_console_logging(self):
        """Enable console logging"""
        if not self.console_logging:
            self.console_logging = True
            self._setup_console_handler()
    
    def disable_console_logging(self):
        """Disable console logging"""
        if self.console_logging:
            self.console_logging = False
            self.logger.handlers.clear()
            sys.stdout.flush()
    
    def _format_exception(self, exc_info):
        """Format exception information into a string"""
        if not exc_info:
            return None
        return ''.join(traceback.format_exception(*exc_info))
    
    def debug(self, message, exc_info=False, trace_id=None):
        """Log a debug message to console and database"""
        # Get current settings
        db_logging_enabled, console_logging_enabled = get_log_settings()
        
        # Update console handler based on current settings
        self._update_console_handler(console_logging_enabled)
        
        exc = sys.exc_info() if exc_info else None
        
        # Console logging
        if console_logging_enabled:
            self.logger.debug(message, exc_info=exc_info)
        
        # Database logging
        if db_logging_enabled:
            record = self.logger.makeRecord(
                self.logger.name, logging.DEBUG, fn='', lno=0, 
                msg=message, args=(), exc_info=exc
            )
            
            self.write_log_to_db(
                level="DEBUG",
                message=message,
                module=getattr(record, 'moduleoverride', record.module),
                function=record.funcName,
                file=getattr(record, 'filenameoverride', record.filename),
                line=getattr(record, 'linenooverride', record.lineno),
                exception=self._format_exception(exc) if exc_info else None,
                trace_id=trace_id
            )
    
    def _update_console_handler(self, should_have_console):
        """Dynamically add/remove console handler based on current settings"""
        has_console = any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers)
        
        if should_have_console and not has_console:
            # Need console handler but don't have one - add it
            self._setup_console_handler()
            self.console_logging = True
        elif not should_have_console and has_console:
            # Have console handler but shouldn't - remove it
            self.logger.handlers = [h for h in self.logger.handlers if not isinstance(h, logging.StreamHandler)]
            self.console_logging = False
    
    def info(self, message, exc_info=False, trace_id=None):
        """Log an info message to console and database"""
        # Get current settings
        db_logging_enabled, console_logging_enabled = get_log_settings()
        
        # Update console handler based on current settings
        self._update_console_handler(console_logging_enabled)
        
        exc = sys.exc_info() if exc_info else None
        
        # Console logging
        if console_logging_enabled:
            self.logger.info(message, exc_info=exc_info)
        
        # Database logging
        if db_logging_enabled:
            record = self.logger.makeRecord(
                self.logger.name, logging.INFO, fn='', lno=0, 
                msg=message, args=(), exc_info=exc
            )
            
            self.write_log_to_db(
                level="INFO",
                message=message,
                module=getattr(record, 'moduleoverride', record.module),
                function=record.funcName,
                file=getattr(record, 'filenameoverride', record.filename),
                line=getattr(record, 'linenooverride', record.lineno),
                exception=self._format_exception(exc) if exc_info else None,
                trace_id=trace_id
            )
    
    def warning(self, message, exc_info=False, trace_id=None):
        """Log a warning message to console and database"""
        # Get current settings
        db_logging_enabled, console_logging_enabled = get_log_settings()
        
        exc = sys.exc_info() if exc_info else None
        
        # Console logging
        if console_logging_enabled:
            self.logger.warning(message, exc_info=exc_info)
        
        # Database logging
        if db_logging_enabled:
            record = self.logger.makeRecord(
                self.logger.name, logging.WARNING, fn='', lno=0, 
                msg=message, args=(), exc_info=exc
            )
            
            self.write_log_to_db(
                level="WARNING",
                message=message,
                module=getattr(record, 'moduleoverride', record.module),
                function=record.funcName,
                file=getattr(record, 'filenameoverride', record.filename),
                line=getattr(record, 'linenooverride', record.lineno),
                exception=self._format_exception(exc) if exc_info else None,
                trace_id=trace_id
            )
    
    def error(self, message, exc_info=False, trace_id=None):
        """Log an error message to console and database"""
        # Get current settings
        db_logging_enabled, console_logging_enabled = get_log_settings()
        
        exc = sys.exc_info() if exc_info else None
        
        # Console logging
        if console_logging_enabled:
            self.logger.error(message, exc_info=exc_info)
        
        # Database logging
        if db_logging_enabled:
            record = self.logger.makeRecord(
                self.logger.name, logging.ERROR, fn='', lno=0, 
                msg=message, args=(), exc_info=exc
            )
            
            self.write_log_to_db(
                level="ERROR",
                message=message,
                module=getattr(record, 'moduleoverride', record.module),
                function=record.funcName,
                file=getattr(record, 'filenameoverride', record.filename),
                line=getattr(record, 'linenooverride', record.lineno),
                exception=self._format_exception(exc) if exc_info else None,
                trace_id=trace_id
            )
    
    def critical(self, message, exc_info=False, trace_id=None):
        """Log a critical message to console and database"""
        # Get current settings
        db_logging_enabled, console_logging_enabled = get_log_settings()
        
        exc = sys.exc_info() if exc_info else None
        
        # Console logging
        if console_logging_enabled:
            self.logger.critical(message, exc_info=exc_info)
        
        # Database logging
        if db_logging_enabled:
            record = self.logger.makeRecord(
                self.logger.name, logging.CRITICAL, fn='', lno=0, 
                msg=message, args=(), exc_info=exc
            )
            
            self.write_log_to_db(
                level="CRITICAL",
                message=message,
                module=getattr(record, 'moduleoverride', record.module),
                function=record.funcName,
                file=getattr(record, 'filenameoverride', record.filename),
                line=getattr(record, 'linenooverride', record.lineno),
                exception=self._format_exception(exc) if exc_info else None,
                trace_id=trace_id
            )
    
    def write_log_to_db(self, level, message, module=None, function=None, file=None, 
          line=None, exception=None, trace_id=None, timestamp=None):
        try:
            # Check if database is available/initialized without making a query
            if not hasattr(sync_db, '_db') or not hasattr(sync_db._db, '_pool') or sync_db._db._pool is None:
                # Database not initialized, skip silently
                return
                
            if not timestamp:
                timestamp = datetime.datetime.now(datetime.timezone.utc)

            sync_db.execute(
                """
                INSERT INTO application_logs
                    (timestamp, level, module, function, message, file, line, exception, trace_id)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                timestamp,
                level,
                module,
                function,
                message,
                file,
                line,
                exception,
                trace_id
            )
        except Exception:
            # Fail silently - don't print errors during startup/shutdown
            pass

# Convenience functions
def get_logger(console_logging=None):
    """Get the logger instance"""
    return Logger.get_instance(console_logging)

def enable_console_logging():
    """Enable console logging"""
    Logger.get_instance().enable_console_logging()

def disable_console_logging():
    """Disable console logging"""
    Logger.get_instance().disable_console_logging()

def debug(message, exc_info=False, trace_id=None):
    """Log a debug message"""
    Logger.get_instance().debug(message, exc_info=exc_info, trace_id=trace_id)

def info(message, exc_info=False, trace_id=None):
    """Log an info message"""
    Logger.get_instance().info(message, exc_info=exc_info, trace_id=trace_id)

def warning(message, exc_info=False, trace_id=None):
    """Log a warning message"""
    Logger.get_instance().warning(message, exc_info=exc_info, trace_id=trace_id)

def error(message, exc_info=False, trace_id=None):
    """Log an error message"""
    Logger.get_instance().error(message, exc_info=exc_info, trace_id=trace_id)

def critical(message, exc_info=False, trace_id=None):
    """Log a critical message"""
    Logger.get_instance().critical(message, exc_info=exc_info, trace_id=trace_id)