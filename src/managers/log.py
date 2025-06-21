import os
import logging
import datetime
import inspect
from logging.handlers import TimedRotatingFileHandler
import colorama
from colorama import Fore, Style
import sys

# Initialize colorama for colored console output
colorama.init(autoreset=True)

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

class LogFormatter(logging.Formatter):
    """Custom formatter for logs with different formats based on log level"""
    
    def format(self, record):
        # Format timestamp with milliseconds - using datetime to handle microseconds properly
        dt = datetime.datetime.fromtimestamp(record.created)
        record.timestamp = dt.strftime('%H:%M:%S') + f':{dt.microsecond//1000:03d}'
        
        # Get function name
        if not record.funcName or record.funcName == '<module>':
            record.function_name = 'main'
        else:
            record.function_name = record.funcName
        
        # Use the overridden filename if available, else fallback
        filename = getattr(record, 'filenameoverride', os.path.basename(record.pathname))
        record.filename = filename
        
        # Use the overridden line number if available
        record.lineno = getattr(record, 'linenooverride', record.lineno)
    
        # Extract exception info if present to prevent it from breaking our format
        exc_text = None
        if record.exc_info and not record.exc_text:
            exc_text = self.formatException(record.exc_info)
            record.exc_text = exc_text
        
        # Choose format based on log level with fixed-width columns for alignment
        if record.levelno <= logging.INFO:
            self._style._fmt = "%(timestamp)12s | %(moduleoverride)-15s | %(function_name)-8s | %(message)s"
        else:
            self._style._fmt = "%(timestamp)12s | %(moduleoverride)-15s | %(function_name)-8s | %(message)s | %(filename)s | %(lineno)d"
        
        # Format the message 
        formatted_message = super().format(record)
        
        # Handle exception info separately to maintain correct formatting
        if record.exc_text and exc_text:
            # Remove the exception info from the formatted message if it was added
            # by the parent formatter and add it on a new line
            formatted_message = formatted_message.replace('\n' + exc_text, '')
            return f"{formatted_message}\n{exc_text}"
        
        return formatted_message

class ConsoleFormatter(LogFormatter):
    """Console formatter with colors"""
    
    def format(self, record):
        # Format the message using parent formatter
        message = super().format(record)
        
        # Apply colors based on log level
        if record.levelno == logging.INFO:
            return f"{Fore.WHITE}{message}"  # White (normal)
        elif record.levelno == logging.DEBUG:
            return f"{Fore.WHITE}{Style.BRIGHT}{message}"  # White (bold)
        elif record.levelno == logging.WARNING:
            return f"{Fore.YELLOW}{message}"  # Yellow (normal)
        elif record.levelno == logging.ERROR:
            return f"{Fore.RED}{message}"  # Red (normal)
        elif record.levelno == logging.CRITICAL:
            return f"{Fore.RED}{Style.BRIGHT}{message}"  # Red (bold)
        else:
            return message

class CustomRotatingFileHandler(TimedRotatingFileHandler):
    """Custom handler that archives logs in year/month folders"""
    
    def doRollover(self):
        # Get current filename before rotation
        current_filename = self.baseFilename
        
        # Execute standard rollover
        super().doRollover()
        
        # Move the rotated file to archives
        if os.path.exists(current_filename):
            # Extract date from filename (YYYY-MM-DD.log)
            filename = os.path.basename(current_filename)
            date_part = filename.split('.')[0]  # Get YYYY-MM-DD
            year, month, _ = date_part.split('-')
            
            # Create archive directory
            archive_dir = os.path.join(os.path.dirname(os.path.dirname(current_filename)), year, month)
            os.makedirs(archive_dir, exist_ok=True)
            
            # Move file to archive
            archive_path = os.path.join(archive_dir, filename)
            try:
                os.replace(current_filename, archive_path)
            except Exception as e:
                print(f"Error archiving log file: {e}")

class Logger:
    """Logger class that manages file and console logging"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, console_logging=True):
        """Get logger singleton instance"""
        if cls._instance is None:
            cls._instance = cls(console_logging)
        elif console_logging != cls._instance.console_logging:
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
        
        # Set up file logging
        self._setup_file_handler()
        
        # Set up console logging if enabled
        self.console_logging = console_logging
        if console_logging:
            self._setup_console_handler()
    
    def _setup_file_handler(self):
        """Set up file logging"""
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Create log file with today's date using the recommended UTC approach
        today = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d')
        log_file = os.path.join(logs_dir, f"{today}.log")
        
        # Set up file handler with midnight rotation (UTC)
        file_handler = CustomRotatingFileHandler(
            filename=log_file,
            when='midnight',
            interval=1,
            backupCount=0,  # Don't delete old logs
            utc=True,
            encoding='utf-8'  # Explicitly set UTF-8 encoding
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(LogFormatter())
        self.logger.addHandler(file_handler)
    
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
            # Create a new logger instance without console handlers
            self.console_logging = False
            
            # Keep track of the file handlers
            file_handlers = [h for h in self.logger.handlers 
                           if not isinstance(h, logging.StreamHandler) or 
                              isinstance(h, logging.FileHandler)]
            
            # Remove all handlers
            self.logger.handlers.clear()
            
            # Re-add only the file handlers
            for handler in file_handlers:
                self.logger.addHandler(handler)
                
            # Flush stdout to ensure any pending output is processed
            sys.stdout.flush()
    
    def debug(self, message, exc_info=False):
        self.logger.debug(message, exc_info=exc_info)
    
    def info(self, message, exc_info=False):
        self.logger.info(message, exc_info=exc_info)
    
    def warning(self, message, exc_info=False):
        self.logger.warning(message, exc_info=exc_info)
    
    def error(self, message, exc_info=False):
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message, exc_info=False):
        self.logger.critical(message, exc_info=exc_info)

# Convenience functions
def get_logger(console_logging=True):
    """Get the logger instance"""
    return Logger.get_instance(console_logging)

def enable_console_logging():
    """Enable console logging"""
    Logger.get_instance().enable_console_logging()

def disable_console_logging():
    """Disable console logging"""
    Logger.get_instance().disable_console_logging()

def debug(message, exc_info=False):
    """Log a debug message"""
    Logger.get_instance().debug(message, exc_info=exc_info)

def info(message, exc_info=False):
    """Log an info message"""
    Logger.get_instance().info(message, exc_info=exc_info)

def warning(message, exc_info=False):
    """Log a warning message"""
    Logger.get_instance().warning(message, exc_info=exc_info)

def error(message, exc_info=False):
    """Log an error message"""
    Logger.get_instance().error(message, exc_info=exc_info)

def critical(message, exc_info=False):
    """Log a critical message"""
    Logger.get_instance().critical(message, exc_info=exc_info)