"""
Logger Test for Email Verification Engine
=========================================

This script tests the logging functionality of the Email Verification Engine.
It verifies various aspects of the logging system including:
- Different log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Console output with colors
- File logging and rotation
- Module name detection
- Exception logging

Usage:
  # From project root
  python src/test/test_log.py
  
  # With specific options
  python src/test/test_log.py --no-console  # Disable console output
  python src/test/test_log.py --file-only   # Check file logging only
  python src/test/test_log.py --exception   # Test exception logging
"""

import sys
import os
import time
from datetime import datetime
import traceback
import argparse

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Import logging system
from src.managers.log import get_logger, debug, info, warning, error, critical
from src.managers.log import enable_console_logging, disable_console_logging

def test_basic_logging():
    """Test basic logging functionality with all log levels."""
    print("\n=== Testing Basic Logging ===")
    
    # Get a logger instance
    logger = get_logger()
    
    print("Logging messages at all levels...")
    logger.debug("This is a DEBUG message")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    logger.critical("This is a CRITICAL message")
    
    print("Using convenience functions...")
    debug("This is a DEBUG message using convenience function")
    info("This is an INFO message using convenience function")
    warning("This is a WARNING message using convenience function")
    error("This is an ERROR message using convenience function")
    critical("This is a CRITICAL message using convenience function")
    
    print("✅ Basic logging test complete")

def test_console_toggle():
    """Test enabling and disabling console logging."""
    print("\n=== Testing Console Logging Toggle ===")
    
    print("Disabling console logging...")
    disable_console_logging()
    
    print("The following log messages should NOT appear in the console:")
    info("This message should NOT appear in the console")
    error("This error should NOT appear in the console")
    
    print("Enabling console logging...")
    enable_console_logging()
    
    print("The following log messages SHOULD appear in the console:")
    info("This message SHOULD appear in the console")
    error("This error SHOULD appear in the console")
    
    print("✅ Console toggle test complete")

def test_exception_logging():
    """Test logging with exception information."""
    print("\n=== Testing Exception Logging ===")
    
    try:
        # Deliberately cause an exception
        print("Causing a deliberate exception...")
        result = 1 / 0
    except Exception as e:
        print("Logging the exception with exc_info=True...")
        error(f"An error occurred: {str(e)}", exc_info=True)
        
    try:
        # Another type of exception
        print("Causing another deliberate exception...")
        some_list = []
        item = some_list[10]  # Index error
    except Exception as e:
        print("Logging the exception with traceback...")
        tb = traceback.format_exc()
        critical(f"Critical error occurred: {str(e)}\n{tb}")
    
    print("✅ Exception logging test complete")

def test_module_name_detection():
    """Test if the module name is correctly detected."""
    print("\n=== Testing Module Name Detection ===")
    
    class TestModule:
        """Inner class to test module detection from different contexts."""
        @staticmethod
        def log_message():
            info("This message should show 'test_log' as module")
    
    # Log from the main script
    info("This message should show 'test_log' as module")
    
    # Log from a method
    TestModule.log_message()
    
    # Create a new function to log
    def nested_function():
        info("This message from nested function should show 'test_log' as module")
    
    nested_function()
    
    print("✅ Module name detection test complete")
    print("Check the logs to verify module names are correctly detected")

def test_file_rotation():
    """Simulate file rotation by changing the system date."""
    print("\n=== Testing Log File Rotation ===")
    print("Note: This test only prepares for checking rotation.")
    print("      Actual rotation happens at midnight UTC.")
    
    # Log a message with current timestamp
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    info(f"Log message at {current_time}")
    
    # Get the current log file path
    log_dir = os.path.join(project_root, 'logs')
    today = datetime.utcnow().strftime('%Y-%m-%d')
    log_file = os.path.join(log_dir, f"{today}.log")
    
    print(f"Current log file: {log_file}")
    print("Check if this file exists and contains the test messages")
    
    # Check for archived logs
    archive_dir = os.path.join(log_dir)
    if os.path.exists(archive_dir):
        print(f"Archive directory exists: {archive_dir}")
        # List log files in archive directory
        logs = [f for f in os.listdir(archive_dir) if f.endswith('.log')]
        print(f"Log files in archive: {logs}")
    else:
        print(f"No archive directory found at: {archive_dir}")
    
    print("✅ File check complete")

def test_log_alignment():
    """Test log column alignment with various length inputs."""
    print("\n=== Testing Log Column Alignment ===")
    
    # Short module and function names
    info("Short names test")
    
    # Long module name (will be truncated in the log)
    class VeryLongModuleNameThatShouldBeTruncated:
        @staticmethod
        def test():
            info("Testing long module name")
    
    VeryLongModuleNameThatShouldBeTruncated.test()
    
    # Long function name
    def this_is_a_very_long_function_name_that_should_be_truncated():
        info("Testing long function name")
    
    this_is_a_very_long_function_name_that_should_be_truncated()
    
    # Long message
    info("This is a very long message that should wrap properly without breaking the alignment of subsequent log lines. " +
         "It contains a lot of text to ensure we test how the logger handles long messages.")
    
    print("✅ Log alignment test complete")
    print("Check the logs to verify column alignment")

def view_log_file():
    """View the current log file contents."""
    log_dir = os.path.join(project_root, 'logs')
    today = datetime.utcnow().strftime('%Y-%m-%d')
    log_file = os.path.join(log_dir, f"{today}.log")
    
    if os.path.exists(log_file):
        print(f"\n=== Contents of {log_file} ===")
        with open(log_file, 'r') as f:
            # Get last 20 lines
            lines = f.readlines()
            if len(lines) > 20:
                print(f"... showing last 20 of {len(lines)} lines ...")
                lines = lines[-20:]
            
            for line in lines:
                print(line.rstrip())
    else:
        print(f"\nLog file not found: {log_file}")

def run_all_tests(args):
    """Run all logging tests."""
    print("=" * 70)
    print("RUNNING LOGGER SYSTEM TESTS")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Configure console logging based on args
    if args.no_console or args.file_only:
        disable_console_logging()
        print("Console logging disabled for tests")
    else:
        enable_console_logging()
        print("Console logging enabled for tests")
    
    # Log a test header to mark the start of the test
    info("--- STARTING LOGGER TESTS ---")
    
    # Run the tests
    test_basic_logging()
    
    if not args.file_only:
        test_console_toggle()
    
    if args.exception:
        test_exception_logging()
    
    test_module_name_detection()
    test_log_alignment()
    test_file_rotation()
    
    # Log a test footer to mark the end of the test
    info("--- FINISHED LOGGER TESTS ---")
    
    # View log file contents
    if args.view_log:
        view_log_file()
    
    print("\nAll tests completed. Check the log file for results.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test the logging system")
    parser.add_argument('--no-console', action='store_true', help="Disable console logging")
    parser.add_argument('--file-only', action='store_true', help="Only test file logging")
    parser.add_argument('--exception', action='store_true', help="Test exception logging")
    parser.add_argument('--view-log', action='store_true', help="View log file contents after tests")
    
    args = parser.parse_args()
    run_all_tests(args)