"""
Email Verification Engine
===================================
Debug functionality for system diagnostics and testing.
"""

import os
import time
import platform
import psutil
import eel
import threading
from datetime import datetime
from src.helpers.dbh import sync_db
from src.utils.notifier import Notifier

notify = Notifier()

@eel.expose
def get_setting(category, sub_category, name):
    """Get a setting value from the app_settings table"""
    try:
        result = sync_db.fetchval(
            "SELECT value FROM app_settings WHERE category = $1 AND sub_category = $2 AND name = $3", 
            category, sub_category, name
        )
        return result if result else "0"
    except Exception as e:
        print(f"Error getting setting {category}.{sub_category}.{name}: {str(e)}")
        return "0"

@eel.expose
def debug_action(action, *args):
    """Handle debug actions"""
    try:
        print(f"Debug action requested: {action} with args: {args}")
        
        if action == 'purge-cache':
            # Implement cache purging logic
            from src.managers.cache import cache_manager
            
            # Clear memory cache
            try:
                cache_manager.mem_cache.clear()
                mem_cleared = True
            except Exception as e:
                print(f"Error clearing memory cache: {e}")
                mem_cleared = False
            
            # Clear disk cache
            try:
                # Use the disk connection directly
                with cache_manager.disk_conn:
                    cache_manager.disk_conn.execute("DELETE FROM cache")
                    cache_manager.disk_conn.commit()
                disk_cleared = True
            except Exception as e:
                print(f"Error clearing disk cache: {e}")
                disk_cleared = False
            
            # Database cache
            try:
                result = sync_db.execute("DELETE FROM cache_entries")
                count = result.split()[1] if 'DELETE' in result else '0'
            except Exception as e:
                print(f"Error clearing database cache: {e}")
                count = "Error"
            
            return {
                "memory": "Cleared" if mem_cleared else "Failed",
                "disk": "Cleared" if disk_cleared else "Failed",
                "database": f"{count} entries deleted"
            }
            
        elif action == 'view-cache':
            # Get cache statistics
            from src.managers.cache import cache_manager
            
            # Memory cache stats
            mem_stats = {
                "size": len(cache_manager.mem_cache),
                "max_size": getattr(cache_manager, 'settings', {}).get("MEM_CACHE_SIZE", 10000),
                "utilization": f"{len(cache_manager.mem_cache) / getattr(cache_manager, 'settings', {}).get('MEM_CACHE_SIZE', 10000) * 100:.1f}%"
            }
            
            # Disk cache stats
            try:
                with cache_manager.disk_conn:
                    total_count = cache_manager.disk_conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                    expired_count = cache_manager.disk_conn.execute(
                        "SELECT COUNT(*) FROM cache WHERE expires_at < ?", 
                        (int(time.time()),)
                    ).fetchone()[0]
                    valid_count = total_count - expired_count
                    
                    # Get total size (approximate)
                    size_result = cache_manager.disk_conn.execute(
                        "SELECT SUM(LENGTH(value)) FROM cache"
                    ).fetchone()[0] or 0
                    
                    disk_stats = {
                        "total_entries": total_count,
                        "valid_entries": valid_count,
                        "expired_entries": expired_count,
                        "size_bytes": size_result,
                        "size_mb": f"{(size_result / (1024 * 1024)):.2f} MB"
                    }
            except Exception as e:
                print(f"Error getting disk cache stats: {e}")
                disk_stats = {"error": str(e)}
            
            # PostgreSQL cache stats - NEW CODE
            try:
                # Get total count
                total_count = sync_db.fetchval("SELECT COUNT(*) FROM cache_entries")
                
                # Get expired count
                expired_count = sync_db.fetchval("""
                    SELECT COUNT(*) FROM cache_entries 
                    WHERE ttl > 0 AND created_at + (ttl * interval '1 second') < NOW()
                """)
                
                # Calculate valid count
                valid_count = total_count - (expired_count or 0)
                
                # Get approximate size (estimating JSONB size is complex)
                size_estimate = sync_db.fetchval("""
                    SELECT pg_size_pretty(pg_table_size('cache_entries')) as table_size
                """)
                
                # Get size in bytes
                size_bytes = sync_db.fetchval("""
                    SELECT pg_table_size('cache_entries')
                """)
                
                # Get some stats on categories
                categories = sync_db.fetch("""
                    SELECT category, COUNT(*) as count 
                    FROM cache_entries 
                    GROUP BY category 
                    ORDER BY count DESC
                """)
                
                pg_stats = {
                    "total_entries": total_count,
                    "valid_entries": valid_count,
                    "expired_entries": expired_count,
                    "size_pretty": size_estimate,
                    "size_bytes": size_bytes,
                    "size_mb": f"{(size_bytes / (1024 * 1024)):.2f} MB",
                    "categories": categories
                }
            except Exception as e:
                print(f"Error getting PostgreSQL cache stats: {e}")
                pg_stats = {"error": str(e)}
            
            return {
                "memory": mem_stats,
                "disk": disk_stats,
                "postgres": pg_stats  # Add PostgreSQL stats to the response
            }
            
        elif action == 'get-logs':
            # Get today's date in the format used by log files
            today = time.strftime('%Y-%m-%d')
            logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
            
            if not args or len(args) == 0:
                # If no specific log requested, list available log files
                log_files = []
                if os.path.exists(logs_dir):
                    for file in os.listdir(logs_dir):
                        if file.endswith('.log'):
                            # Extract log level and date
                            parts = file.split('.')
                            if len(parts) >= 3:
                                level = parts[0]
                                date = parts[1]
                                log_files.append({
                                    "filename": file,
                                    "level": level,
                                    "date": date
                                })
                
                # Sort by date (newest first) then by level
                log_files.sort(key=lambda x: (x['date'], x['level']), reverse=True)
                return {
                    "files": log_files,
                    "today": today
                }
            else:
                # Read specific log file
                filename = args[0]
                log_path = os.path.join(logs_dir, filename)
                
                if os.path.exists(log_path):
                    try:
                        with open(log_path, 'r', encoding='utf-8') as file:
                            content = file.read()
                        return {
                            "filename": filename,
                            "content": content
                        }
                    except Exception as e:
                        return {
                            "filename": filename,
                            "error": str(e)
                        }
                else:
                    return {
                        "filename": filename,
                        "error": "Log file not found"
                    }
            
        elif action == 'system-info':
            # Get system info
            return {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "processor": platform.processor(),
                "memory": {
                    "total": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
                    "available": f"{psutil.virtual_memory().available / (1024**3):.2f} GB",
                    "percent": f"{psutil.virtual_memory().percent}%"
                },
                "disk": {
                    "total": f"{psutil.disk_usage('/').total / (1024**3):.2f} GB",
                    "free": f"{psutil.disk_usage('/').free / (1024**3):.2f} GB",
                    "percent": f"{psutil.disk_usage('/').percent}%"
                }
            }
            
        elif action == 'test-mx':
            # Test MX lookup for a domain
            if not args or not args[0]:
                return "No domain provided"
                
            from src.engine.functions.mx import fetch_mx_records
            domain = args[0]
            mx_results = fetch_mx_records(domain)
            return mx_results
            
        elif action == 'test-smtp':
            # Test SMTP connection to a domain
            if not args or not args[0]:
                return "No domain provided"
                
            # This requires implementing the test_smtp_connection function
            # For now, return a placeholder
            return f"SMTP test for {args[0]} not implemented yet"
            
        elif action == 'purge-exit':
            # Will be handled by the purge_and_exit function in purge.py
            return "Please select items to purge in the dialog"
            
        else:
            return f"Unknown debug action: {action}"
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error executing debug action: {str(e)}"

@eel.expose
def test_notifications():
    """Test the notification system with different types of notifications"""
    try:
        from src.utils.notifier import Notifier
        
        notify = Notifier()
        
        # Show different types of notifications with a slight delay between them
        # Info notifications - auto-dismiss
        notify.info("This is an information notification", "More details about this info notification that will appear on hover")
        time.sleep(0.5)
        
        # Success notifications - auto-dismiss
        notify.success("Operation completed successfully", "Task completed in 2.3 seconds with no errors")
        time.sleep(0.5)
        
        # Warning notifications - persistent until clicked
        notify.warning("This action may have consequences", 
                    "This action will affect the following systems:\n- User accounts\n- Permissions\n- Access logs")
        time.sleep(0.5)
        
        # Error notifications - persistent until clicked
        notify.error("An error occurred during the process", 
                   "Error details:\nFailed to connect to database.\nError code: DB-1234\n\nPlease contact system administrator")
        time.sleep(0.5)
        
        # Custom notification with custom label and persistence setting
        notify.custom("Custom notification with special styling", 
                     "This is a detailed explanation of the custom notification with additional information", 
                     "special:notice", True)
        
        return {"success": True, "message": "All notification types sent"}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}

class LogMonitor:
    """Monitors log files for changes and sends notifications for new entries."""
    
    def __init__(self, notifier=None):
        self.notifier = notifier
        self.running = False
        self.monitor_thread = None
        self.log_positions = {}  # Track position in each log file
        self.logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    
    def start_monitoring(self):
        """Start the log monitoring thread."""
        if self.running:
            return False
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_logs, daemon=True)
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop the log monitoring thread."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        return True
    
    def _monitor_logs(self):
        """Monitor log files for changes."""
        while self.running:
            today = datetime.now().strftime('%Y-%m-%d')
            
            # Check error logs
            self._check_log_file(f"error.{today}.log", "error")
            
            # Check warning logs
            self._check_log_file(f"warning.{today}.log", "warning")
            
            # Sleep before next check
            time.sleep(2)  # Check every 2 seconds
    
    def _check_log_file(self, filename, log_level):
        """Check a specific log file for new entries."""
        log_path = os.path.join(self.logs_dir, filename)
        
        if not os.path.exists(log_path):
            return
        
        # Get file size
        file_size = os.path.getsize(log_path)
        
        # If we haven't seen this file before, or if it's been reset
        if filename not in self.log_positions or file_size < self.log_positions[filename]:
            self.log_positions[filename] = file_size
            return
        
        # If file hasn't changed
        if file_size == self.log_positions[filename]:
            return
        
        # File has grown, read new content
        with open(log_path, 'r', encoding='utf-8') as f:
            f.seek(self.log_positions[filename])
            new_content = f.read()
        
        # Update our position
        self.log_positions[filename] = file_size
        
        # Process new content
        self._process_new_logs(new_content, log_level)
    
    def _process_new_logs(self, content, log_level):
        """Process and sanitize log entries before sending notifications."""
        if not content.strip() or not self.notifier:
            return
        
        # Split into lines and process each line
        lines = content.strip().split('\n')
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
                
            try:
                # Extract time, module and error message using regex
                import re
                
                # Pattern to match HH:MM:SS timestamp at the beginning
                time_match = re.search(r'(\d{2}:\d{2}:\d{2})', line)
                timestamp = time_match.group(1) if time_match else "??:??:??"
                
                # Extract module name (text before the first colon after timestamp)
                parts = line.split(' ', 1)  # Split at first space to separate timestamp
                if len(parts) > 1:
                    module_parts = parts[1].split(':', 1)  # Split at first colon
                    module = module_parts[0].strip() if len(module_parts) > 1 else "unknown"
                else:
                    module = "unknown"
                
                # Extract error message (main content after module identification)
                message = ""
                if len(parts) > 1 and ':' in parts[1]:
                    message = parts[1].split(':', 1)[1].strip()
                else:
                    message = line  # Fallback to the whole line
                
                # Extract file reference if present (in parentheses at the end)
                file_ref = ""
                file_match = re.search(r'\(([^)]*)\)$', line)
                if file_match:
                    file_ref = file_match.group(1)
                    # Remove the file reference from the message
                    message = re.sub(r'\([^)]*\)$', '', message).strip()
                
                # Create a clean notification message for the main notification
                clean_message = f"{timestamp} | {module}: {message[:50]}..." if len(message) > 50 else f"{timestamp} | {module}: {message}"
                
                # Create detailed information for the expanded notification
                detailed_info = f"""TIME: {timestamp}
MODULE: {module}
MESSAGE: {message}"""
                
                # Add file reference if available
                if file_ref:
                    detailed_info += f"\nFILE: {file_ref}"
                
                # Try to parse more context if available
                try:
                    # Check if this looks like a JSON structure
                    if line.strip().startswith('{') and line.strip().endswith('}'):
                        import json
                        json_data = json.loads(line)
                        if isinstance(json_data, dict):
                            detailed_info += "\n\nADDITIONAL CONTEXT:"
                            for key, value in json_data.items():
                                if key not in ['timestamp', 'module', 'message']:  # Skip already shown fields
                                    detailed_info += f"\n{key}: {value}"
                except:
                    pass  # Ignore if not JSON or parsing fails
                
                # Add full original log line for reference
                detailed_info += f"\n\nORIGINAL LOG:\n{line}"
                    
                # Send notification based on log level with detailed information
                if log_level == "error":
                    self.notifier.error(clean_message, detailed_info, "log")
                else:
                    self.notifier.warning(clean_message, detailed_info, "log")
                
            except Exception as e:
                print(f"Error processing log line: {e}")
                # Fallback to simple splitting if parsing fails
                message = line.split(' - ')[-1] if ' - ' in line else line
                notification = f"{log_level.upper()}: {message[:50]}..." if len(message) > 50 else f"{log_level.upper()}: {message}"
                
                if log_level == "error":
                    self.notifier.error(notification, line, "log")
                else:
                    self.notifier.warning(notification, line, "log")

# Create a global log monitor instance near the top of your file
log_monitor = LogMonitor(notifier=notify)

@eel.expose
def toggle_log_monitoring(enable=True):
    """Toggle real-time log monitoring."""
    if enable:
        success = log_monitor.start_monitoring()
        if success:
            notify.info("Log monitoring started")
            return {"success": True, "status": "started"}
        else:
            return {"success": False, "error": "Log monitoring already running"}
    else:
        success = log_monitor.stop_monitoring()
        if success:
            notify.info("Log monitoring stopped")
            return {"success": True, "status": "stopped"}
        else:
            return {"success": False, "error": "Failed to stop log monitoring"}

@eel.expose
def get_log_monitoring_status():
    """Get the current status of log monitoring."""
    return {"active": log_monitor.running}