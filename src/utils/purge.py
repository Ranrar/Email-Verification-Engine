"""
Email Verification Engine
===================================
Purge functionality for cleaning up cache and log files before exit.
"""

import os
import sys
import time
import threading
import eel

@eel.expose
def purge_and_exit(selected_options):
    """Purge selected cache items and exit the application"""
    try:
        print(f"Purging selected items before exit: {selected_options}")
        
        # Initialize purge results
        purge_results = []
        
        # 1. Clear memory cache
        if 'memory' in selected_options:
            try:
                from src.managers.cache import cache_manager
                cache_manager.mem_cache.clear()
                purge_results.append("✓ Memory cache cleared")
            except Exception as e:
                purge_results.append(f"✗ Memory cache clear failed: {str(e)}")

        # 2. Delete disk cache - SIMPLIFIED METHOD
        if 'disk' in selected_options:
            try:
                from src.managers.cache import cache_manager
                
                # First, properly close any open connections
                try:
                    if hasattr(cache_manager, 'disk_conn') and cache_manager.disk_conn:
                        cache_manager.disk_conn.close()
                        # Remove reference to ensure garbage collection
                        delattr(cache_manager, 'disk_conn')
                        print("Closed disk cache connection")
                except Exception as e:
                    print(f"Error closing disk cache connection: {str(e)}")
                
                # Force garbage collection to release file handles
                import gc
                gc.collect()
                    
                # Give system time to release file handles
                time.sleep(0.5)
                
                # Delete the cache database file directly
                cache_db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.cache', 'cache.db')
                print(f"Looking for cache database at: {cache_db_path}")
                
                if os.path.exists(cache_db_path):
                    # Try to delete the file
                    try:
                        os.unlink(cache_db_path)
                        purge_results.append("✓ Cache database deleted")
                    except Exception as e:
                        print(f"Error deleting cache database: {str(e)}")
                        
                        # Windows-specific fallback: try renaming first then delete
                        if os.name == 'nt':
                            try:
                                temp_path = cache_db_path + ".old"
                                os.rename(cache_db_path, temp_path)
                                os.unlink(temp_path)
                                purge_results.append("✓ Cache database deleted (rename and delete)")
                            except Exception as e2:
                                purge_results.append(f"✗ Could not delete cache database: {str(e)}")
                        else:
                            purge_results.append(f"✗ Could not delete cache database: {str(e)}")
                else:
                    purge_results.append("- No cache database file found")
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                purge_results.append(f"✗ Disk cache deletion failed: {str(e)}")
        
        # 3. Delete all rows from cache_entries table
        if 'database' in selected_options:
            try:
                from src.helpers.dbh import sync_db
                result = sync_db.execute("DELETE FROM cache_entries")
                count = result.split()[1] if 'DELETE' in result else '0'
                purge_results.append(f"✓ Database cache entries deleted ({count} rows)")
            except Exception as e:
                purge_results.append(f"✗ Database cache clear failed: {str(e)}")
        
        # 4. Delete all *.log files in logs folder
        if 'logs' in selected_options:
            try:
                # Close logger handlers properly first
                import logging
                
                # Thorough shutdown of all logging
                print("Shutting down loggers before deleting log files...")
                
                # First, shutdown standard logging system
                logging.shutdown()
                
                # Also get the Axe logger if available and close it explicitly
                try:
                    from src.managers.log import Axe
                    logger = Axe()
                    # Use getattr with default no-op function to handle missing 'close' method
                    getattr(logger, 'close', lambda: None)()
                    
                    # If your Axe logger uses custom handlers, close them too
                    if hasattr(logger, 'handlers'):
                        for handler in logger.handlers:
                            if hasattr(handler, 'close'):
                                handler.close()
                except Exception as e:
                    print(f"Error closing Axe logger: {e}")
            
                # Give system time to close file handles
                time.sleep(1)
                
                # Now try to delete the log files
                logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
                if os.path.exists(logs_dir):
                    deleted_count = 0
                    failed_logs = []
                    
                    # First, identify all log files
                    log_files = [f for f in os.listdir(logs_dir) if f.endswith('.log')]
                    
                    # Try to delete each one, with multiple attempts
                    for log_file in log_files:
                        file_path = os.path.join(logs_dir, log_file)
                        success = False
                        
                        # Try up to 3 times with increasing delays
                        for attempt in range(3):
                            try:
                                os.unlink(file_path)
                                deleted_count += 1
                                success = True
                                break
                            except Exception as e:
                                if attempt < 2:  # Only sleep if we're going to retry
                                    time.sleep((attempt + 1) * 0.5)  # Increasing delay
                        
                        if not success:
                            failed_logs.append(log_file)
                    
                    if failed_logs:
                        purge_results.append(f"✓ {deleted_count} log files deleted, {len(failed_logs)} files could not be deleted")
                        purge_results.append(f"  Files still in use: {', '.join(failed_logs[:3])}{'...' if len(failed_logs) > 3 else ''}")
                    else:
                        purge_results.append(f"✓ All log files deleted ({deleted_count} files)")
                else:
                    purge_results.append("- No logs directory found")
            except Exception as e:
                import traceback
                traceback.print_exc()
                purge_results.append(f"✗ Log deletion failed: {str(e)}")
        
        # Return results and initiate exit after a brief delay
        print("\n".join(purge_results))
        
        # IMPORTANT: Use a more reliable exit method
        # First, schedule a forced exit after a short delay
        def force_exit():
            print("Force exiting application...")
            # Try to use os._exit which cannot be caught by exception handlers
            os._exit(0)
        
        # Schedule the hard exit after 2 seconds
        threading.Timer(2.0, force_exit).start()
        
        # Also try the normal exit method
        threading.Timer(1.0, lambda: sys.exit(0)).start()
        
        return {
            "success": True,
            "results": purge_results,
            "exiting": True
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "error": str(e)
        }