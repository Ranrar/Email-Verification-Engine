"""
Email Verification Engine
===================================
Standalone shutdown system:
This module handles the graceful termination of all EVE components to ensure
resources are properly released and data is saved.

Basic Usage:
from src.helpers.shutdown import shutdown
# Shutdown all components
success = shutdown()
"""
import asyncio
import atexit
import time
from typing import Any, Dict, Optional
from src.managers.cache import cache_manager
from src.managers.executor import thread_pool, process_pool
from src.managers.log import Axe
from src.helpers.dbh import sync_db
from src.helpers.dbh import DBHandler

logger = Axe()
db = None
_app_components = None

def get_db():
    global db
    if db is None:
        try:
            # Directly instantiate the DBHandler
            db = DBHandler()
        except Exception as e:
            logger.error(f"Failed to get database handler: {e}")
            db = None
    return db

def shutdown_engine(engine: Any) -> bool:
    """Shut down the validation engine"""
    try:
        logger.info("Shutting down validation engine...")
        
        # Cache blacklist data if needed
        if engine is not None and hasattr(engine, "blacklist_checker") and hasattr(engine.blacklist_checker, "save_cache"):
            engine.blacklist_checker.save_cache()
            
        # Disconnect from any open SMTP connections
        if hasattr(engine, "smtp") and hasattr(engine.smtp, "close_all_connections"):
            engine.smtp.close_all_connections()
            
        # Log status
        logger.info("Validation engine shut down successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to shut down validation engine: {e}")
        return False

def shutdown_flow_manager(flow_manager: Any) -> bool:
    """Shut down the flow validation manager"""
    try:
        logger.info("Shutting down flow validation manager...")
        
        # Save any in-progress jobs to cache
        if hasattr(flow_manager, "save_jobs_to_cache"):
            flow_manager.save_jobs_to_cache()
            logger.info("Saved in-progress validation jobs to cache")
            
        # Cancel any timer threads
        if hasattr(flow_manager, "_save_timer") and flow_manager._save_timer:
            flow_manager._save_timer.cancel()
            logger.info("Cancelled job saving timer")
            
        # Set stop event for monitor thread
        if hasattr(flow_manager, "event"):
            flow_manager.event.set()
            
        logger.info("Flow validation manager shut down successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to shut down flow validation manager: {e}")
        return False

def shutdown_thread_pools() -> bool:
    """Shut down thread and process pools"""
    try:
        logger.info("Shutting down thread and process pools...")
        
        # Shut down thread pool
        if thread_pool and hasattr(thread_pool, "shutdown"):
            thread_pool.shutdown(wait=True)
            logger.info("Thread pool shut down")
            
        # Shut down process pool
        if process_pool and hasattr(process_pool, "shutdown"):
            process_pool.shutdown(wait=True)
            logger.info("Process pool shut down")
            
        return True
    except Exception as e:
        logger.error(f"Failed to shut down thread/process pools: {e}")
        return False

def shutdown_database() -> bool:
    """Shut down database connections"""
    try:
        logger.info("Shutting down database connections...")      
        
        # First shut down thread pool
        if sync_db and hasattr(sync_db, "shutdown"):
            sync_db.shutdown()
            logger.info("Shut down database thread pool")
        
        # Then close connection pool
        if sync_db and hasattr(sync_db, "disconnect"):
            sync_db.disconnect()
            logger.info("Database connection pool closed")
            
        return True
    except Exception as e:
        logger.error(f"Failed to shut down database connections: {e}")
        return False

def shutdown() -> bool:
    global _app_components
    """Properly shut down all system resources"""
    logger.info("System shutting down...")
    start_time = time.time()
    success = True
    
    try:
        # Import components without initializing them if not already done
        # This avoids creating components during shutdown
        
        # Determine if components are already initialized
        components = _app_components
        
        if components is None:
            logger.info("No initialized components found")
        else:
            # Step 1: Shut down engine
            if 'engine' in components:
                if not shutdown_engine(components['engine']):
                    success = False
            
            # Step 2: Shut down flow manager
            if 'flow_manager' in components:
                if not shutdown_flow_manager(components['flow_manager']):
                    success = False
        
        # Step 3: Shut down thread and process pools
        if not shutdown_thread_pools():
            success = False
        
        # Step 4: Close database connections last
        if not shutdown_database():
            success = False
        
        elapsed = (time.time() - start_time) * 1000
        logger.info(f"System shutdown completed in {elapsed:.2f}ms (Success: {success})")
        return success
           
    except Exception as e:
        logger.error(f"Critical error during shutdown: {e}", exc_info=True)
        return False

# Register automatic database shutdown at application exit
atexit.register(lambda: shutdown_database())

if __name__ == "__main__":
    print("EVE Shutdown System")
    print("------------------")
    
    try:
        # Perform shutdown
        success = shutdown()
        
        print(f"\nShutdown {'successful' if success else 'completed with errors'}!")
        
    except Exception as e:
        print(f"\nShutdown failed with critical error: {e}")