"""
Email Verification Engine
===================================
Dynamic Validation Queue
- Loads validation functions and dependencies directly from database
- No hardcoded function registrations required
- Dynamic function importing based on database configuration
"""

import importlib
import threading
import inspect
import time
from typing import Any, Dict, List, Optional, Set, Callable, Tuple
from datetime import datetime
import json

from src.managers.time import EnhancedOperationTimer
from src.managers.log import get_logger
from src.helpers.dbh import sync_db
from src.managers.cache import CacheKeys, cache_manager

logger = get_logger()

class DynamicQueue:
    """
    Dynamic function queue that loads validation functions from database
    and executes them in proper dependency order without hardcoded registrations.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        """Get singleton instance of DynamicQueue."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance
    
    def __init__(self):
        """Initialize function queue from database."""
        self.functions = {}
        self.execution_order = []
        self.lock = threading.RLock()
        self._cache_key = CacheKeys.VALIDATION_QUEUE_CONFIG
        
        # Load everything from the database
        self._load_from_database()
        
    def _load_from_database(self):
        """Load validation functions and dependencies directly from database."""
        try:
            # Load functions from the email_validation_functions table
            functions = sync_db.fetch_all("""
                SELECT id, function_name, display_name, description, 
                       module_path, function_path, priority, enabled
                FROM email_validation_functions
                ORDER BY priority ASC
            """)
            
            if not functions:
                logger.warning("No validation functions found in database")
                return
                
            # Load all function dependencies at once
            dependencies = sync_db.fetch_all("""
                SELECT function_name, depends_on
                FROM email_validation_function_dependencies
            """)
            
            # Create dependency mapping
            dependency_map = {}
            for dep in dependencies:
                # Make sure dep is a dictionary before using .get()
                if not isinstance(dep, dict):
                    logger.error(f"Expected dictionary for dependency but got {type(dep)}: {dep}")
                    continue
                    
                func_name = dep.get('function_name')
                depends_on = dep.get('depends_on')
                
                if not func_name or not depends_on:
                    logger.error(f"Missing function_name or depends_on in dependency: {dep}")
                    continue
                
                if func_name not in dependency_map:
                    dependency_map[func_name] = set()
                    
                dependency_map[func_name].add(depends_on)
            
            # Register functions in memory
            with self.lock:
                self.functions = {}
                
                for func in functions:
                    # Make sure func is a dictionary before using .get()
                    if not isinstance(func, dict):
                        logger.error(f"Expected dictionary for function but got {type(func)}: {func}")
                        continue
                        
                    function_name = func.get('function_name')
                    if not function_name:
                        logger.error(f"Missing function_name in function: {func}")
                        continue
                    
                    self.functions[function_name] = {
                        'id': func.get('id'),
                        'display_name': func.get('display_name', ''),
                        'description': func.get('description', ''),
                        'module_path': func.get('module_path', ''),
                        'function_path': func.get('function_path', ''),
                        'priority': func.get('priority', 100),
                        'enabled': func.get('enabled', True),
                        'dependencies': dependency_map.get(function_name, set()),
                        'func': None  # Function will be dynamically loaded when needed
                    }
                
                # Calculate execution order based on dependencies and priority
                self._update_execution_order()
                
                logger.info(f"Loaded {len(self.functions)} validation functions from database")
                
        except Exception as e:
            logger.error(f"Error loading validation functions from database: {e}")
    
    def reload(self):
        """Reload all functions and dependencies from database."""
        with self.lock:
            self._load_from_database()
            logger.info("Reloaded validation functions from database")
            
            # Clear cache
            cache_manager.delete(self._cache_key)
    
    def get_function(self, function_name: str) -> Optional[Callable]:
        """Get a function by name, dynamically loading it from configured module."""
        if function_name not in self.functions:
            return None
            
        func_info = self.functions[function_name]
        
        # Return if already loaded
        if func_info['func'] is not None:
            return func_info['func']
            
        # Load the function dynamically
        module_path = None
        function_path = None
        try:
            module_path = func_info['module_path']
            function_path = func_info['function_path']
            
            # Import the module
            module = importlib.import_module(module_path)
            
            # Get the function
            func = getattr(module, function_path)
            
            # Cache the loaded function
            with self.lock:
                self.functions[function_name]['func'] = func
                
            return func
        except Exception as e:
            logger.error(f"Error loading function {function_name} from {module_path}.{function_path}: {e}")
            return None
    
    def _update_execution_order(self):
        """Update execution order based on dependencies and priorities."""
        with self.lock:
            # Build dependency graph
            graph = {name: info['dependencies'].copy() for name, info in self.functions.items()}
            
            # Topological sort with priority as tiebreaker
            result = []
            no_deps = [name for name, deps in graph.items() if not deps]
            
            # Sort no_deps by priority (lowest first)
            no_deps.sort(key=lambda name: self.functions[name]['priority'])
            
            while no_deps:
                # Get next function with highest priority
                node = no_deps.pop(0)
                result.append(node)
                
                # Remove this node from all dependency lists
                for name in list(graph.keys()):
                    if node in graph[name]:
                        graph[name].remove(node)
                        if not graph[name]:
                            # Insert based on priority
                            priority = self.functions[name]['priority']
                            inserted = False
                            
                            for i, existing in enumerate(no_deps):
                                if priority < self.functions[existing]['priority']:
                                    no_deps.insert(i, name)
                                    inserted = True
                                    break
                                    
                            if not inserted:
                                no_deps.append(name)
                                
                # Remove from graph
                if node in graph:
                    del graph[node]
            
            # Check for circular dependencies
            if graph:
                logger.error("Circular dependencies detected in validation functions!")
                # Add remaining functions in priority order
                remaining = sorted(graph.keys(), key=lambda n: self.functions[n]['priority'])
                result.extend(remaining)
            
            self.execution_order = result
    
    def enable(self, function_name: str):
        """Enable a function."""
        return self._set_enabled_status(function_name, True)
    
    def disable(self, function_name: str):
        """Disable a function."""
        return self._set_enabled_status(function_name, False)
    
    def _set_enabled_status(self, function_name: str, enabled: bool):
        """Set enabled status for a function."""
        try:
            if function_name not in self.functions:
                logger.error(f"Function {function_name} doesn't exist")
                return False
                
            # Update database
            sync_db.execute(
                "UPDATE email_validation_functions SET enabled = $1 WHERE function_name = $2",
                enabled, function_name
            )
            
            # Update in-memory registry
            with self.lock:
                self.functions[function_name]['enabled'] = enabled
                
                # Clear cache
                cache_manager.delete(self._cache_key)
                
            status = "enabled" if enabled else "disabled"
            logger.info(f"Function {function_name} {status}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting enabled status: {e}")
            return False
    
    def execute(self, context):
        """Execute all validation functions in proper order with dependencies."""
        from src.managers.log import get_logger
        email_logger = get_logger()
        
        email = context.get('email')
        trace_id = context.get('trace_id')
        track_steps = context.get('track_steps', False)
        
        if email:
            logger.debug(f"Queue execution starting for: {email}")

        # Add code to create parent record first if needed
        if track_steps and trace_id and email:
            try:
                # Check if record already exists
                exists = sync_db.fetchval(
                    "SELECT 1 FROM email_validation_records WHERE trace_id = $1",
                    trace_id
                )
                
                if not exists:
                    # Create the parent record
                    domain = email.split('@')[1] if '@' in email else ""
                    sync_db.execute(
                        """
                        INSERT INTO email_validation_records 
                        (trace_id, email, domain, timestamp)
                        VALUES ($1, $2, $3, NOW())
                        ON CONFLICT (trace_id) DO NOTHING
                        """,
                        trace_id, email, domain
                    )
                    logger.debug(f"Created validation record for trace_id: {trace_id}")
            except Exception as e:
                logger.error(f"Failed to create validation record: {e}")
        
        results = {}
        
        # Lock to prevent concurrent execution
        with self.lock:
            # Update execution order just in case it changed
            self._update_execution_order()
            
            # Execute functions in order
            for function_name in self.execution_order:
                if not self.functions[function_name]['enabled']:
                    continue
                    
                # Check dependencies
                dependencies_met = True
                for dep in self.functions[function_name]['dependencies']:
                    if dep not in results or not results[dep].get('valid', False):
                        dependencies_met = False
                        if email:
                            logger.debug(f"Skipping {function_name}: dependency {dep} not met")
                        break
                
                if not dependencies_met:
                    # Skip this function as dependencies aren't met
                    results[function_name] = {
                        'valid': False, 
                        'error': 'Dependencies not met', 
                        'step': function_name
                    }
                    continue
                
                # Get the function
                func = self.get_function(function_name)
                if not func:
                    logger.debug(f"Failed to load function: {function_name}")
                    results[function_name] = {
                        'valid': False, 
                        'error': 'Function not found', 
                        'step': function_name
                    }
                    continue
                
                # Execute the function with step tracking
                start_time = None  # Ensure start_time is always defined
                try:
                    if email:
                        logger.debug(f"Executing function: {function_name}")
                    
                    start_time = datetime.now()
                    
                    # Execute the function
                    func_result = func(context)
                    
                    end_time = datetime.now()
                    
                    # Calculate execution time
                    elapsed_ms = (end_time - start_time).total_seconds() * 1000
                    
                    # Store result
                    results[function_name] = func_result
                    
                    # Log step to database if tracking enabled
                    if track_steps and trace_id:
                        try:
                            # Fix: Check if func_result is a dictionary, if not, convert it
                            if not isinstance(func_result, dict):
                                # Handle string or other non-dict result
                                error_msg = str(func_result) if func_result else "Unknown error"
                                func_result = {
                                    'valid': False,
                                    'error': error_msg,
                                    'step': function_name
                                }
                            
                            values = {
                                "trace_id": trace_id,
                                "email": email,
                                "step_name": self.functions[function_name]['display_name'],
                                "function_name": function_name,
                                "step_order": len(results),
                                "start_time": start_time,
                                "end_time": end_time,
                                "duration_ms": elapsed_ms,
                                "status": "success" if func_result.get('valid', False) else "failed",
                                "is_success": func_result.get('valid', False),
                                "result": json.dumps(func_result),
                                "errors": func_result.get('error')
                            }
                            
                            columns = ", ".join(values.keys())
                            placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
                            
                            sync_db.execute(
                                f"INSERT INTO validation_steps ({columns}) VALUES ({placeholders})",
                                *values.values()
                            )
                        except Exception as e:
                            logger.warning(f"Failed to log validation step: {e}")
                    
                    # Log result
                    valid = func_result.get('valid', False)
                    if email:
                        logger.debug(f"Function {function_name} completed in {elapsed_ms:.1f}ms: {'PASS' if valid else 'FAIL'}")
                        
                        # Log extra details on failure
                        if not valid and 'error' in func_result:
                            logger.error(f"  Error: {func_result['error']}")
                except Exception as e:
                    logger.error(f"Error in validation function {function_name}: {e}")
                    results[function_name] = {
                        'valid': False, 
                        'error': str(e), 
                        'step': function_name
                    }
                    
                    # Log error step
                    if track_steps and trace_id:
                        try:
                            end_time = datetime.now()
                            # Ensure start_time is always defined
                            safe_start_time = start_time if start_time is not None else end_time
                            duration_ms = (end_time - safe_start_time).total_seconds() * 1000
                            values = {
                                "trace_id": trace_id,
                                "email": email,
                                "step_name": self.functions[function_name]['display_name'],
                                "function_name": function_name,
                                "step_order": len(results),
                                "start_time": safe_start_time,
                                "end_time": end_time,
                                "duration_ms": duration_ms,
                                "status": "error",
                                "is_success": False,
                                "result": None,
                                "errors": str(e)
                            }
                            
                            columns = ", ".join(values.keys())
                            placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
                            
                            sync_db.execute(
                                f"INSERT INTO validation_steps ({columns}) VALUES ({placeholders})",
                                *values.values()
                            )
                        except Exception as log_err:
                            logger.warning(f"Failed to log validation step error: {log_err}")
    
        if email:
            logger.debug(f"Queue execution completed with {sum(1 for r in results.values() if r.get('valid', False))}/{len(results)} valid steps")
    
        return results
    
    def get_config(self) -> Dict[str, Any]:
        """Get the current queue configuration."""
        # Check cache
        config = cache_manager.get(self._cache_key)
        if config:
            return config
            
        with self.lock:
            config = {
                'functions': {},
                'execution_order': self.execution_order
            }
            
            for name, info in self.functions.items():
                config['functions'][name] = {
                    'id': info['id'],
                    'display_name': info['display_name'], 
                    'description': info['description'],
                    'priority': info['priority'],
                    'enabled': info['enabled'],
                    'dependencies': list(info['dependencies']),
                }
            
            # Cache the config
            cache_manager.set(self._cache_key, config)
            
            return config