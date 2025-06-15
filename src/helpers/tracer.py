"""
Email Verification Engine
===================================
Trace_id helper for distributed tracing and operation tracking
"""

import uuid
import threading
from typing import Optional, Dict, Any, Callable
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Thread-local storage for current trace context
_trace_context = threading.local()

class TraceContext:
    """Thread-local trace context management"""
    
    def __init__(self, trace_id: str, parent_span_id: Optional[str] = None):
        self.trace_id = trace_id
        self.parent_span_id = parent_span_id
        self.span_stack = []
        
    def push_span(self, span_id: str):
        """Push a new span onto the stack"""
        self.span_stack.append(span_id)
        
    def pop_span(self) -> Optional[str]:
        """Pop the current span from the stack"""
        return self.span_stack.pop() if self.span_stack else None
        
    def current_span_id(self) -> Optional[str]:
        """Get the current span ID"""
        return self.span_stack[-1] if self.span_stack else None

def generate_trace_id() -> str:
    """Generate a new UUID for trace_id"""
    return str(uuid.uuid4())

def generate_span_id() -> str:
    """Generate a new UUID for span_id"""
    return str(uuid.uuid4())

def get_current_trace_id() -> Optional[str]:
    """Get the current trace_id from thread-local storage"""
    try:
        trace_context = getattr(_trace_context, 'trace_context', None)
        return trace_context.trace_id if trace_context else None
    except AttributeError:
        return None

def set_current_trace_id(trace_id: str, parent_span_id: Optional[str] = None) -> None:
    """Set the current trace_id in thread-local storage"""
    _trace_context.trace_context = TraceContext(trace_id, parent_span_id)

def get_or_create_trace_id(provided_trace_id: Optional[str] = None) -> str:
    """Get existing trace_id or create a new one if none exists"""
    if provided_trace_id:
        set_current_trace_id(provided_trace_id)
        return provided_trace_id
    
    current = get_current_trace_id()
    if current:
        return current
    
    # Create new trace_id
    new_trace_id = generate_trace_id()
    set_current_trace_id(new_trace_id)
    logger.debug(f"Created new trace_id: {new_trace_id}")
    return new_trace_id

def ensure_trace_id(trace_id: Optional[str] = None) -> str:
    """Ensure a valid trace_id exists, creating one if necessary"""
    return get_or_create_trace_id(trace_id)

def validate_trace_id(trace_id: Optional[str]) -> bool:
    """Validate that a trace_id is a valid UUID format"""
    if not trace_id:
        return False
    try:
        uuid.UUID(trace_id)
        return True
    except (ValueError, TypeError):
        return False

def ensure_context_has_trace_id(context: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure context object contains a valid trace_id"""
    if not context:
        context = {}
    
    existing_trace_id = context.get('trace_id')
    
    # Validate existing trace_id
    if not validate_trace_id(existing_trace_id):
        # Create or get current trace_id
        context['trace_id'] = get_or_create_trace_id(existing_trace_id)
        if existing_trace_id:
            logger.warning(f"Invalid trace_id '{existing_trace_id}' replaced with '{context['trace_id']}'")
    else:
        # Set as current trace_id
        if existing_trace_id is not None:
            set_current_trace_id(existing_trace_id)
    
    return context

def create_child_trace_id(parent_trace_id: Optional[str] = None) -> str:
    """Create a new trace_id that inherits from a parent operation"""
    parent_id = parent_trace_id or get_current_trace_id()
    if parent_id:
        # For child operations, we could use the same trace_id but different span_ids
        # This maintains trace continuity across spawned operations
        return parent_id
    else:
        # No parent, create completely new trace
        return generate_trace_id()

def trace_function(operation_name: Optional[str] = None, 
                  inherit_trace: bool = True,
                  log_entry_exit: bool = True):
    """
    Decorator to automatically add tracing to functions
    
    Args:
        operation_name: Name for the operation (defaults to function name)
        inherit_trace: Whether to inherit parent trace_id
        log_entry_exit: Whether to log function entry/exit
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine operation name
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            # Handle trace_id for the function
            trace_id = None
            
            # Look for trace_id in various places
            if 'trace_id' in kwargs:
                trace_id = kwargs['trace_id']
            elif args and isinstance(args[0], dict) and 'trace_id' in args[0]:
                trace_id = args[0]['trace_id']
            elif args and not isinstance(args[0], dict) and hasattr(args[0], 'trace_id'):
                trace_id = args[0].trace_id
            
            # Ensure we have a valid trace_id
            if inherit_trace:
                trace_id = get_or_create_trace_id(trace_id)
            else:
                trace_id = trace_id or generate_trace_id()
                set_current_trace_id(trace_id)
            
            # Update context if it exists
            if args and isinstance(args[0], dict):
                args[0]['trace_id'] = trace_id
            
            # Generate span_id for this function call
            span_id = generate_span_id()
            
            # Get current context and push new span
            current_context = getattr(_trace_context, 'trace_context', None)
            if current_context:
                current_context.push_span(span_id)
            
            if log_entry_exit:
                logger.debug(f"[{trace_id}:{span_id}] Entering {op_name}")
            
            try:
                result = func(*args, **kwargs)
                
                if log_entry_exit:
                    logger.debug(f"[{trace_id}:{span_id}] Exiting {op_name} successfully")
                
                return result
                
            except Exception as e:
                logger.error(f"[{trace_id}:{span_id}] Error in {op_name}: {str(e)}")
                raise
            finally:
                # Pop span from stack
                if current_context:
                    current_context.pop_span()
        
        return wrapper
    return decorator

class TraceableContext:
    """Context manager for trace operations"""
    
    def __init__(self, trace_id: Optional[str] = None, operation_name: str = "operation"):
        self.trace_id = get_or_create_trace_id(trace_id)
        self.operation_name = operation_name
        self.span_id = generate_span_id()
        self.previous_context = None
        
    def __enter__(self):
        # Store previous context
        self.previous_context = getattr(_trace_context, 'trace_context', None)
        
        # Set new context
        new_context = TraceContext(self.trace_id)
        new_context.push_span(self.span_id)
        _trace_context.trace_context = new_context
        
        logger.debug(f"[{self.trace_id}:{self.span_id}] Started {self.operation_name}")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.error(f"[{self.trace_id}:{self.span_id}] Error in {self.operation_name}: {exc_val}")
        else:
            logger.debug(f"[{self.trace_id}:{self.span_id}] Completed {self.operation_name}")
        
        # Restore previous context
        _trace_context.trace_context = self.previous_context