"""
Email Verification Engine
===================================
Time management utilities:
This module provides timing-related functionality for measuring and reporting
execution time across the application.

TIMEZONE BEST PRACTICES:
-----------------------
Always use timezone-aware datetimes with UTC:
    dt = now_utc()  # Preferred over datetime.now() or datetime.utcnow()

When working with PostgreSQL:
    - Database columns: Use TIMESTAMPTZ type
    - Comparison: Only compare aware ↔ aware datetimes 
    - Insertion: Always pass timezone-aware datetimes to SQL

Available Functions:
    - now_utc(): Get current UTC time (timezone-aware)
    - normalize_datetime(): Convert any datetime to timezone-aware UTC
    - to_iso8601(): Format datetime as ISO 8601 string
    - from_iso8601(): Parse ISO 8601 string to datetime
    - ensure_timezone_aware(): Validate a datetime is timezone-aware
"""

import functools
import json
import threading
import uuid
import time
import pytz
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from src.managers.log import get_logger

logger = get_logger()

def now_utc() -> datetime:
    """
    Get current time as timezone-aware UTC datetime.
    This is the preferred way to get current time in the application.
    
    Returns:
        Current time as timezone-aware datetime in UTC
    """
    return datetime.now(timezone.utc)

def normalize_datetime(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Ensures all datetime objects are timezone-aware and in UTC.
        
    Args:
        dt: A datetime object or None
        
    Returns:
        A timezone-aware datetime object in UTC, or None if input was None
    """
    if dt is None:
        return None
        
    # If naive (no timezone), force to UTC
    if dt.tzinfo is None:
        logger.debug(f"Converting naive datetime to UTC: {dt}")
        dt = dt.replace(tzinfo=timezone.utc)
    # If already has timezone but not UTC, convert to UTC
    elif dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    
    return dt

def ensure_timezone_aware(dt: datetime, context: str = "unknown") -> datetime:
    """
    Ensures a datetime is timezone-aware, raising warning if not.
    
    Args:
        dt: Datetime to validate
        context: Context for error message
        
    Returns:
        Normalized timezone-aware datetime
    
    Raises:
        ValueError: If dt is None
    """
    if dt is None:
        raise ValueError(f"None datetime in {context}")
        
    if dt.tzinfo is None:
        logger.warning(f"Timezone-naive datetime used in {context}. Always use datetime.now(timezone.utc)")
        normalized = normalize_datetime(dt)
        if normalized is None:
            raise ValueError(f"Failed to normalize datetime in {context}")
        return normalized
    return dt

def to_iso8601(dt: Optional[datetime]) -> Optional[str]:
    """
    Convert datetime to ISO 8601 string format with timezone.
    Ensures compatibility with PostgreSQL's timestamp formatting.
    
    Args:
        dt: A datetime object (will be normalized to UTC)
        
    Returns:
        ISO 8601 formatted string with timezone indicator (Z)
    """
    if dt is None:
        return None
        
    # Normalize to UTC first
    dt = normalize_datetime(dt)
    if dt is None:
        return None
    
    # Format as ISO 8601 with Z suffix (preferred for JSON and DB)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def from_iso8601(iso_str: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO 8601 formatted string to timezone-aware datetime object.
    Handles both Z suffix and explicit +00:00 formats.
    
    Args:
        iso_str: ISO 8601 formatted datetime string
        
    Returns:
        UTC timezone-aware datetime object
    """
    if not iso_str:
        return None
        
    # Handle 'Z' suffix
    if iso_str.endswith('Z'):
        iso_str = iso_str[:-1] + '+00:00'
    
    # Parse ISO format
    dt = datetime.fromisoformat(iso_str)
    
    # Ensure timezone is UTC
    return dt.astimezone(timezone.utc)

def measure_time(func):
    """
    Decorator to measure execution time of src.
    Always returns (result, timing_ms) tuple.
    
    Args:
        func: The function to measure
        
    Returns:
        Wrapped function that returns (original_result, elapsed_ms)
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return result, elapsed_ms
    return wrapper

def add_timing_to_dict(result_dict: dict, method_name: str, elapsed_ms):
    """
    Add timing information to a result dictionary safely.
    
    Args:
        result_dict: Dictionary to add timing info to
        method_name: Name of method/operation being timed
        elapsed_ms: Elapsed time in milliseconds
        
    Returns:
        Updated dictionary with timing information
    """
    if elapsed_ms is not None:
        try:
            result_dict[f"{method_name}_time_ms"] = round(float(elapsed_ms), 2)
        except (TypeError, ValueError):
            # Handle case where elapsed_ms can't be converted to float
            result_dict[f"{method_name}_time_ms"] = elapsed_ms
    else:
        # Use 0 or None for unavailable timing data
        result_dict[f"{method_name}_time_ms"] = 0  # Alternative: use None
    return result_dict

class TimingStats:
    """
    Class to collect and report timing statistics.
    
    Collects timing measurements for different operations and provides
    methods to retrieve and report on those timings.
    """
    def __init__(self):
        self.timings = {}
        
    def add_timing(self, operation: str, elapsed_ms: float):
        """
        Add a timing measurement.
        
        Args:
            operation: Name of the operation being timed
            elapsed_ms: Elapsed time in milliseconds
        """
        self.timings[operation] = elapsed_ms
        
    def get_all_timings(self) -> Dict[str, float]:
        """
        Get all timing measurements.
        
        Returns:
            Dictionary of operation:time_ms pairs
        """
        return self.timings
        
    def get_total_time(self) -> float:
        """
        Get sum of all timing measurements.
        
        Returns:
            Total time in milliseconds
        """
        return sum(self.timings.values())
        
    def __str__(self) -> str:
        """
        String representation of timing stats.
        
        Returns:
            Formatted string with all timings and total
        """
        parts = [f"{op}: {time:.2f}ms" for op, time in self.timings.items()]
        total = self.get_total_time()
        parts.append(f"Total: {total:.2f}ms")
        return ", ".join(parts)


@dataclass
class TraceSpan:
    """
    Represents a single span in a trace (an operation being timed)
    """
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operation_name: str = "unnamed_operation"
    start_time: float = field(default_factory=time.perf_counter)
    end_time: Optional[float] = None
    elapsed_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    children: List[str] = field(default_factory=list)  # List of child span IDs
    
    def finish(self) -> Optional[float]:
        """Mark the span as complete and calculate elapsed time"""
        if not self.end_time:
            self.end_time = time.perf_counter()
            self.elapsed_ms = (self.end_time - self.start_time) * 1000
        return self.elapsed_ms
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the span"""
        self.metadata[key] = value
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "trace_id": self.trace_id,
            "operation_name": self.operation_name,
            "start_time_epoch": self.start_time,
            "end_time_epoch": self.end_time,
            "elapsed_ms": self.elapsed_ms,
            "metadata": self.metadata,
            "children": self.children
        }


class TraceManager:
    """
    Manages traces across module boundaries
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        self.traces = {}  # trace_id -> dict of spans
        self.active_spans = {}  # span_id -> TraceSpan
        self.current_span = threading.local()  # Thread-local storage for current span
        self._lock = threading.Lock()
        
    def start_trace(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None) -> TraceSpan:
        """Start a new trace with no parent"""
        span = TraceSpan(operation_name=operation_name, metadata=metadata or {})
        
        with self._lock:
            if span.trace_id not in self.traces:
                self.traces[span.trace_id] = {}
            self.traces[span.trace_id][span.span_id] = span
            self.active_spans[span.span_id] = span
            
        self.current_span.span = span
        logger.debug(f"Started trace {span.trace_id} with root span {span.span_id} ({operation_name})")
        return span
    
    def start_span(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None) -> TraceSpan:
        """Start a new span under the current span"""
        parent_span = getattr(self.current_span, 'span', None)
        
        # Create the new span
        span = TraceSpan(
            operation_name=operation_name,
            metadata=metadata or {},
            trace_id=parent_span.trace_id if parent_span else str(uuid.uuid4()),
            parent_span_id=parent_span.span_id if parent_span else None
        )
        
        with self._lock:
            if span.trace_id not in self.traces:
                self.traces[span.trace_id] = {}
            self.traces[span.trace_id][span.span_id] = span
            self.active_spans[span.span_id] = span
            
            # Update parent's children list if there is a parent
            if parent_span:
                parent_span.children.append(span.span_id)
        
        # Update thread-local current span
        self.current_span.span = span
        logger.debug(f"Started span {span.span_id} ({operation_name}) under trace {span.trace_id}")
        return span
    
    def finish_span(self, span_id: Optional[str] = None) -> Optional[float]:
        """Finish a span by ID or the current span"""
        span = None
        
        if span_id is None:
            # Use the current span
            span = getattr(self.current_span, 'span', None)
            if not span:
                logger.warning("No current span to finish")
                return None
        else:
            # Use the specified span
            with self._lock:
                span = self.active_spans.get(span_id)
                
        if not span:
            logger.warning(f"Span {span_id} not found or already finished")
            return None
            
        # Finish the span and calculate elapsed time
        elapsed_ms = span.finish()
        
        # Clean up
        with self._lock:
            if span.span_id in self.active_spans:
                del self.active_spans[span.span_id]
                
        # If this span has a parent, make the parent current again
        if span.parent_span_id:
            parent = None
            with self._lock:
                if span.trace_id in self.traces and span.parent_span_id in self.traces[span.trace_id]:
                    parent = self.traces[span.trace_id][span.parent_span_id]
            
            if parent:
                self.current_span.span = parent
                
        logger.debug(f"Finished span {span.span_id} ({span.operation_name}) in {elapsed_ms:.2f}ms")
        return elapsed_ms
    
    def get_trace(self, trace_id: str) -> Dict[str, TraceSpan]:
        """Get all spans for a trace"""
        with self._lock:
            return self.traces.get(trace_id, {}).copy()
    
    def export_trace(self, trace_id: str) -> Dict[str, Any]:
        """Export a trace in a serializable format"""
        trace_spans = self.get_trace(trace_id)
        if not trace_spans:
            return {}
            
        return {
            "trace_id": trace_id,
            "spans": {span_id: span.to_dict() for span_id, span in trace_spans.items()},
            "start_time": min(span.start_time for span in trace_spans.values()),
            "end_time": max((span.end_time or 0) for span in trace_spans.values()),
            "total_time_ms": sum((span.elapsed_ms or 0) for span in trace_spans.values() 
                              if not span.parent_span_id)  # Sum only root spans
        }
    
    def save_trace(self, trace_id: str, file_path: str) -> bool:
        """Save a trace to a JSON file"""
        trace_data = self.export_trace(trace_id)
        if not trace_data:
            return False
            
        try:
            with open(file_path, 'w') as f:
                json.dump(trace_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save trace: {e}")
            return False


class EnhancedOperationTimer:
    """
    Enhanced context manager for timing code blocks with tracing support
    
    Example:
        with EnhancedOperationTimer("validate_email") as timer:
            # code to time
            from src.engine.engine import get_engine
            result = get_engine().validate("user@example.com")
            
        # Access the timing information
        elapsed_ms = timer.elapsed_ms
        span_id = timer.span_id
        trace_id = timer.trace_id
    """
    def __init__(self, operation_name=None, metadata=None, trace_manager=None, 
                 start_new_trace=False):
        self.operation_name = operation_name or "unnamed_operation"
        self.metadata = metadata or {}
        self.trace_manager = trace_manager or TraceManager.get_instance()
        self.span = None
        self.elapsed_ms = None
        self.start_new_trace = start_new_trace
    
    def __enter__(self):
        if self.start_new_trace:
            self.span = self.trace_manager.start_trace(self.operation_name, self.metadata)
        else:
            self.span = self.trace_manager.start_span(self.operation_name, self.metadata)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type and self.span is not None:
            # Add exception info to the span metadata
            self.span.add_metadata("exception_type", exc_type.__name__)
            self.span.add_metadata("exception_message", str(exc_val))
        
        if self.span is not None:
            self.elapsed_ms = self.trace_manager.finish_span(self.span.span_id)
            logger.debug(f"{self.operation_name} completed in {self.elapsed_ms:.2f}ms")
        else:
            self.elapsed_ms = None
    
    @property
    def span_id(self):
        return self.span.span_id if self.span else None
    
    @property
    def trace_id(self):
        return self.span.trace_id if self.span else None
    
    def add_metadata(self, key, value):
        """Add metadata to the current span"""
        if self.span:
            self.span.add_metadata(key, value)


class TimeManager:
    """
    Manages timing operations, metrics, and traces throughout the application.
    Implemented as a singleton.
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        self.timing_stats = {}  # Store timing statistics by category
        self.trace_manager = TraceManager.get_instance()
    
    def measure_function(self, func):
        """Decorator to measure execution time of src."""
        return measure_time(func)
        
    def add_timing(self, result_dict, method_name, elapsed_ms):
        """Add timing information to a result dictionary safely."""
        return add_timing_to_dict(result_dict, method_name, elapsed_ms)
    
    def create_stats(self, category='default'):
        """Create a new TimingStats object for a category."""
        if category not in self.timing_stats:
            self.timing_stats[category] = TimingStats()
        return self.timing_stats[category]
    
    def get_stats(self, category='default'):
        """Get timing statistics for a category."""
        return self.timing_stats.get(category)
    
    def start_trace(self, operation_name, metadata=None):
        """Start a new trace and return the span"""
        return self.trace_manager.start_trace(operation_name, metadata)
    
    def start_span(self, operation_name, metadata=None):
        """Start a new span under the current trace"""
        return self.trace_manager.start_span(operation_name, metadata)
    
    def finish_span(self, span_id=None):
        """Finish a span by ID or the current span"""
        return self.trace_manager.finish_span(span_id)
    
    def get_trace(self, trace_id):
        """Get a trace by ID"""
        return self.trace_manager.get_trace(trace_id)
    
    def export_trace(self, trace_id):
        """Export a trace in a serializable format"""
        return self.trace_manager.export_trace(trace_id)
    
    def save_trace(self, trace_id, file_path):
        """Save a trace to a file"""
        return self.trace_manager.save_trace(trace_id, file_path)
    
    def create_timer(self, operation_name=None, metadata=None, start_new_trace=False):
        """Create an EnhancedOperationTimer for timing code blocks with tracing"""
        return EnhancedOperationTimer(
            operation_name=operation_name,
            metadata=metadata,
            trace_manager=self.trace_manager,
            start_new_trace=start_new_trace
        )


# Additional timing utility functions

def time_function_call(func, *args, **kwargs):
    """
    Measure time of a function call without using a decorator.
    Useful for one-off timing measurements.
    
    Args:
        func: Function to call
        *args, **kwargs: Arguments to pass to the function
        
    Returns:
        Tuple of (function_result, elapsed_ms)
    """
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms


class OperationTimer:
    """
    Context manager for timing code blocks.
    
    Example:
        with OperationTimer() as timer:
            # code to time
            result = some_operation()
            
        elapsed_ms = timer.elapsed_ms
        logger.debug(f"Operation took {elapsed_ms:.2f}ms")
    """
    def __init__(self, operation_name=None):
        self.operation_name = operation_name
        self.start_time = None
        self.end_time = None
        self.elapsed_ms = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        if self.start_time is not None and self.end_time is not None:
            self.elapsed_ms = (self.end_time - self.start_time) * 1000
        else:
            self.elapsed_ms = None
        if self.operation_name:
            logger.debug(f"{self.operation_name} completed in {self.elapsed_ms:.2f}ms")


# Helper function to get the current trace ID
def get_current_trace_id():
    """Get the current trace ID or None if no active trace"""
    trace_manager = TraceManager.get_instance()
    current_span = getattr(trace_manager.current_span, 'span', None)
    return current_span.trace_id if current_span else None


# Example decorator for tracing function calls
def trace_function(operation_name=None, start_new_trace=False):
    """
    Decorator to trace function execution with timing
    
    Args:
        operation_name: Name for the operation (defaults to function name)
        start_new_trace: If True, starts a new trace instead of a child span
        
    Returns:
        Decorated function that traces execution time
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = operation_name or func.__name__
            trace_manager = TraceManager.get_instance()
            
            # Create metadata with function info
            metadata = {
                "function": func.__name__,
                "module": func.__module__,
                "args_count": len(args),
                "kwargs_count": len(kwargs)
            }
            
            # Start span or trace
            if start_new_trace:
                span = trace_manager.start_trace(func_name, metadata)
            else:
                span = trace_manager.start_span(func_name, metadata)
                
            try:
                # Execute the function
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                # Add exception info to span
                span.add_metadata("exception_type", type(e).__name__)
                span.add_metadata("exception_message", str(e))
                raise
            finally:
                # Finish the span
                trace_manager.finish_span(span.span_id)
                
        return wrapper
    return decorator

# Create global instance
time_manager = TimeManager.get_instance()