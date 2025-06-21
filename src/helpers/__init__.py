"""
Email Verification Engine Helpers
=================================
Common utility functions and helpers
"""

from .tracer import (
    generate_trace_id,
    generate_span_id,
    get_current_trace_id,
    set_current_trace_id,
    get_or_create_trace_id,
    ensure_trace_id,
    validate_trace_id,
    ensure_context_has_trace_id,
    create_child_trace_id,
    trace_function,
    TraceableContext
)

__all__ = [
    'generate_trace_id',
    'generate_span_id', 
    'get_current_trace_id',
    'set_current_trace_id',
    'get_or_create_trace_id',
    'ensure_trace_id',
    'validate_trace_id',
    'ensure_context_has_trace_id',
    'create_child_trace_id',
    'trace_function',
    'TraceableContext'
]