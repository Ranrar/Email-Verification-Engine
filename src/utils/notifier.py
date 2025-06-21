"""
Email Verification Engine
===================================
Notifier Module for Eel-based Python Apps

This lightweight Python Notifier module lets you send styled notification messages 
from Python to the frontend in Eel-based desktop applications.

Features:

    Simple API: notify.info(), notify.error(), etc.
    
    Control over persistence: decide if notifications stay until clicked
    
    Optional details for additional context
    
    Fully frontend-agnostic - only requires a small JS/CSS snippet

Ideal for showing success messages, errors, task progress, and user feedback with minimal frontend code.

# In any Python function exposed to Eel
from src.utils.notifier import Notifier

notify = Notifier()
notify.info("This is an information message")
notify.success("Task completed successfully")
notify.error("Something went wrong")
notify.warning("Be careful with this action")
"""

import eel
from typing import Optional

class Notifier:
    def __init__(self):
        pass

    def _send(self, message: str, details: Optional[str] = None, type_name: str = "info", persistent: bool = False):
        """Internal function to send message to frontend."""
        eel.show_message(type_name, message, persistent, details)  # type: ignore

    def info(self, message: str, details: Optional[str] = None, persistent: bool = False):
        """Send an information message. Default: not persistent."""
        self._send(message, details, "info", persistent)

    def success(self, message: str, details: Optional[str] = None, persistent: bool = False):
        """Send a success message. Default: not persistent."""
        self._send(message, details, "success", persistent)

    def error(self, message: str, details: Optional[str] = None, persistent: bool = True):
        """Send error notification. Default: persistent until clicked."""
        self._send(message, details, "error", persistent)

    def warning(self, message: str, details: Optional[str] = None, persistent: bool = True):
        """Send warning notification. Default: persistent until clicked."""
        self._send(message, details, "warning", persistent)

    def custom(self, message: str, details: Optional[str] = None, type_name: str = "info", persistent: bool = False):
        """Send a message with full control over type and persistence."""
        self._send(message, details, type_name, persistent)