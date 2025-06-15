"""
Email Verification Engine
===================================
Public Suffix List (PSL) Management Module

The Public Suffix List is a database of domain name suffixes (TLDs) maintained by Mozilla.
It helps identify the boundary between the registrable domain and the public suffix
(e.g., example.co.uk -> registrable domain is "example", public suffix is "co.uk").

This module provides functionality to:
1. Download the latest PSL from the official repository
2. Parse and extract suffix information (ICANN vs private domains, wildcards, etc.)
3. Update the local database with PSL entries
4. Track version changes and manage updates
5. Support organizational domain extraction for email validation

The PSL is critical for correctly analyzing domains for:
- DMARC/DKIM/SPF validation
- Email provider detection
- Domain reputation analysis
- Properly handling ccTLDs and multi-part TLDs

Usage:
  - During initialization: `initialize_suffix_list()` checks and updates if needed
  - Force an update: `update_public_suffix_list(force=True)`
  - Internal use: Consumed by domain validation components

Database Tables:
  - public_suffix_list: Stores all suffix entries and metadata
  - public_suffix_list_version: Tracks version history and update dates

References:
  - https://publicsuffix.org/
  - https://github.com/publicsuffix/list
"""

import os
import re
import requests
import shutil
import hashlib
from datetime import datetime
from pathlib import Path

from src.helpers.dbh import sync_db
from src.managers.log import get_logger

logger = get_logger()

# Constants
PSL_URL = "https://raw.githubusercontent.com/publicsuffix/list/refs/heads/main/public_suffix_list.dat"
TEMP_DIR = Path(".temp")

def download_psl_file():
    """
    Download the latest Public Suffix List file from GitHub.
    
    Returns:
        Path: Path to the downloaded file
    """
    logger.info("Downloading Public Suffix List...")
    
    # Create temp directory if it doesn't exist
    temp_dir = TEMP_DIR
    temp_dir.mkdir(exist_ok=True)
    
    # Download the file
    response = requests.get(PSL_URL)
    response.raise_for_status()
    
    # Save to temporary file
    temp_file = temp_dir / "public_suffix_list.dat"
    with open(temp_file, "wb") as f:
        f.write(response.content)
    
    logger.info(f"Downloaded Public Suffix List to {temp_file}")
    return temp_file

def get_file_hash(file_path):
    """
    Calculate SHA256 hash of a file.
    
    Args:
        file_path (Path): Path to the file
    
    Returns:
        str: Hexadecimal hash string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def parse_psl_file(file_path):
    """
    Parse the Public Suffix List file and extract suffix information.
    
    Args:
        file_path (Path): Path to the PSL file
    
    Returns:
        tuple: (list of entries, version hash)
    """
    logger.info(f"Parsing Public Suffix List from {file_path}...")
    
    entries = []
    current_category = "UNKNOWN"
    current_country_code = None
    current_source_url = None
    current_description = None
    current_organization = None
    
    # Read the file
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        lines = content.splitlines()
    
    # Use file hash as version identifier
    version = get_file_hash(file_path)
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # Process comments
        if line.startswith("//"):
            comment = line[2:].strip()
            
            # Check for section markers
            if "BEGIN ICANN DOMAINS" in comment:
                current_category = "ICANN"
                continue
            elif "END ICANN DOMAINS" in comment:
                current_category = "UNKNOWN"
                continue
            elif "BEGIN PRIVATE DOMAINS" in comment:
                current_category = "PRIVATE"
                continue
            elif "END PRIVATE DOMAINS" in comment:
                current_category = "UNKNOWN"
                continue
            
            # Try to extract country code and URL from comments like "// cc : http://..."
            country_code_match = re.search(r"^([a-z]{2})\s*:", comment)
            if country_code_match:
                current_country_code = country_code_match.group(1).upper()
                # Find URL in the same line
                url_match = re.search(r"(https?://[^\s]+)", comment)
                if url_match:
                    current_source_url = url_match.group(1)
                continue
            
            # Try to extract organization info
            if "Submitted by" in comment:
                current_organization = comment.split("Submitted by")[1].strip()
                if "<" in current_organization and ">" in current_organization:
                    current_organization = current_organization.split("<")[0].strip()
            
            # Use remaining comments as description
            if not any(marker in comment for marker in ["BEGIN", "END", "Submitted by"]):
                current_description = comment
                
            continue
        
        # Process suffix entries
        is_wildcard = False
        is_exception = False
        suffix = line
        
        if line.startswith("!"):
            is_exception = True
        elif line.startswith("*."):
            is_wildcard = True
        
        entry = {
            "suffix": suffix,
            "is_wildcard": is_wildcard,
            "is_exception": is_exception,
            "category": current_category,
            "country_code": current_country_code,
            "organization": current_organization,
            "source_url": current_source_url,
            "description": current_description
        }
        
        entries.append(entry)
    
    logger.info(f"Parsed {len(entries)} entries from PSL file")
    return entries, version

def get_current_version():
    """
    Get the current PSL version from the database.
    
    Returns:
        str or None: Current version or None if not found
    """
    try:
        # Replace fetch_one with fetchrow
        result = sync_db.fetchrow(
            """
            SELECT version, entry_count, import_date
            FROM public_suffix_list_version
            ORDER BY import_date DESC
            LIMIT 1
            """
        )
        
        if result:
            logger.info(f"Current PSL version: {result['version']} with {result['entry_count']} entries (imported on {result['import_date']})")
            return result["version"]
        
        logger.info("No PSL version found in database")
        return None
        
    except Exception as e:
        logger.error(f"Failed to get current PSL version: {e}")
        return None

def update_database(entries, version):
    """
    Update the database with the parsed PSL entries.
    
    Args:
        entries (list): List of PSL entries
        version (str): Version string
    
    Returns:
        bool: True if update was successful
    """
    logger.info(f"Updating database with PSL version {version[:8]}... ({len(entries)} entries)")
    
    try:
        # Execute operations individually without explicit transaction
        # Clear existing entries
        sync_db.execute("DELETE FROM public_suffix_list")
        
        # Insert new entries
        for entry in entries:
            sync_db.execute(
                """
                INSERT INTO public_suffix_list 
                (suffix, is_wildcard, is_exception, category, country_code, organization, source_url, description)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                entry["suffix"],
                entry["is_wildcard"],
                entry["is_exception"],
                entry["category"],
                entry["country_code"],
                entry["organization"],
                entry["source_url"],
                entry["description"]
            )
        
        # Update version tracking
        sync_db.execute(
            """
            INSERT INTO public_suffix_list_version
            (version, source_url, entry_count)
            VALUES ($1, $2, $3)
            """,
            version,
            PSL_URL,
            len(entries)
        )
        
        logger.info(f"Successfully updated database with {len(entries)} PSL entries")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update PSL database: {e}")
        return False

def update_public_suffix_list(force=False):
    """
    Check for updates to the Public Suffix List and update the database if necessary.
    
    Args:
        force (bool): Whether to force an update even if the version hasn't changed
        
    Returns:
        dict: Update status information
    """
    logger.info("Checking for Public Suffix List updates...")
    
    try:
        # Create temp directory
        temp_dir = TEMP_DIR
        temp_dir.mkdir(exist_ok=True)
        
        # Download the latest PSL file
        try:
            file_path = download_psl_file()
        except Exception as e:
            logger.error(f"Failed to download PSL file: {e}")
            return {"success": False, "error": f"Download failed: {str(e)}"}
        
        # Parse the file
        try:
            entries, version = parse_psl_file(file_path)
        except Exception as e:
            logger.error(f"Failed to parse PSL file: {e}")
            return {"success": False, "error": f"Parse failed: {str(e)}"}
        
        # Check if we need to update
        current_version = get_current_version()
        if current_version == version and not force:
            logger.info(f"PSL is already up to date (version {version[:8]})")
            return {"success": True, "updated": False, "version": version, "reason": "Already up to date"}
        
        # Update the database
        success = update_database(entries, version)
        if not success:
            return {"success": False, "error": "Database update failed"}
        
        return {
            "success": True, 
            "updated": True, 
            "version": version, 
            "entries": len(entries),
            "previous_version": current_version
        }
        
    finally:
        # Clean up temporary files
        try:
            if os.path.exists(TEMP_DIR):
                shutil.rmtree(TEMP_DIR)
                logger.info(f"Cleaned up temporary directory {TEMP_DIR}")
        except Exception as e:
            logger.error(f"Failed to clean up temporary files: {e}")

def initialize_suffix_list(force_update=False):
    """
    Initialize the Public Suffix List in the database.
    Called during application initialization.
    
    Args:
        force_update (bool): Whether to force an update even if the version hasn't changed
        
    Returns:
        dict: Initialization status
    """
    logger.info("Initializing Public Suffix List...")
    
    # Check if the PSL is already populated
    try:
        # Replace fetch_one with fetchrow
        count_result = sync_db.fetchrow("SELECT COUNT(*) as count FROM public_suffix_list")
        count = count_result['count'] if count_result else 0
        
        # If we have entries and not forcing update, skip
        if count > 0 and not force_update:
            logger.info(f"PSL is already populated with {count} entries. Skipping update.")
            return {"success": True, "updated": False, "reason": "Already populated"}
    
    except Exception as e:
        logger.error(f"Failed to check if PSL is populated: {e}")
    
    # Update the PSL
    return update_public_suffix_list(force=force_update)