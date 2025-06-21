"""
Email Verification Engine
===================================
PostgreSQL backup and restore module:
"""
import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Define ANSI color codes
COLORS = {
    'GREEN': '\033[92m',    # Success
    'RED': '\033[91m',      # Error
    'BLUE': '\033[94m',     # Info
    'YELLOW': '\033[93m',   # Highlight
    'CYAN': '\033[96m',     # Prompt
    'RESET': '\033[0m',     # Reset to default
}

# Helper functions for formatted output
def print_success(text):
    print(f"{COLORS['GREEN']}{text}{COLORS['RESET']}")

def print_error(text):
    print(f"{COLORS['RED']}{text}{COLORS['RESET']}")

def print_info(text):
    print(f"{COLORS['BLUE']}{text}{COLORS['RESET']}")

def print_highlight(text):
    print(f"{COLORS['YELLOW']}{text}{COLORS['RESET']}")

def print_prompt(text):
    return input(f"{COLORS['CYAN']}{text}{COLORS['RESET']}")

def load_db_config():
    """Load database configuration from environment variables"""
    current_dir = Path(__file__).parent
    env_file = current_dir / "key.env"
    
    if not env_file.exists():
        print_error(f"Configuration file not found: {env_file}")
        return None
    
    load_dotenv(dotenv_path=env_file)
    
    required_params = ['PG_HOST', 'PG_PORT', 'PG_DATABASE', 'PG_USER', 'PG_PASSWORD']
    missing_params = [param for param in required_params if not os.getenv(param)]
    
    if missing_params:
        print_error(f"Missing required parameters in key.env: {', '.join(missing_params)}")
        return None
        
    return {
        'host': os.getenv('PG_HOST'),
        'port': os.getenv('PG_PORT'),
        'database': os.getenv('PG_DATABASE'),
        'user': os.getenv('PG_USER'),
        'password': os.getenv('PG_PASSWORD')
    }

def find_pg_tool(tool_name):
    """Find PostgreSQL tool executable in various locations"""
    # Look in custom tools directory first
    script_dir = Path(__file__).parent
    
    # Check for tools in pg_tools/win directory
    tool_paths = [
        script_dir / "pg_tools" / "win" / f"{tool_name}.exe",
        script_dir / "pg_tools" / f"{tool_name}.exe",
        # Add more possible locations here
    ]
    
    # Check each custom path
    for path in tool_paths:
        if path.exists():
            print_info(f"Using {tool_name} from: {path}")
            return str(path)
    
    # Fall back to system PATH
    system_tool = shutil.which(tool_name)
    if system_tool:
        print_info(f"Using {tool_name} from system PATH: {system_tool}")
        return system_tool
    
    print_error(f"{tool_name} not found in any location")
    return None

def check_pg_tool(tool_name):
    """Check if PostgreSQL tool is available in the system PATH"""
    return find_pg_tool(tool_name) is not None

def suggest_pg_installation():
    """Provide guidance on installing PostgreSQL client tools based on OS"""
    os_name = platform.system().lower()
    
    print_error(f"{os_name.capitalize()} PostgreSQL client tools not found")
    
    if "windows" in os_name:
        print_highlight("\nPlease download PostgreSQL client tools:")
        print_info("1. Visit: https://www.enterprisedb.com/download-postgresql-binaries")
        print_info("2. Download the installer for your version of Windows")
        print_info("3. During installation, make sure to select 'Command Line Tools'")
        print_info("4. Ensure the bin directory is added to your PATH")
        
        input(f"{COLORS['CYAN']}Press Enter after you've installed the tools...{COLORS['RESET']}")
    
    elif "linux" in os_name:
        print_highlight("\nInstall PostgreSQL client tools:")
        
        if shutil.which("apt"):
            print_info("Run: sudo apt update && sudo apt install -y postgresql-client")
        elif shutil.which("dnf"):
            print_info("Run: sudo dnf install -y postgresql")
        elif shutil.which("yum"):
            print_info("Run: sudo yum install -y postgresql")
        else:
            print_info("Please install PostgreSQL client tools using your distribution's package manager")
    
    elif "darwin" in os_name:  # macOS
        print_highlight("\nInstall PostgreSQL client tools:")
        print_info("Run: brew install postgresql")
        print_info("Or download from: https://www.postgresql.org/download/macosx/")
    
    else:
        print_info("Please install PostgreSQL client tools for your platform")

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def backup_database(custom_filename=None):
    clear_screen()
    print_info("Creating database backup...")
    
    # Create backup directory if it doesn't exist
    backup_dir = Path(__file__).parent / "backups"
    backup_dir.mkdir(exist_ok=True)
    
    # Check for pg_dump
    if not check_pg_tool("pg_dump"):
        suggest_pg_installation()
        if not check_pg_tool("pg_dump"):  # Check again after suggestion
            print_error("pg_dump still not available. Backup failed.")
            return False
    
    # Load database config
    config = load_db_config()
    if not config:
        return False
    
    # Generate filename with timestamp if not provided
    if not custom_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"eve_backup_{timestamp}.dump"
    else:
        backup_file = backup_dir / custom_filename
    
    print_info(f"Creating database backup to: {backup_file}")
    print_info(f"Connecting to {config['host']}:{config['port']} as {config['user']}")
    
    # Set up environment with password
    env = os.environ.copy()
    env["PGPASSWORD"] = config['password'] or ""
    
    try:
        # Using pg_dump to backup the database
        pg_dump_cmd = find_pg_tool("pg_dump")
        if not pg_dump_cmd:
            print_error("pg_dump command not found.")
            return False
        result = subprocess.run([
            str(pg_dump_cmd),
            "-U", str(config['user']),
            "-h", str(config['host']),
            "-p", str(config['port']),
            "-F", "c",  # Custom format (compressed)
            "-f", str(backup_file),
            str(config['database'])
        ], check=True, env=env, capture_output=True, text=True)
        
        print_success(f"Database backup created successfully at: {backup_file}")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Backup failed: {e}")
        if e.stderr:
            print_error(f"Details: {e.stderr}")
        return False

def restore_database(backup_file=None):
    clear_screen()
    print_info("Preparing to restore database...")
    
    # Load database config
    config = load_db_config()
    if not config:
        return False
    
    # Find pg_restore executable
    pg_restore_cmd = find_pg_tool("pg_restore")
    if not pg_restore_cmd:
        print_error("pg_restore command not found")
        return False
    
    # If no specific file is provided, list available backups for user to choose
    backup_dir = Path(__file__).parent / "backups"
    
    if not backup_dir.exists() or not list(backup_dir.glob("*.dump")):
        print_error(f"No backup files found in {backup_dir}")
        return False
    
    if backup_file is None:
        # List all backups
        backup_files = sorted(backup_dir.glob("*.dump"), key=lambda x: x.stat().st_mtime, reverse=True)
        
        print_highlight("\nAvailable backups:")
        for i, file in enumerate(backup_files, 1):
            mod_time = datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{COLORS['YELLOW']}{i}.{COLORS['RESET']} {file.name} ({mod_time})")
        
        choice = print_prompt("Enter backup number to restore: ")
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(backup_files):
                backup_file = backup_files[idx]
            else:
                print_error("Invalid selection")
                return False
        except ValueError:
            print_error("Please enter a number")
            return False
    
    print_info(f"Restoring database from: {backup_file}")
    print_info(f"Connecting to {config['host']}:{config['port']} as {config['user']}")
    
    # Set up environment with password
    env = os.environ.copy()
    env["PGPASSWORD"] = config['password'] or ""
    
    # Try first with target database directly
    try:
        print_info(f"Attempting to restore directly to database: {config['database']}")
        result = subprocess.run([
            str(pg_restore_cmd),
            "-U", str(config['user']),
            "-h", str(config['host']),
            "-p", str(config['port']),
            "--clean",
            "--if-exists",
            "-d", str(config['database']),
            str(backup_file)
        ], check=True, env=env, capture_output=True, text=True)
        
        print_success(f"Database restored successfully from: {backup_file}")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Restore failed: {e}")
        if e.stderr:
            print_error(f"Details: {e.stderr}")
        return False

if __name__ == "__main__":
    # Add a welcome message
    print_highlight("\n=== PostgreSQL Database Backup Utility ===")
    
    # When run as a script, parse arguments
    if len(sys.argv) < 2:
        print_error("Usage:")
        print_info("  python backup.py backup [filename]  - Create a database backup")
        print_info("  python backup.py restore [filename] - Restore database from backup")
        sys.exit(1)
        
    command = sys.argv[1].lower()
    
    if command == "backup":
        filename = sys.argv[2] if len(sys.argv) > 2 else None
        success = backup_database(filename)
        sys.exit(0 if success else 1)
        
    elif command == "restore":
        filename = sys.argv[2] if len(sys.argv) > 2 else None
        if filename:
            # Convert filename to full path if it's just a filename
            backup_dir = Path(__file__).parent / "backups"
            filename = backup_dir / filename if not os.path.isabs(filename) else Path(filename)
        success = restore_database(filename)
        sys.exit(0 if success else 1)
        
    else:
        print_error(f"Unknown command: {command}")
        print_info("Use 'backup' or 'restore'")
        sys.exit(1)