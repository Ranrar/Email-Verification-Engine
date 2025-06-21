"""
Email Verification Engine
===================================
Database key connection
PostgreSQL Populate Module
"""

import os
import psycopg2
import re
import sys
from dotenv import load_dotenv
from pathlib import Path
import platform

current_dir = str(Path(__file__).parent)
if current_dir not in sys.path:
    sys.path.append(current_dir)

# backup functions
from backup import backup_database as perform_backup
from backup import restore_database as perform_restore

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

# Helper functions for formatted output
def print_success(text):
    print(f"{Colors.GREEN}{text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}{text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}{text}{Colors.RESET}")

def print_highlight(text):
    print(f"{Colors.YELLOW}{text}{Colors.RESET}")

# IPv4 regex patterns
IPV4_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
IPV4_REGEX = rf'({IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET})'
PORT_REGEX = r'^(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})$'

def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    # Check if the operating system is Windows
    if platform.system().lower() == "windows":
        os.system("cls")
    else:
        # For Unix/Linux/MacOS
        os.system("clear")

# Simple input functions with validation
def get_input(message, validator=None, default=None, is_password=False):
    """Get input from user with optional validation"""
    while True:
        # Handle password input
        if is_password:
            import getpass
            value = getpass.getpass(message)
        else:
            value = input(message)
        
        # Apply default value if input is empty and default is provided
        if not value and default is not None:
            value = default
            
        # Validate input if validator is provided
        if validator and not validator(value):
            continue
            
        return value

# Validation functions
def validate_ip(value):
    """Validate IP address"""
    if not value:  # Allow empty for default
        return True
        
    if not re.fullmatch(IPV4_REGEX, value):
        print_error("Invalid IP address format.")
        return False
    return True

def validate_port(value):
    """Validate port number"""
    if not value:  # Allow empty for default
        return True
        
    if not re.match(PORT_REGEX, value):
        print_error("Port must be between 1 and 65535")
        return False
    return True

def validate_not_empty(value, message="This field cannot be empty"):
    """Validate that input is not empty"""
    if not value.strip():
        print_error(message)
        return False
    return True

def prompt_for_db_config():
    """Prompt user for database configuration and return credentials"""
    clear_screen()
    print_highlight("\n=== Database Configuration Setup ===")
    print_info("Please provide the following information to connect to your database:")
    
    # Get host with validation
    host = get_input(
        f"{Colors.CYAN}Database host (IP or domain name): {Colors.RESET}",
        validator=validate_ip
    )
    
    # Get port with validation (default to 5432 if empty)
    port = get_input(
        f"{Colors.CYAN}Database port [5432]: {Colors.RESET}",
        validator=validate_port,
        default="5432"
    )
    
    # Get database name (required)
    database = get_input(
        f"{Colors.CYAN}Database name: {Colors.RESET}",
        validator=lambda x: validate_not_empty(x, "Database name cannot be empty")
    )
    
    # Get username (required)
    user = get_input(
        f"{Colors.CYAN}Database username: {Colors.RESET}",
        validator=lambda x: validate_not_empty(x, "Username cannot be empty")
    )
    
    # For password, use getpass for masking
    password = get_input(
        f"{Colors.CYAN}Database password: {Colors.RESET}",
        validator=lambda x: validate_not_empty(x, "Password cannot be empty"),
        is_password=True
    )
    
    # Confirm information
    confirm = get_input(f"{Colors.CYAN}Is this information correct? (y/n): {Colors.RESET}")
    
    # More lenient check - accept anything starting with 'y'
    if not confirm or not confirm.startswith('y'):
        print_info("Install cancelled. Please try again.")
        return None
    
    # Return the credentials as a dictionary
    return {
        'host': host,
        'port': port,
        'database': database,
        'user': user,
        'password': password
    }

def test_connection_with_credentials(credentials):
    """Test if the provided credentials work"""
    clear_screen()
    print_info("\nTesting database connection with provided credentials...")
    
    try:
        conn = psycopg2.connect(
            host=credentials['host'],
            port=credentials['port'],
            database=credentials['database'],
            user=credentials['user'],
            password=credentials['password']
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        
        if db_version and len(db_version) > 0:
            print_success(f"Connection successful! Database version: {db_version[0]}")
        else:
            print_success("Connection successful! (Could not retrieve database version)")
        
        cursor.close()
        conn.close()
        return True
    
    except Exception as e:
        print_error(f"Connection failed: {e}")
        return False

def save_credentials_to_file(credentials, env_file):
    """Save working credentials to key.env file"""
    config_content = f"""# Database Connection Settings
PG_HOST={credentials['host']}
PG_PORT={credentials['port']}
PG_DATABASE={credentials['database']}
PG_USER={credentials['user']}
PG_PASSWORD={credentials['password']}
"""
    
    try:
        with open(env_file, 'w') as f:
            f.write(config_content)
        print_success(f"\nConfiguration saved to: {env_file}")
        return True
    except Exception as e:
        print_error(f"Error creating configuration file: {e}")
        return False

def connect_to_postgres(retry=True):
    # Get the directory containing this script
    current_dir = Path(__file__).parent
    env_file = current_dir / "key.env"
    
    # Handle configuration setup with connection test
    def setup_config():
        print_info("Setting up database configuration...")
        
        # First, get the credentials
        credentials = prompt_for_db_config()
        if not credentials:
            return False
        
        # Test if credentials work before saving
        if test_connection_with_credentials(credentials):
            # Save working credentials to file
            return save_credentials_to_file(credentials, env_file)
        else:
            print_highlight("\nConnection test failed. Would you like to try again?")
            retry_input = get_input("Enter 'y' to try again, any other key to exit: ")
            
            if retry_input.lower().strip() == 'y':
                return setup_config()  # Recursive call to restart config
            return False
    
    # Check if the environment file exists; if not, create it interactively
    if not env_file.exists():
        print_info(f"No key or database found")
        if not setup_config():
            return None
    
    load_dotenv(dotenv_path=env_file)
    
    required_params = ['PG_HOST', 'PG_PORT', 'PG_DATABASE', 'PG_USER', 'PG_PASSWORD']
    missing_params = [param for param in required_params if not os.getenv(param)]
    
    if missing_params:
        print_error(f"ERROR: Missing required parameters in key.env: {', '.join(missing_params)}")
        
        if retry:
            print_highlight("\nWould you like to delete the existing configuration and create a new one?")
            confirm = get_input("Enter 'y' to recreate configuration, any other key to exit: ")
            
            if confirm.lower().strip() == 'y':
                try:
                    os.remove(env_file)
                    print_success(f"Deleted invalid configuration file: {env_file}")
                    return connect_to_postgres(retry=False)
                except Exception as e:
                    print_error(f"Error deleting configuration file: {e}")
        
        return None
    
    try:
        # Get connection parameters from environment variables
        host = os.getenv('PG_HOST')
        port = os.getenv('PG_PORT')
        database = os.getenv('PG_DATABASE')
        user = os.getenv('PG_USER')
        password = os.getenv('PG_PASSWORD')
       
        # Connect to the database
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        
        # Create a cursor
        cursor = conn.cursor()
        
        # Execute a test query
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        
        print_success(f"Connected to database at {host}:{port}")
        if db_version and len(db_version) > 0:
            print_success(f"Database: {db_version[0]}")
        else:
            print_success("Database: (version info unavailable)")
        
        return conn
    except (Exception, psycopg2.Error) as error:
        print_error(f"Error connecting to database: {error}")
        
        if retry:
            print_highlight("\nDatabase connection failed. The configuration may be incorrect.")
            print_highlight("Would you like to delete the existing configuration and create a new one?")
            confirm = get_input("Enter 'y' to recreate configuration, any other key to exit: ")
            
            if confirm.lower().strip() == 'y':
                try:
                    os.remove(env_file)
                    print_success(f"Deleted invalid configuration file: {env_file}")
                    return connect_to_postgres(retry=False)
                except Exception as e:
                    print_error(f"Error deleting configuration file: {e}")
        
        return None

def test_db_connection():
    """Test database connection and run a basic query"""
    clear_screen()
    print_info("Testing database connection...")
    conn = connect_to_postgres()
    
    if not conn:
        print_error("\nFailed to establish database connection.")
        print_info("Please check your configuration and try again.")
        return False
        
    cursor = None
    try:
        # Create a cursor
        cursor = conn.cursor()
        
        # Example query - get table names 
        cursor.execute(""" 
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        
        tables = cursor.fetchall()
        
        print_highlight("\nDatabase Tables:")
        for table in tables:
            print_success(f"- {table[0]}")
        
        return True
    except (Exception, psycopg2.Error) as error:
        print_error(f"Error executing query: {error}")
        return False
    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            print_info("Database connection closed.")

def execute_sql_file(conn, sql_file_path):
    """Execute SQL file in a transaction with commit/rollback."""
    try:
        print_info(f"Executing SQL file: {sql_file_path}")
        
        # Read the entire file content
        with open(sql_file_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Create cursor and execute entire file in a transaction
        cursor = conn.cursor()
        cursor.execute(sql_content)
        
        # Commit changes
        conn.commit()
        
        print_success(f"Successfully executed SQL file: {sql_file_path}")
        cursor.close()
        return True
        
    except Exception as e:
        # Roll back any changes made before the error
        conn.rollback()
        print_error(f"Failed to execute SQL file: {e}")
        print_error(f"Error details: {str(e)}")
        return False

def backup_database():
    """Create a database backup using the backup module."""
    return perform_backup()

def restore_database(backup_file):
    """Restore database from a backup file using the backup module."""
    return perform_restore(backup_file)

def check_database_and_handle_options():
    """Check if database exists, get its size and handle user options."""
    conn = connect_to_postgres(retry=False)
    
    if not conn:
        print_error("Cannot connect to database. Please check your configuration.")
        return False
    
    cursor = None
    try:
        # Get database size and count tables
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pg_size_pretty(pg_database_size(current_database())) as db_size;
        """)
        db_size_row = cursor.fetchone()
        db_size = db_size_row[0] if db_size_row else "Unknown"
        
        # Count tables in the database
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = 'public';
        """)
        table_count_row = cursor.fetchone()
        table_count = table_count_row[0] if table_count_row else 0
        
        clear_screen()
        print_highlight("\n=== Database Information ===")
        print_success(f"Database size: {db_size}")
        print_success(f"Number of tables: {table_count}")
        
        # Different flow based on whether tables exist
        if table_count == 0:
            print_info("\nEmpty database detected. Installing schema...")
            
            # Default schema location - same directory as this script
            schema_path = Path(__file__).parent / "schema.sql"
            
            if not schema_path.exists():
                print_error(f"Schema file not found: {schema_path}")
                return False
            
            print_info(f"Installing schema from: {schema_path}")
            
            # Execute the schema file
            if execute_sql_file(conn, schema_path):
                clear_screen()
                print_success("Schema installed successfully!")
                
                # Create an initial backup
                print_info("Creating initial backup of fresh installation...")
                backup_database()
                return True
            else:
                print_error("Schema installation failed.")
                return False
        else:
            # Existing database with tables - different menu
            print_info("\nExisting database detected. Please choose an option:")
            print(f"{Colors.YELLOW}1.{Colors.RESET} Backup current database")
            print(f"{Colors.YELLOW}2.{Colors.RESET} Restore database from backup")
            print(f"{Colors.YELLOW}3.{Colors.RESET} Exit (keep current database)")
            
            choice = get_input(f"{Colors.CYAN}Enter your choice (1-3): {Colors.RESET}")
            
            if choice == "1":
                # Handle backup
                clear_screen()
                print_info("Creating database backup...")
                backup_database()
                return True
                
            elif choice == "2":
                # Handle restore
                clear_screen()
                print_info("=== Database Restore ===")
                backup_dir = Path(__file__).parent / "backups"
                dump_files = sorted(backup_dir.glob("*.dump"))
                if not dump_files:
                    print_error("No .dump files found in the backup folder.")
                    return True

                print_highlight("\nAvailable backup files:")
                for idx, file in enumerate(dump_files, 1):
                    # Get file modified time and size
                    mtime = file.stat().st_mtime
                    size_mb = file.stat().st_size / (1024 * 1024)
                    from datetime import datetime
                    date_str = datetime.fromtimestamp(mtime).strftime('%m-%d-%Y')
                    print_info(f"{idx}. Backup from {date_str} ({size_mb:.2f} MB) - {file.name}")

                file_choice = get_input(f"{Colors.CYAN}Select a backup file by number (or leave empty to cancel): {Colors.RESET}")
                if not file_choice.isdigit() or int(file_choice) < 1 or int(file_choice) > len(dump_files):
                    print_info("Restore cancelled.")
                    return True

                selected_file = dump_files[int(file_choice) - 1]
                confirm = get_input(f"{Colors.CYAN}This will overwrite your current database with '{selected_file.name}'. Continue? (y/n): {Colors.RESET}")

                if confirm.lower().strip().startswith('y'):
                    clear_screen()
                    print_info(f"Restoring database from {selected_file.name} ...")
                    restore_database(str(selected_file))
                else:
                    clear_screen()
                    print_info("Database restore cancelled.")

                return True
                
            elif choice == "3":
                clear_screen()
                print_info("Exiting and keeping current database.")
                return True
            else:
                clear_screen()
                print_error("Invalid choice. Exiting.")
                return False
                
    except Exception as e:
        print_error(f"Error while checking database: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            print_info("Database connection closed.")

def update_database_tables():
    conn = connect_to_postgres()
    if not conn:
        print_error("Cannot connect to database. Aborting update.")
        return False

    schema_path = Path(__file__).parent / "schema.sql"
    if not schema_path.exists():
        print_error(f"Schema file not found: {schema_path}")
        return False

    schema_tables = get_schema_tables(schema_path)
    db_tables = get_db_tables(conn)

    # Tables to add and drop
    to_create = schema_tables - db_tables
    to_drop = db_tables - schema_tables

    print_highlight("\n=== Database Table Synchronization ===")
    print_info(f"Tables to create: {', '.join(to_create) if to_create else 'None'}")
    print_info(f"Tables to drop: {', '.join(to_drop) if to_drop else 'None'}")

    confirm = get_input(f"{Colors.CYAN}This will modify your database schema. Continue? (y/n): {Colors.RESET}")
    if not confirm.startswith('y'):
        print_info("Update cancelled.")
        return False

    cursor = conn.cursor()
    try:
        # Drop tables not in schema.sql
        for table in to_drop:
            cursor.execute(f'DROP TABLE IF EXISTS {table} CASCADE;')
            print_info(f"Dropped table: {table}")

        # Create tables that are missing
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql = f.read()
        for table in to_create:
            # Extract the CREATE TABLE statement for this table
            match = re.search(
                rf'(CREATE TABLE IF NOT EXISTS\s+{table}\s*\(.*?\);)',
                sql, re.IGNORECASE | re.DOTALL
            )
            if match:
                cursor.execute(match.group(1))
                print_success(f"Created table: {table}")
            else:
                print_error(f"Could not find CREATE statement for table: {table}")

        conn.commit()
        print_success("Database schema synchronized successfully!")
        return True

    except Exception as e:
        conn.rollback()
        print_error(f"Error updating tables: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
        print_info("Database connection closed.")

def get_schema_tables(schema_path):
    with open(schema_path, 'r', encoding='utf-8') as f:
        sql = f.read()
    # Regex to match CREATE TABLE IF NOT EXISTS table_name (
    return set(re.findall(r'CREATE TABLE IF NOT EXISTS\s+([a-zA-Z0-9_]+)', sql, re.IGNORECASE))

def get_db_tables(conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
    """)
    return set(row[0] for row in cursor.fetchall())

def upsertify_schema(schema_path):
    with open(schema_path, 'r', encoding='utf-8') as f:
        sql = f.read()

    # Find all INSERT INTO ... ON CONFLICT (col) DO NOTHING;
    pattern = re.compile(
        r"(INSERT INTO\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)\s*VALUES\s*.*?ON CONFLICT\s*\(([^)]+)\)\s*DO NOTHING;)",
        re.DOTALL | re.IGNORECASE
    )

    def upsert_replacer(match):
        insert_stmt, table, columns, conflict_col = match.groups()
        columns = [c.strip() for c in columns.split(',')]
        # Don't update the conflict column itself
        update_cols = [c for c in columns if c != conflict_col]
        set_clause = ', '.join([f"{col} = EXCLUDED.{col}" for col in update_cols])
        return re.sub(
            r"DO NOTHING;",
            f"DO UPDATE SET {set_clause};",
            insert_stmt
        )

    new_sql = pattern.sub(upsert_replacer, sql)

    # Save or print the new schema
    with open(schema_path.replace('.sql', '_upsert.sql'), 'w', encoding='utf-8') as f:
        f.write(new_sql)
    print("Upsert schema written to", schema_path.replace('.sql', '_upsert.sql'))

def display_welcome_message():
    """Display a welcome message when the program starts"""
    clear_screen()
    print("\n" + "="*65)
    print_highlight("Email Verification Engine Database installer")
    print("="*65)
    print_info("This utility helps you install, backup, or reinstall the database.")
    print("="*65 + "\n")

if __name__ == "__main__":
    display_welcome_message()
    print(f"{Colors.YELLOW}1.{Colors.RESET} Install/Backup database")
    print(f"{Colors.YELLOW}2.{Colors.RESET} Update database tables (drop & recreate)")
    print(f"{Colors.YELLOW}3.{Colors.RESET} Exit")
    choice = get_input(f"{Colors.CYAN}Enter your choice (1-3): {Colors.RESET}")
    if choice == "1":
        check_database_and_handle_options()
    elif choice == "2":
        clear_screen()
        print_highlight("You are about to DROP ALL TABLES, VIEWS, FUNCTIONS, etc. and recreate the schema.")
        confirm = get_input(f"{Colors.CYAN}This will ERASE ALL DATA. Are you sure? (y/n): {Colors.RESET}")
        if not confirm.lower().strip().startswith('y'):
            print_info("Update cancelled.")
        else:
            conn = connect_to_postgres()
            if not conn:
                print_error("Cannot connect to database. Aborting update.")
            else:
                # 1. Run drop.sql
                drop_path = Path(__file__).parent / "drop.sql"
                if not drop_path.exists():
                    print_error(f"drop.sql not found: {drop_path}")
                elif not execute_sql_file(conn, drop_path):
                    print_error("Failed to execute drop.sql. Aborting.")
                else:
                    # 2. Confirm DB is empty (no tables)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';
                    """)
                    result = cursor.fetchone()
                    table_count = result[0] if result is not None else 0
                    if table_count > 0:
                        print_error("Database is NOT empty after drop.sql. Aborting.")
                    else:
                        print_success("Database is empty. Proceeding to install schema.sql...")
                        schema_path = Path(__file__).parent / "schema.sql"
                        if not schema_path.exists():
                            print_error(f"schema.sql not found: {schema_path}")
                        elif execute_sql_file(conn, schema_path):
                            print_success("Schema installed successfully!")
                        else:
                            print_error("Failed to execute schema.sql.")
                    cursor.close()
                conn.close()
                print_info("Database connection closed.")
    else:
        print_info("Exiting installer.")