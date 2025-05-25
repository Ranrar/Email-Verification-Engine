"""
Email Verification Engine
===================================
Database key connection
PostgreSQL Populate Module
"""

import os
import psycopg2
import re
from dotenv import load_dotenv
from pathlib import Path
from pathlib import Path
import platform
# Enhanced prompt_toolkit imports
from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.styles import Style as PromptStyle
from prompt_toolkit import print_formatted_text, HTML
from backup import backup_database, restore_database

# Define a style dictionary for prompt_toolkit
style = PromptStyle.from_dict({
    'success': '#00AA00',  # Green
    'error': '#AA0000',    # Red
    'info': '#0000AA',     # Blue
    'highlight': '#AAAA00', # Yellow
    'prompt': '#00AAAA',    # Cyan
})

# IPv4 regex patterns
IPV4_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
IPV4_REGEX = rf'({IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET})'
PORT_REGEX = r'^(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})$'

# Helper functions for formatted output
def print_success(text):
    print_formatted_text(HTML(f"<success>{text}</success>"), style=style)

def print_error(text):
    print_formatted_text(HTML(f"<error>{text}</error>"), style=style)

def print_info(text):
    print_formatted_text(HTML(f"<info>{text}</info>"), style=style)

def print_highlight(text):
    print_formatted_text(HTML(f"<highlight>{text}</highlight>"), style=style)

def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    # Check if the operating system is Windows
    if platform.system().lower() == "windows":
        os.system("cls")
    else:
        # For Unix/Linux/MacOS
        os.system("clear")

class IPValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text:  # Allow empty for now, we'll check later
            return
            
        # Only accept valid IP addresses
        if re.fullmatch(IPV4_REGEX, text):
            return
            
        raise ValidationError(
            message="Invalid IP address format.",
            cursor_position=len(text)
        )

class PortValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text:  # Default will be applied later
            return
            
        if not re.match(PORT_REGEX, text):
            raise ValidationError(
                message="Port must be between 1 and 65535",
                cursor_position=len(text)
            )

class NotEmptyValidator(Validator):
    def __init__(self, message="This field cannot be empty"):
        self.message = message
        
    def validate(self, document):
        text = document.text
        if not text.strip():
            raise ValidationError(
                message=self.message,
                cursor_position=0
            )

def prompt_for_db_config():
    """Prompt user for database configuration and return credentials"""
    clear_screen()
    print_highlight("\n=== Database Configuration Setup ===")
    print_info("Please provide the following information to connect to your database:")
    
    # Get host with real-time validation
    host = prompt(
        message=HTML("<prompt>Database host (IP or domain name): </prompt>"),
        style=style,
        validator=IPValidator(),
        validate_while_typing=True
    )
    
    # Get port with validation (default to 5432 if empty)
    port = prompt(
        message=HTML("<prompt>Database port [5432]: </prompt>"),
        style=style,
        validator=PortValidator(),
        validate_while_typing=True,
        default="5432"
    ) or "5432"
    
    # Get database name (required)
    database = prompt(
        message=HTML("<prompt>Database name: </prompt>"),
        style=style,
        validator=NotEmptyValidator("Database name cannot be empty"),
        validate_while_typing=False
    )
    
    # Get username (required)
    user = prompt(
        message=HTML("<prompt>Database username: </prompt>"),
        style=style,
        validator=NotEmptyValidator("Username cannot be empty"),
        validate_while_typing=False
    )
    
    # For password, use prompt with password masking
    password = prompt(
        message=HTML("<prompt>Database password: </prompt>"),
        style=style,
        is_password=True,  # This enables the password masking with asterisks
        validator=NotEmptyValidator("Password cannot be empty"),
        validate_while_typing=False
    )
    
    # Use prompt_toolkit for confirmation too
    confirm = prompt(
        message=HTML("<prompt>Is this information correct? (y/n): </prompt>"),
        style=style
    ).lower().strip()
    
    # More lenient check - accept anything starting with 'y'
    if not confirm or not confirm.startswith('y'):
        print_info("install cancelled. Please try again.")
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
            retry_input = prompt(
                message=HTML("<prompt>Enter 'y' to try again, any other key to exit: </prompt>"),
                style=style
            ).lower().strip()
            
            if retry_input == 'y':
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
            confirm = prompt(
                message=HTML("<prompt>Enter 'y' to recreate configuration, any other key to exit: </prompt>"),
                style=style
            ).lower().strip()
            
            if confirm == 'y':
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
            confirm = prompt(
                message=HTML("<prompt>Enter 'y' to recreate configuration, any other key to exit: </prompt>"),
                style=style
            ).lower().strip()
            
            if confirm == 'y':
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
            print_formatted_text(HTML("<highlight>1.</highlight> Backup current database"), style=style)
            print_formatted_text(HTML("<highlight>2.</highlight> Restore database from backup"), style=style)
            print_formatted_text(HTML("<highlight>3.</highlight> Exit (keep current database)"), style=style)
            
            choice = prompt(
                message=HTML("<prompt>Enter your choice (1-3): </prompt>"),
                style=style
            ).strip()
            
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
                custom_path = prompt(
                    message=HTML("<prompt>Enter backup file path (leave empty for default): </prompt>"),
                    style=style
                ).strip()
                
                confirm = prompt(
                    message=HTML("<prompt>This will overwrite your current database. Continue? (y/n): </prompt>"),
                    style=style
                ).lower().strip()
                
                if confirm.startswith('y'):
                    clear_screen()
                    print_info("Restoring database...")
                    backup_path = custom_path if custom_path else None
                    restore_database(backup_path)
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

    confirm = prompt(
        message=HTML("<prompt>This will modify your database schema. Continue? (y/n): </prompt>"),
        style=style
    ).lower().strip()
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
    print_formatted_text(HTML("<highlight>EVE Database installer</highlight>"), style=style)
    print("="*65)
    print_info("This utility helps you install, update, or reinstall the database for EVE.")
    print("="*65 + "\n")

if __name__ == "__main__":
    display_welcome_message()
    print_formatted_text(HTML("<highlight>1.</highlight> Install/Reinstall database"), style=style)
    print_formatted_text(HTML("<highlight>2.</highlight> Update database tables (drop &amp; recreate)"), style=style)
    print_formatted_text(HTML("<highlight>3.</highlight> Exit"), style=style)
    choice = prompt(
        message=HTML("<prompt>Enter your choice (1-3): </prompt>"),
        style=style
    ).strip()
    if choice == "1":
        check_database_and_handle_options()
    elif choice == "2":
        update_database_tables()
    else:
        print_info("Exiting installer.")