# Email Verification Engine - Docker Setup

This directory contains Docker configuration files to run the Email Verification Engine in a containerized environment with PostgreSQL.

## Quick Start

1. **Build and start the services:**
   ```bash
   docker-compose up --build
   ```

2. **Access the application:**
   - Web Interface: http://localhost:8080
   - PostgreSQL Database: localhost:5432

3. **Stop the services:**
   ```bash
   docker-compose down
   ```

## Services

### PostgreSQL Database (`postgres`)
- **Image:** postgres:16
- **Port:** 5432
- **Credentials:**
  - User: `postgres`
  - Password: `password`
  - Database: `postgres`
- **Volume:** Persistent data storage in `postgres_data` volume
- **Initialization:** Automatically loads schema from `src/database/schema.sql`

### Email Verification Engine (`eve-app`)
- **Port:** 8080
- **Environment:** Configured to connect to the PostgreSQL service
- **Volumes:**
  - `./logs` for application logs
  - `./src/database/backups` for database backups

## Configuration

### Environment Variables
The application uses these environment variables (configured in docker-compose.yml):

- `PG_HOST=postgres` - Database host (container name)
- `PG_PORT=5432` - Database port
- `PG_DATABASE=postgres` - Database name
- `PG_USER=postgres` - Database user
- `PG_PASSWORD=password` - Database password

### Custom Configuration
To customize the setup:

1. **Change database credentials:** Edit the `docker-compose.yml` file
2. **Use custom environment file:** Copy `.env.docker` to `.env` and modify
3. **Change ports:** Modify the ports section in `docker-compose.yml`

## Commands

### Development Commands
```bash
# Build only
docker-compose build

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f
docker-compose logs -f eve-app  # App logs only
docker-compose logs -f postgres  # Database logs only

# Execute commands in containers
docker-compose exec eve-app bash
docker-compose exec postgres psql -U postgres -d postgres

# Restart a service
docker-compose restart eve-app
```

### Database Management
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U postgres -d postgres

# Create a database backup
docker-compose exec eve-app python src/database/backup.py

# View database tables
docker-compose exec postgres psql -U postgres -d postgres -c "\dt"
```

### Cleanup
```bash
# Stop and remove containers
docker-compose down

# Remove containers and volumes (DESTROYS DATA!)
docker-compose down -v

# Remove everything including images
docker-compose down -v --rmi all
```

## Troubleshooting

### Common Issues

1. **Port already in use:**
   ```bash
   # Change ports in docker-compose.yml
   ports:
     - "8081:8080"  # Use different host port
   ```

2. **Database connection failed:**
   - Check if PostgreSQL container is healthy: `docker-compose ps`
   - View PostgreSQL logs: `docker-compose logs postgres`

3. **Application won't start:**
   - Check application logs: `docker-compose logs eve-app`
   - Ensure all required files are present

4. **Permission denied errors:**
   ```bash
   # Fix file permissions
   chmod +x docker-entrypoint.sh
   ```

### Logs
- Application logs: `./logs/` directory
- Container logs: `docker-compose logs`

### Health Checks
The PostgreSQL service includes a health check. The application waits for the database to be ready before starting.

## Production Considerations

For production use, consider:

1. **Change default passwords** in docker-compose.yml
2. **Use secrets management** instead of environment variables
3. **Configure proper logging** and log rotation
4. **Set up monitoring** and alerting
5. **Use external volumes** for data persistence
6. **Configure backup strategies**
7. **Set resource limits** in docker-compose.yml

## File Structure

```
├── docker-compose.yml      # Main Docker Compose configuration
├── Dockerfile              # Application container definition
├── .dockerignore           # Files to exclude from Docker context
├── .env.docker             # Environment variables template
├── docker-entrypoint.sh    # Application startup script
└── src/database/
    ├── key.env.docker       # Database config for Docker
    └── schema.sql           # Database schema (loaded automatically)
```