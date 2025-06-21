
# Setup Guide: PostgreSQL 16 with pgAgent on docker

## Info
- Tested on **Ubuntu 24.04**
- Use `ufw` to open any ports if needed

## Recommended
- Install **pgAdmin** (not required, but helpful for setting up pgAgent jobs)
- Linux username: `postgres`
- PostgreSQL username: `postgres`
- Default database name: `postgres`

---

## Install PostgreSQL

```bash
docker pull postgres:16

docker run -d \
  --name postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_DB=postgres \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -v /home/user/docker/postgres:/var/lib/postgresql/data \
  postgres:16
```

## Install pgAdmin

```bash
docker exec -it postgres bash # log into the docker container

apt install -y curl gnupg lsb-release ca-certificates

curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    | gpg --dearmor -o /usr/share/keyrings/postgresql.gpg

echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list

apt update

apt install -y pgagent
```

## setup pgAdmin

```bash
psql -U postgres
```

Enable pgAgent extension:

```bash
postgres=# CREATE EXTENSION pgagent;
postgres=# \q
```
## Run pgAgent as a Service

Create service file:
```bash
apt install nano
sudo nano /etc/systemd/system/pgagent.service
```

Paste:
```ini
[Unit]
Description=pgAgent Job Scheduler for PostgreSQL
After=network.target

[Service]
User=postgres
ExecStart=/usr/bin/pgagent -f "dbname=postgres user=postgres"
Restart=on-failure
StandardOutput=append:/var/log/pgagent.log
StandardError=append:/var/log/pgagent.log

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
apt install systemctl
systemctl daemon-reload
systemctl enable --now pgagent
systemctl status pgagent
```

Enable and start the log:
```bash
touch /var/log/pgagent.log
chmod 644 /var/log/pgagent.log
chown postgres:postgres /var/log/pgagent.log
tail -f /var/log/pgagent.log
```

---

## SQL Queries to Check Job Status

### Check Scheduled Jobs
```sql
SELECT jobid, jobname, jobnextrun, joblastrun
FROM pgagent.pga_job
ORDER BY jobnextrun;
```

### Check Job Logs
```sql
SELECT * FROM pgagent.pga_joblog ORDER BY jlgid DESC LIMIT 10;
```

### View Job Classes
```sql
SELECT * FROM pgagent.pga_jobclass;
```

### Check Schedule Details
```sql
SELECT jscid, jscname, jscminutes, jschours FROM pgagent.pga_schedule;
```

---

## Troubleshooting

### Terminal Checks
```bash
dpkg -l | grep pgagent          # Check if pgAgent is installed
sudo systemctl status pgagent  # Check if service is running
```

### SQL Check
```sql
SELECT * FROM pgagent.pga_joblog ORDER BY jlgid DESC LIMIT 10;
```

### Debugging
```bash
/usr/bin/pgagent -l 2 -f "dbname=postgres user=postgres"
```

---

## Additional Info

- pgAgent Docs: https://www.pgadmin.org/docs/pgadmin4/latest/pgagent.html
- PostgreSQL: https://www.postgresql.org/download/linux/ubuntu/