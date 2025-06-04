
# Setup Guide: PostgreSQL 16 with pgAgent on Ubuntu 24.04 LTS

## Info
- Tested on **Windows 11** using **WSL2**
- Use `ufw` to open any ports if needed

## Recommended
- Install **pgAdmin** (not required, but helpful for setting up pgAgent jobs)
- Linux username: `postgres`
- PostgreSQL username: `postgres`
- Default database name: `postgres`

---

## Install PostgreSQL

```bash
sudo apt update
sudo apt upgrade
sudo apt install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh  # Load repository from PostgreSQL.org
sudo apt update
sudo apt install postgresql-16
sudo apt upgrade
```

---

## Set up PostgreSQL and pgAdmin

```bash
psql
postgres=# \password postgres     # Set a password for postgres
postgres=# \q
```

Install pgAgent:

```bash
sudo apt install pgagent
```

Enable pgAgent extension:

```bash
psql
postgres=# CREATE EXTENSION pgagent;
postgres=# \q
```

---

## Configure PostgreSQL for Remote Access (Optional)

```bash
sudo nano /etc/postgresql/16/main/postgresql.conf
```

Change:
```conf
#listen_addresses = 'localhost'
```
To:
```conf
listen_addresses = '*'
```

Edit `pg_hba.conf` to allow external connections:

```bash
sudo nano /etc/postgresql/16/main/pg_hba.conf
```

Add at bottom:
```conf
host    all             all             0.0.0.0/0               md5
```

Restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

If using `ufw`:
```bash
sudo ufw allow 5432/tcp
sudo ufw reload
```

---

## Run pgAgent as a Service

Create service file:
```bash
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

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pgagent
sudo systemctl status pgagent
journalctl -u pgagent -f
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

`jlgstatus`:  
- `'s'` = Success  
- `'f'` = Fail  
- `'i'` = Idle  

### View Job Classes
```sql
SELECT * FROM pgagent.pga_jobclass;
```

### Check Schedule Details
```sql
SELECT jscid, jscname, jscminutes, jschours FROM pgagent.pga_schedule;
```

**Interpretation of array values:**

- `jscminutes`: 60 elements (one per minute)  
  - `t` at position 15 = run job at minute 15  
- `jschours`: 24 elements (one per hour)  
  - `t` in all = run every hour  
The job runs at the 15th minute of every hour.

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
- WSL2 Network Note: pgAgent may run inside WSL2, but access from Windows GUI tools (pgAdmin) may need port and firewall rules