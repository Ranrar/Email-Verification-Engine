# Roadmap

A simple development roadmap for the Email Verification Engine.

---

## Phase 1 – Core System (Almost Done)

- [x] Backend email validation engine  
- [x] Syntax & format check
- [x] DNS & MX records
- [x] SMTP deliverability
- [x] Blacklist & Whitelist
- [x] IDN and IDNA Support
- [x] IPv4 resolver
- [x] IPv6 resolver
- [x] Progress tracking and monitoring
- [x] Homebrew multi-layer caching `L3 Cache`
- [x] DNS rotation IPv4 and IPv6 `Random, round-robin and best performer`
- [x] DNS Warmup for best performer and statistics
- [x] Central configuration in database
- [x] Thread & Process Pool executor benchmark `to ensure max performance on premise server`
- [x] Initialization system
- [x] Customizable queue system with function dependency requirements
- [x] Validation scoring and confidence levels
- [x] Basic backend API `EEL`
- [x] Rate limiting engine
- [x] Port configurations
- [x] WHOIS lookup
- [X] SPF
- [X] DKIM
- [X] DMARC
- [ ] IMAP check
- [ ] POP3 check
- [ ] Catch-all check
- [ ] Disposable detection
- [ ] Encrypt database connection file
- [ ] Automatic blacklist domain checking
- [ ] Batch job support `bulk processing`

---

## Phase 2 – Interfaces

### Backend GUI
- [x] Main Theme
- [x] Settings
- [x] Debug and test
- [x] Light and dark theme
- [x] Email regex filter configurator
- [x] Single mail validation `works with all implemented functions above`
- [x] System logs
- [x] Cache stats and hit rates
- [x] Notification
- [ ] Statistics page
- [ ] Server performance information page
- [ ] Validation report export
- [ ] Batch job support `bulk processing`
- [ ] File import for batch
- [ ] Lookup email validation from `Trace ID`
- [ ] Admin dashboard
- [ ] Database backup
- [ ] Reports
- [ ] Validations analyze


### Frontend (Web UI)
- [ ] User registration and login
- [ ] User dashboard  
- [ ] Submit single/batch email jobs  
- [ ] View own job progress & results  
- [ ] API key management 
- [ ] Replade `EEL` with `FastAPI`

---

## Phase 3 – Security & User Roles

- [ ] Role-based access (Admin, Operator, Viewer)  
- [ ] Audit logs (who did what & when)
- [ ] Move log from files to DB
- [ ] Live Log for admin
- [ ] RFC documentation
- [ ] GDPR compliance  
  - [ ] Right to delete user data  
  - [ ] Data retention limits  
  - [ ] Log anonymization
  - [ ] Opt-out request

---

## Phase 4 – Batch & Performance

- [ ] Real-time job progress tracker  
- [ ] Import/export CSV files  
- [ ] High-scale batch job support  
- [ ] Asynchronous queue support
- [ ] Statistics
  - [ ] Generic statistics
  - [ ] Tracking success/failure rates for domains
  - [ ] Managing retry availability based on exponential backoff
  - [ ] Recording performance metrics for SMTP connections
  - [ ] Maintaining domain-specific error statistics
  - [ ] WHOIS data
  - [ ] Geo location
  - [ ] Provider
  - [ ] IP

---

## Phase 5 – Documentation & Deployment

- [ ] Developer guide (how to extend or modify)
- [ ] Payment portal  
- [ ] API docs (Swagger/FastAPI)  
- [ ] Deployment guide (Docker, environment config)  
- [ ] GDPR checklist  
- [ ] Improved `install.py` or web installer  

"NB. I'm sure I have missed something."

---

_Questions or suggestions? Reach out: [kim@skovrasmussen.com](mailto:kim@skovrasmussen.com)_