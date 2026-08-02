-- Disable foreign key checks momentarily to allow clean drop/recreate
PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS incident_actions;
DROP TABLE IF EXISTS threat_intelligence;
DROP TABLE IF EXISTS incident_devices;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS policies;

PRAGMA foreign_keys = ON;

-- 1. Users Table (SOC Analysts, Managers)
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Junior Analyst', 'SOC Analyst', 'Security Manager')),
    department TEXT NOT NULL DEFAULT 'Security Operations'
);

-- 2. Incidents Table
CREATE TABLE incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT NOT NULL CHECK(status IN ('Open', 'Investigating', 'Resolved', 'Closed')),
    assigned_to INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES users(user_id) ON DELETE SET NULL
);

-- 3. Devices Table (Company Endpoints)
CREATE TABLE devices (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    ip_address TEXT UNIQUE NOT NULL,
    criticality TEXT NOT NULL CHECK(criticality IN ('Normal', 'Important', 'Critical')),
    status TEXT NOT NULL CHECK(status IN ('Online', 'Offline', 'Isolated'))
);

-- 4. Incident Devices Table (Many-to-Many)
CREATE TABLE incident_devices (
    incident_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, device_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- 5. Threat Intelligence Table (Removed UNIQUE constraint on value to allow indicator reuse across incidents)
CREATE TABLE threat_intelligence (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('IP', 'Domain', 'Hash')),
    severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    reputation TEXT NOT NULL CHECK(reputation IN ('Unknown', 'Suspicious', 'Malicious', 'Safe')),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

-- 6. Incident Actions Table (Audit trail for high-stakes actions like isolation/closure)
CREATE TABLE incident_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    action_type TEXT NOT NULL CHECK(action_type IN ('Investigate', 'Isolate Device', 'Close Incident', 'Escalate')),
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- 7. Audit Logs Table
CREATE TABLE audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- 8. Policies Table (Exposed directly as MCP Resources)
CREATE TABLE policies (
    policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_by INTEGER,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocked_by) REFERENCES users(user_id)
);