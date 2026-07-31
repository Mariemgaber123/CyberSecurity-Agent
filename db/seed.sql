-- Insert Users (Covers different roles for Notification/Tool Access triggers)
INSERT INTO users (name, email, role, department)
VALUES
('Mariem Gaber', 'mariem@securini.com', 'SOC Analyst', 'Security Operations'),
('Reem Ahmed', 'reem@securini.com', 'Security Manager', 'Security Operations'),
('Aser Alaa', 'aser@securini.com', 'Junior Analyst', 'Security Operations');

-- Insert Devices (Covers Critical vs Normal for Elicitation testing)
INSERT INTO devices (hostname, ip_address, criticality, status)
VALUES
('WEB-SERVER-01', '10.0.0.15', 'Critical', 'Online'),       -- Isolation requires Elicitation (Manager approval)
('EMPLOYEE-LAPTOP-22', '10.0.0.25', 'Normal', 'Online'),    -- Isolation can complete immediately
('DB-SERVER-PRIMARY', '10.0.0.30', 'Critical', 'Online');

-- Insert Incidents
INSERT INTO incidents (title, description, severity, status, assigned_to)
VALUES
('Multiple Failed Login Attempts', 'Several failed authentication attempts detected from suspicious IP address.', 'High', 'Investigating', 1),
('Ransomware Execution Attempt', 'Malicious file execution blocked on employee laptop.', 'Critical', 'Open', 3);

-- Link Incidents to Devices
INSERT INTO incident_devices (incident_id, device_id)
VALUES
(1, 1), -- Incident 1 linked to Critical Web Server
(2, 2); -- Incident 2 linked to Normal Laptop

-- Insert Threat Intelligence (Fixed: added incident_id)
INSERT INTO threat_intelligence (incident_id, value, type, severity, reputation)
VALUES
(1, '192.168.1.50', 'IP', 'High', 'Malicious'),
(2, 'malware-example.com', 'Domain', 'Critical', 'Malicious'),
(1, '45.33.32.156', 'IP', 'Medium', 'Suspicious');

-- Insert Policies (To be served via MCP resources/read)
INSERT INTO policies (title, category, content)
VALUES
(
    'Critical Device Isolation Policy',
    'Incident Response',
    'POLICY-IR-001: Any isolation request targeting a device marked as "Critical" MUST require explicit human authorization (Elicitation) from a Security Manager before the connection is severed.'
),
(
    'Incident Closure Policy',
    'Incident Management',
    'POLICY-IM-002: Incidents with "Critical" or "High" severity can only be closed by users holding the "Security Manager" role. Automated or Junior Analyst closure is prohibited.'
);

-- Insert Initial Audit Log Entry
INSERT INTO audit_logs (user_id, action, details)
VALUES
(1, 'System Initialized', 'Database seeded with default SOC assets and threat intelligence indicators.');