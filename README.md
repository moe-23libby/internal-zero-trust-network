# Internal Zero Trust Network Implementation

This project implements an **Internal Zero Trust Network** in a controlled virtual laboratory environment.

The main purpose of the project is to reduce implicit trust inside an organization's internal network. Instead of allowing access simply because a user or device is connected to the internal network, the system verifies identity, authentication status, device information, trust level, risk level, role, and enterprise policy before allowing access to protected resources.

The project combines **network segmentation, multi-factor authentication, certificate-based device trust, policy-based access control, continuous access evaluation, session management, and security monitoring**.

---

## Project Overview

The project demonstrates the principle:

> **Never trust implicitly; verify before granting access.**

The system uses several security layers.

- **pfSense** provides network segmentation and firewall enforcement.
- **Certificate Authentication** provides device trust.
- **Password and OTP/MFA** verify the user.
- **Policy Engine (PE)** evaluates trust, risk, role, and enterprise policy.
- **Policy Administrator (PA)** creates and revokes authenticated sessions.
- **Policy Enforcement Point (PEP)** protects company resources.
- **MySQL** stores identities, policies, sessions, risk information, and security events.
- **Network Analyzer** detects selected suspicious network activities.
- **Security Dashboard** provides monitoring and administrative controls.

Network connectivity alone does not provide access to protected company resources.

---

## Project Objectives

The main objectives of this project are:

1. Implement an internal Zero Trust architecture.
2. Divide the internal network into separate security zones.
3. Authenticate users using certificate, password, and OTP/MFA.
4. Implement role-based and policy-based resource authorization.
5. Calculate a trust score using identity and device conditions.
6. Evaluate identity risk separately from trust.
7. Implement the logical Zero Trust components PE, PA, and PEP.
8. Continuously re-evaluate protected resource access.
9. Allow active sessions to be revoked when security conditions change.
10. Monitor selected suspicious network activities.
11. Provide an administrative and security monitoring dashboard.

---

# Network Topology

The project was implemented using **GNS3 and pfSense**.

The internal network is divided into four separate security zones.

```text
                         Upstream / R1
                              |
                           pfSense
                              |
          ____________________|____________________
         |                    |                    |                    |
         |                    |                    |                    |
     EMPLOYEE               GUEST                SERVER          SECURITY TESTING
  192.168.10.0/24      192.168.20.0/24      192.168.30.0/24     192.168.40.0/24
         |                    |                    |                    |
    Employee-SW           Guest-SW             Server-SW          Security-SW
         |                    |                    |                    |
    Employee PC            Guest PC           Ubuntu Server          Kali Linux
  192.168.10.20        192.168.20.30        192.168.30.10       192.168.40.50
```

## Network Addressing

| Security Zone | Network | Gateway | Main Device |
|---|---|---|---|
| Employee | `192.168.10.0/24` | `192.168.10.1` | Employee PC `192.168.10.20` |
| Guest | `192.168.20.0/24` | `192.168.20.1` | Guest PC `192.168.20.30` |
| Server | `192.168.30.0/24` | `192.168.30.1` | Ubuntu Server `192.168.30.10` |
| Security Testing | `192.168.40.0/24` | `192.168.40.1` | Kali Linux `192.168.40.50` |

---

# Network Segmentation

The network is segmented into four zones using **pfSense**.

## 1. Employee Zone

```text
Network: 192.168.10.0/24
Employee PC: 192.168.10.20
Gateway: 192.168.10.1
```

This zone represents normal organizational employees.

Employees can communicate with selected services in the Server zone according to the configured pfSense firewall rules.

Application access is still controlled separately by the Zero Trust system.

---

## 2. Guest Zone

```text
Network: 192.168.20.0/24
Guest PC: 192.168.20.30
Gateway: 192.168.20.1
```

This zone represents users with more restricted privileges.

A Guest may be able to reach the Zero Trust authentication service, but this does not mean the Guest can access every protected company resource.

Enterprise policies determine which resources the Guest role can access.

---

## 3. Server Zone

```text
Network: 192.168.30.0/24
Ubuntu Server: 192.168.30.10
Gateway: 192.168.30.1
```

The Ubuntu server hosts the main Zero Trust components, including:

- MFA/authentication service
- Policy Engine
- Policy Administrator
- Company Portal / PEP
- Administration Dashboard
- Threat Dashboard
- Network Analyzer
- MySQL database

---

## 4. Security Testing Zone

```text
Network: 192.168.40.0/24
Kali Linux: 192.168.40.50
Gateway: 192.168.40.1
```

This zone is separated from normal Employee and Guest networks.

Kali Linux is used only for **controlled security testing** against the laboratory server.

Examples include:

- TCP port scanning
- UDP port scanning
- Rapid ICMP traffic

The purpose is to verify that the monitoring system can detect selected suspicious traffic patterns.

---

# Why Network Segmentation Is Used

Network segmentation reduces unnecessary communication between different types of systems.

In this project, pfSense provides **network-level enforcement**.

For example:

```text
Employee Network
       |
       | selected communication
       v
     pfSense
       |
       v
Server Network
```

However, being able to reach the server does **not** automatically mean the user is authorized to access a protected application.

Therefore, the project uses two enforcement layers:

```text
Layer 1
pfSense
   ↓
Network-level segmentation and firewall enforcement

Layer 2
Zero Trust PE / PA / PEP
   ↓
Identity- and policy-based application access
```

In simple terms:

> **pfSense asks: "Can this network traffic pass?"**

> **Zero Trust asks: "Should this authenticated identity access this resource?"**

---

# How the Zero Trust System Works

The main authentication and authorization flow is:

```text
User / Device
      |
      v
Client Certificate
      |
      v
Username + Password
      |
      v
OTP / MFA
      |
      v
Policy Engine (PE)
      |
      | Calculate Trust
      | Check Risk
      | Check Role
      | Check Enterprise Policy
      |
      v
GRANT / DENY
      |
      v
Policy Administrator (PA)
      |
      | If GRANT
      v
Create Active ZTNA Session
      |
      v
Policy Enforcement Point (PEP)
      |
      v
Protected Company Resource
```

---

# Authentication Process

The system uses multiple authentication conditions.

## Step 1 - Device Certificate

The connecting device presents a client certificate.

The system uses certificate-based device trust to verify that the device possesses an accepted certificate issued for the laboratory environment.

## Step 2 - Username and Password

The user enters the configured username and password.

If the credentials are incorrect, the failed-login mechanism records the attempt.

Repeated failed authentication attempts can result in temporary account locking.

## Step 3 - OTP / MFA

After the primary credentials are verified, the user must successfully complete OTP/MFA verification.

Only after the required authentication conditions are satisfied does the system proceed to the Zero Trust access decision.

---

# Policy Engine (PE)

The **Policy Engine** is responsible for making the Zero Trust access decision.

The main implementation is:

```text
policy_engine.py
```

The PE evaluates information including:

- Account status
- MFA verification
- Certificate status
- Expected device IP
- Device posture
- User role
- Trust score
- Identity risk
- Requested resource
- Enterprise policy

The PE can return decisions such as:

```text
GRANT
DENY
REVOKE
```

---

# Trust Score Calculation

The project calculates a trust score from several conditions.

| Security Condition | Trust Contribution |
|---|---:|
| Account is ACTIVE | +20 |
| MFA verified | +25 |
| Certificate ACTIVE | +25 |
| Expected IP matches | +15 |
| Device posture COMPLIANT | +15 |
| **Maximum** | **100** |

Example:

```text
Account ACTIVE        +20
MFA verified          +25
Certificate ACTIVE    +25
Expected IP           +15
Compliant posture     +15
-------------------------
Trust Score           100
```

The calculated score is compared with the minimum trust requirement in the applicable enterprise policy.

Typical project policy thresholds are:

| Role | Minimum Trust |
|---|---:|
| Guest | 60 |
| Employee | 70 |
| Admin | 80 |

These thresholds are project-defined policy values.

They are associated with role/resource policies rather than being permanent properties of individual devices.

---

# Risk Evaluation

Trust and risk are treated as separate concepts.

```text
Trust
  ↓
How much confidence does the system currently have?

Risk
  ↓
How much suspicious or unsafe behavior is currently associated with the identity?
```

Examples of factors that may affect identity risk include failed authentication attempts and behavioral conditions implemented by the project.

The Policy Engine checks both:

```text
Trust >= min_trust
```

and:

```text
Risk <= max_risk
```

before granting access.

---

# Enterprise Policy

Enterprise policies define what each role is allowed to access.

Example:

```text
Employee
├── Portal       → ALLOW
├── Documents    → ALLOW
├── Directory    → ALLOW
├── Projects     → ALLOW
├── Finance      → DENY
└── User Admin   → DENY
```

An Employee with a trust score of `100` can still be denied access to Finance.

This demonstrates an important principle:

> **Trust determines confidence. Role and enterprise policy determine privilege.**

High trust does not override an explicit resource restriction.

---

# Policy Administrator (PA)

The **Policy Administrator** executes the Policy Engine decision.

The main implementation is:

```text
policy_administrator.py
```

If the PE returns:

```text
GRANT
```

the PA can create an authenticated Zero Trust session.

The session contains information related to:

- Username
- Device IP
- Session status
- MFA verification
- Certificate verification
- Authentication level
- Creation time
- Last activity

The PA can also revoke an active session.

---

# Policy Enforcement Point (PEP)

The Company Portal acts as the application-level **Policy Enforcement Point**.

The main implementation is:

```text
protected_server/company_app.py
```

Protected resources include:

```text
/portal
/documents
/directory
/projects
/finance
/users
```

Before a protected resource is returned, the PEP checks the current Zero Trust decision.

```text
Browser Request
      |
      v
     PEP
      |
      v
PE evaluates current conditions
      |
      +------ GRANT ------> Allow Resource
      |
      +------ DENY -------> Block Resource
      |
      +------ REVOKE -----> Revoke Session + Block
```

---

# Continuous Access Evaluation

Zero Trust verification does not stop immediately after login.

For protected requests, the system can re-evaluate current access conditions.

For example:

```text
Initial Login
Trust = 100
Policy requirement = 70

100 >= 70
      ↓
GRANT
```

If security conditions later change:

```text
Trust decreases
      ↓
Current trust < required trust
      ↓
REVOKE
      ↓
PA revokes session
      ↓
PEP blocks access
```

Continuous verification does **not** mean repeatedly asking the user for an OTP every few seconds.

It means that the system can re-evaluate current security conditions while access is active.

---

# Security Monitoring

The project includes a network traffic analyzer:

```text
ztna_analyzer.py
```

The analyzer monitors selected traffic patterns against the protected server.

## Detection Rules

| Detection | Laboratory Threshold | Risk Score | Severity |
|---|---|---:|---|
| ICMP Ping Flood | 20 ICMP packets within 10 seconds | 65 | High |
| TCP Port Scan | 5 unique TCP ports | Project-defined | Medium |
| UDP Port Scan | 5 unique UDP ports | 45 | Medium |

These values are **laboratory detection policies** and should not be interpreted as universal industry severity standards.

Detected events are recorded and displayed through the project's security monitoring interface.

---

# Technologies Used

| Technology | Purpose |
|---|---|
| GNS3 | Virtual network laboratory |
| pfSense | Routing, segmentation, and firewall enforcement |
| Ubuntu Linux | Zero Trust application server |
| Kali Linux | Controlled security testing |
| Python 3 | Backend implementation |
| Flask | Web applications and APIs |
| MySQL | Project database |
| Scapy | Packet monitoring and traffic analysis |
| HTML/CSS | Dashboard and portal interfaces |
| Git | Source-code version control |
| GitHub | Project repository |

---

# Main Project Files

```text
ztna-project/
│
├── mfa_server.py
├── dashboard.py
├── database.py
├── policy.py
├── policy_engine.py
├── policy_administrator.py
├── risk_engine.py
├── security_utils.py
├── timeline.py
├── ztna_analyzer.py
│
├── protected_server/
│   └── company_app.py
│
├── templates/
├── static/
├── certs/
├── docs/
│   └── images/
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

# Installation and Setup

## Step 1 - Clone the Repository

```bash
git clone https://github.com/moe-23libby/internal-zero-trust-network.git
```

Enter the project directory:

```bash
cd internal-zero-trust-network
```

---

## Step 2 - Install Python

Check Python:

```bash
python3 --version
```

If required on Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

---

## Step 3 - Install Project Dependencies

Install the required packages:

```bash
pip3 install -r requirements.txt
```

The project uses packages such as:

```text
Flask
mysql-connector-python
Scapy
```

---

## Step 4 - Install MySQL

Install MySQL:

```bash
sudo apt install mysql-server -y
```

Check the service:

```bash
sudo systemctl status mysql
```

Start it if necessary:

```bash
sudo systemctl start mysql
```

---

## Step 5 - Configure Environment Variables

Copy the example configuration:

```bash
cp .env.example .env
```

Open it:

```bash
nano .env
```

Configure your local values.

Example:

```text
ZTNA_DB_HOST=127.0.0.1
ZTNA_DB_USER=YOUR_DATABASE_USER
ZTNA_DB_PASSWORD=YOUR_DATABASE_PASSWORD
ZTNA_DB_NAME=ztna_gateway

ZTNA_DASHBOARD_SECRET=YOUR_RANDOM_SECRET
```

Do not commit `.env` to GitHub.

Load the variables:

```bash
set -a
source .env
set +a
```

---

# How to Run the Project

The project contains several services. Run them in separate terminals.

Before starting a component, load the local environment variables.

```bash
cd ~/ztna-project
set -a
source .env
set +a
```

## Terminal 1 - MFA Server

```bash
cd ~/ztna-project
set -a
source .env
set +a

python3 mfa_server.py
```

This starts the authentication component responsible for the project's certificate/password/OTP authentication flow.

---

## Terminal 2 - Company Portal / PEP

```bash
cd ~/ztna-project
set -a
source .env
set +a

python3 protected_server/company_app.py
```

This starts the protected company application and application-level PEP.

---

## Terminal 3 - Administration Dashboard

```bash
cd ~/ztna-project
set -a
source .env
set +a

python3 dashboard.py
```

This starts the administrative and monitoring dashboard.

---

## Terminal 4 - Network Analyzer

```bash
cd ~/ztna-project
```

Start the analyzer using the privileges required for packet capture.

```bash
sudo python3 ztna_analyzer.py
```

The exact interface used by the analyzer should match the Ubuntu interface connected to the Server network.

---

# Application Services

The laboratory design uses the Ubuntu server:

```text
192.168.30.10
```

The main services are designed around:

| Service | Port |
|---|---:|
| Administration Dashboard | 5000 |
| MFA / Authentication | 5050 |
| Company Portal / PEP | 8000 |

Verify the current ports in the source code before deployment because they may be changed during development.

---

# Testing Employee Access

From the Employee endpoint:

```text
Employee PC
192.168.10.20
```

the expected flow is:

```text
Employee PC
      ↓
pfSense
      ↓
MFA Authentication
      ↓
Certificate + Password + OTP
      ↓
PE evaluates trust/risk/policy
      ↓
PA creates session
      ↓
PEP
      ↓
Company Portal
```

The Employee should be able to access authorized resources such as Documents while restricted resources such as Finance remain denied according to enterprise policy.

---

# Testing Guest Access

The Guest endpoint is:

```text
192.168.20.30
```

The Guest authenticates through the same Zero Trust process but receives permissions according to the Guest enterprise policies.

Guest access is therefore more restricted than Employee or Admin access.

---

# Testing Administrative Access

Admin authentication also requires the configured Zero Trust authentication conditions.

The Admin role has policies for administrative resources.

The dashboard can be used for actions such as:

- Viewing access information
- Viewing security events
- Revoking sessions
- Revoking registered certificates
- Unlocking locked accounts

---

# Controlled Security Testing

The Kali host is:

```text
192.168.40.50
```

The protected Ubuntu server is:

```text
192.168.30.10
```

Only perform these tests in an authorized laboratory environment.

## TCP Port Scan Test

```bash
sudo nmap -Pn -sS \
-p 22,80,443,5000,5050,8000 \
192.168.30.10
```

Purpose:

```text
Test TCP reconnaissance detection
        ↓
Network Analyzer
        ↓
TCP Port Scan event
        ↓
Threat Dashboard
```

---

## UDP Port Scan Test

```bash
sudo nmap -Pn -sU \
-p 53,67,68,123,161,500 \
192.168.30.10
```

Purpose:

```text
Test selected UDP reconnaissance detection
        ↓
Network Analyzer
        ↓
UDP Port Scan event
        ↓
Threat Dashboard
```

---

## Rapid ICMP Test

```bash
ping -i 0.1 -c 30 192.168.30.10
```

This generates rapid ICMP Echo Requests for the controlled laboratory test.

It is used to test the configured ICMP detection threshold.

---

# Security Design

The project separates three important security concepts:

```text
Authentication
      ↓
Who are you?

Authorization
      ↓
What are you allowed to access?

Monitoring
      ↓
What suspicious activity is occurring?
```

The project combines all three within the internal Zero Trust laboratory.

---

# Limitations

This implementation is an academic prototype and is not intended to be a production-ready Zero Trust platform.

Current limitations include:

- Controlled virtual laboratory environment
- Simplified database-based device posture
- Rule-based trust calculation
- Rule-based identity risk
- Selected network attack-pattern detection
- No full enterprise EDR/MDM integration
- No enterprise identity provider or SSO
- No production-scale certificate lifecycle management
- No high-availability deployment
- Limited scalability and performance testing

---

# Future Improvements

Possible future enhancements include:

- Real-time EDR/MDM device posture
- Enterprise identity provider integration
- SSO integration
- Stronger PKI and certificate lifecycle management
- Behavioral anomaly detection
- Automated security response
- SIEM integration
- High availability
- Scalability testing
- External/remote Zero Trust access

---

# Security Notice

Sensitive information is intentionally excluded from this repository.

The following files should never be committed:

```text
.env
*.key
*.p12
*.pfx
private credentials
access tokens
database passwords
```

This repository is intended for educational and authorized laboratory use.
