# 🔒 IntraGate: Zero-Trust Web Application Gateway & Reverse Proxy

IntraGate is a modern, high-performance, dynamic reverse proxy and identity-aware authentication gateway. It secures internal web applications using **Microsoft Entra ID (Azure AD)** Single Sign-On (SSO) and group-based access control (RBAC). 

With a local administrative control panel, administrators can register new applications, configure organizational branding, manage active sessions, and restrict access down to specific Entra ID Security Group IDs—all dynamically, without server restarts or config files edits.

---

## 🚀 Key Features

* **🛡️ Identity-Aware Proxy (IAP):** Gateways all upstream HTTP traffic behind Microsoft Entra ID OIDC SSO.
* **👥 Group-Based RBAC:** Fine-grained authorization restricting application routing to specific Entra ID Security Group Object UUIDs.
* **🎛️ Dynamic Upstream Registry:** Add, modify, or disable target applications and routing rules instantly via the admin interface.
* **🔐 Double-Encrypted Secrets:** All sensitive client credentials (e.g. Entra ID Client Secrets) and session tokens are encrypted symmetrically at rest (using AES-256 Fernet) in the PostgreSQL database.
* **🖥️ Localhost-Only Admin Panel:** Port-bound management console (`8585`) secured by local credentials and Multi-Factor Authentication (TOTP).
* **🎨 Custom Portal Branding:** Dynamically set theme colors, portal headers, footers, and upload custom organizational logos.
* **⏱️ Session Enforcement:** Customizable sliding inactivity timeouts and absolute session lifetimes.

---

## 📐 System Architecture

```
                                    +-----------------------------------+
                                    |         User Web Browser          |
                                    +-----------------+-----------------+
                                                      |
                                        Dynamic HTTP  |  SSO Callback /
                                        App Requests  |  OAuth Route
                                                      v
+-------------------------+         +-----------------+-----------------+
|   Local Administrator   |         |         IntraGate Proxy           |
|  (Localhost / Tunnel)   |         |        (Port 9000 / Custom)       |
+-----------+-------------+         +--------+--------+--------+--------+
            |                                |        |        |
            | HTTP (Port 8585)               |        |        | HTTP Reverse Proxy
            v                                |        v        | (Overwritten Auth Headers)
+-----------+-------------+                  |  +-----+----+   +---> +-----------------------+
|  IntraGate Admin Panel  |                  |  |  Azure   |         |   Upstream App #1     |
| (Setup, Apps, Branding) <==================+  | Entra ID |         +-----------------------+
+-----------+-------------+  Encrypt/Persist |  +----------+   +---> +-----------------------+
            |                Dynamic Registry|                       |   Upstream App #2     |
            v                                v                       +-----------------------+
+-----------+--------------------------------+--+
|              PostgreSQL Database              |
|        (Encrypted Sessions & Config)          |
+-----------------------------------------------+
```

---

## 🛠️ Deployment & Port Customization

IntraGate runs on two principal network entry points:
1. **User Gateway (`GATEWAY_PORT`, default: `9000`)**: The public/internal endpoint where users access secured applications.
2. **Admin Panel (`ADMIN_PORT`, default: `8585`)**: The configuration port bound to `127.0.0.1` by default for security.

### ⚓ How to Customize Ports & Host Bindings
If you want to use ports other than `9000` or `8585` (for instance, to run the gateway on port `80/443` or to bind the admin console to a private subnet interface), customize them in the `.env` file prior to launching:

* **To change the User Gateway Port**: Modify `GATEWAY_PORT` (e.g., `GATEWAY_PORT=80`).
* **To change the Admin Panel Port**: Modify `ADMIN_PORT` (e.g., `ADMIN_PORT=4433`).
* **To change binding host interfaces**: Modify `GATEWAY_HOST` (e.g., `GATEWAY_HOST=10.0.1.15`).

---

## 💿 Option A: Docker Compose Deployment (Recommended)

Follow these steps to deploy IntraGate using Docker Compose:

### 1. Clone the Repository
```bash
git clone https://github.com/adi469/Intragate.git
cd Intragate
```

### 2. Configure Environment Variables
Copy the template `.env.example` file to `.env`:
```bash
cp .env.example .env
```

Generate secure credentials and keys to fill out your `.env` file:
```bash
# 1. Generate GATEWAY_SECRET_KEY (must be at least 32 hex chars)
python3 -c "import secrets; print(secrets.token_hex(32))"

# 2. Generate GATEWAY_ENCRYPTION_KEY (must be a valid Fernet key)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Edit the `.env` file and set the generated values:
```env
# Session signature key
GATEWAY_SECRET_KEY=staged_secret_key_from_step_above

# Symmetric database encryption key
GATEWAY_ENCRYPTION_KEY=staged_fernet_key_from_step_above

# Custom ports
GATEWAY_PORT=9000
ADMIN_PORT=8585

# Database credentials
POSTGRES_PASSWORD=your_secure_postgres_db_password
DATABASE_URL=postgresql+asyncpg://postgres:your_secure_postgres_db_password@database:5432/intragate_gateway
```

### 3. Deploy the Stack
Start the database and gateway services in detached mode:
```bash
docker compose up -d
```

Verify that the containers are healthy:
```bash
docker compose ps
```

---

## 🐍 Option B: Native Python Setup (Local Development)

If you wish to run IntraGate directly on your system:

### 1. Clone the Repository
```bash
git clone https://github.com/adi469/Intragate.git
cd Intragate
```

### 2. Install PostgreSQL Database
Ensure you have a running PostgreSQL database server. Alternatively, spin up a lightweight PostgreSQL container:
```bash
docker run -d \
  --name intragate_postgres \
  -p 5432:5432 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=intragate_gateway \
  postgres:15-alpine
```

### 3. Install Python Dependencies
Set up a virtual environment and install the required modules:
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Create and Edit `.env`
```bash
cp .env.example .env
```
Update the `.env` file with your local database URL:
```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/intragate_gateway
GATEWAY_SECRET_KEY=32_or_more_character_random_string
GATEWAY_ENCRYPTION_KEY=valid_fernet_key_base64
```

### 5. Launch the Server
```bash
python run.py
```
This boots:
* The **User Gateway** listening on `http://localhost:9000` (or your custom `GATEWAY_PORT`).
* The **Admin Panel** listening on `http://127.0.0.1:8585` (or your custom `ADMIN_PORT`).

---

## ⚙️ Initial Configuration Workflow

Once the gateway is running, complete the following initial steps:

### Step 1: Initialize Admin Console
1. Open the Admin Panel in your browser: `http://localhost:8585`
2. Complete the initial setup by creating your root administrator credentials.
3. **MFA Enablement**: Navigate to the **Security** tab, scan the generated QR code with any TOTP application (Google Authenticator, Aegis, Bitwarden), verify the code, and enable MFA to secure your dashboard.

### Step 2: Register Microsoft Entra ID Application
1. Log in to the [Microsoft Azure Portal](https://portal.azure.com) and navigate to **Microsoft Entra ID -> App Registrations**.
2. Create a **New Registration**:
   * Name: `IntraGate SSO Gateway`
   * Supported account types: Single Tenant.
3. Configure **Redirect URIs**:
   * Platform: **Web**
   * Redirect URI: `http://localhost:9000/auth/callback` (replace with your production domain for actual deployment).
   * Ensure that **ID tokens (used for implicit and hybrid flows)** is checked under the implicit grant options.
4. Generate **Client Secret**:
   * Go to **Certificates & secrets** -> **Client secrets** -> **New client secret**.
   * Copy the secret string **Value** immediately (this string is masked after you leave the page).
5. Configure **Group Claims** (Optional - recommended for group access controls):
   * Select **Token configuration** -> **Add groups claim**.
   * Check **Security groups** to pass Group Object IDs in authorization tokens.

### Step 3: Seed Credentials in Admin Console
1. In the IntraGate Admin Console, click the **Entra ID** tab.
2. Provide your Tenant ID, Client ID, Client Secret, and Redirect URI.
3. Click **Save Configuration** and run **Test Connection** to verify connection to Entra ID APIs.

### Step 4: Register Secured Upstream Applications
1. Navigate to the **Applications** tab in the Admin Console.
2. Click **Add Application** and define:
   * **Name**: Display name for the application in the user selection portal.
   * **Slug / Route**: Subdomain or path prefix for routing (e.g. `dispatch-app`).
   * **Upstream Target**: The actual internal server address (e.g., `http://10.0.2.45:8080`).
   * **TLS Verify**: Enable or disable verification of upstream TLS certificates.
   * **Allowed Groups**: Comma-separated list of Entra ID Group Object UUIDs allowed to access this app. (Leave empty to allow all authenticated employees).
3. Save the application registry. The routing changes are immediately hot-loaded!

---

## 🛡️ Security Hardening

To run IntraGate in production safely, ensure the following practices:

* **Production Mode:** Set `GATEWAY_DEV_MODE=false` in your `.env`.
* **Trusted Proxies:** If deploying behind an external load balancer (like Cloudflare, Traefik, AWS ALB), define their IP addresses or CIDR blocks in `TRUSTED_PROXIES` (e.g. `TRUSTED_PROXIES=10.0.0.0/24,192.168.1.1`). This prevents spoofed `X-Forwarded-For` and `X-Real-IP` headers from bypassing brute-force lockout rules.
* **Admin Dashboard Access:** Keep the Admin Panel bound to loopback `127.0.0.1` and use SSH local port forwarding (`ssh -L 8585:127.0.0.1:8585 user@your-server`) to access it, rather than binding to `0.0.0.0`.
