# Microsoft Entra ID Integration Setup Guide

Use this step-by-step guide during your remote session to configure **Microsoft Entra ID (M365 Admin Portal)** for the IntraGate Gateway.

---

## Part 1: Microsoft Entra Admin Portal Setup

### Step 1: Register the Application
1. Log in to the [Microsoft Entra admin center](https://entra.microsoft.com) using your admin credentials.
2. Expand the **Identity** menu on the left and navigate to **Applications > App registrations**.
3. Click **New registration** at the top.
4. Fill in the following details:
   - **Name**: `IntraGate Tools Gateway`
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**: Select **Web** from the dropdown and enter:
     `https://ai.intragate.net/auth/callback`
5. Click **Register**.

### Step 2: Note Down Application Identifiers
Once the application is registered, copy the following strings from the **Overview** tab:
- **Application (client) ID**: (Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- **Directory (tenant) ID**: (Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### Step 3: Create a Client Secret
1. In the left navigation of your app registration, go to **Certificates & secrets**.
2. Select the **Client secrets** tab and click **New client secret**.
3. Add a description (e.g., `Gateway Client Secret`) and set an expiration (e.g., 730 days / 24 months).
4. Click **Add**.
5. **CRITICAL**: Copy the value in the **Value** column (not Secret ID) immediately. It will be hidden permanently once you leave this page.

### Step 4: Configure Group Claims
To allow the gateway to authorize users based on their security groups, you must inject groups into the login tokens:
1. In the left navigation, go to **Token configuration**.
2. Click **Add groups claim**.
3. Check the box for **Security groups**.
4. Expand the **ID** section, and under **Customize token claims by type**, choose **Group ID** (this returns the group's GUID object ID).
5. Click **Add**.

### Step 5: Configure API Permissions
1. In the left navigation, go to **API permissions**.
2. Verify that **Microsoft Graph** has the following delegated permissions:
   - `User.Read`
   - `openid`
   - `profile`
   - `email`
3. Click **Grant admin consent for <your organization>** at the top, and click **Yes** to confirm.

---

## Part 2: Create Security Groups

Now, create the 4 groups that correspond to each tool:
1. Navigate to **Identity > Groups > All groups**.
2. Click **New group**.
3. Configure as:
   - **Group type**: `Security`
   - **Group name**: `IntraGate-Dispatch-Planning`
   - **Membership type**: `Assigned`
4. Click **Create**.
5. Repeat this step for the remaining 3 groups:
   - `IntraGate-FG-Assembly`
   - `IntraGate-Quality-Dashboard`
   - `IntraGate-VMC-Planning`

Navigate back to the list of groups, click each group, and copy their **Object ID** (GUIDs) from the overview.

---

## Part 3: Gateway Configuration (`.env`)

Create a `.env` file inside the `gateway/` directory on your server and populate it with the secrets you gathered:

```env
# ─── Microsoft Entra ID (Azure AD) ────────────────────────────
AZURE_TENANT_ID=your-tenant-id-here
AZURE_CLIENT_ID=your-client-id-here
AZURE_CLIENT_SECRET=your-client-secret-here

# ─── Gateway ──────────────────────────────────────────────────
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=9000
GATEWAY_SECRET_KEY=generate-a-random-64-char-hex-string
GATEWAY_BASE_URL=https://ai.intragate.net
SESSION_LIFETIME_HOURS=12

# ─── Entra Group → App Mapping (Object IDs) ──────────────────
GROUP_DISPATCH=object-id-of-IntraGate-Dispatch-Planning
GROUP_ASSEMBLY=object-id-of-IntraGate-FG-Assembly
GROUP_QUALITY=object-id-of-IntraGate-Quality-Dashboard
GROUP_VMC=object-id-of-IntraGate-VMC-Planning

# ─── Internal App Upstreams (127.0.0.1 only) ─────────────────
DISPATCH_UPSTREAM=http://127.0.0.1:8001
ASSEMBLY_UPSTREAM=http://127.0.0.1:8002
QUALITY_UPSTREAM=http://127.0.0.1:8003
VMC_UPSTREAM=http://127.0.0.1:8004
```
