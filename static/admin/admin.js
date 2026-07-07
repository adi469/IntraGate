/* ══════════════════════════════════════════════════════════════
   INTRAGATE GATEWAY — ADMIN PANEL LOGIC
   ══════════════════════════════════════════════════════════════ */

const API = '/admin/api';
let isSetupMode = false;

// ── Utilities ────────────────────────────────────────────────

async function api(path, opts = {}) {
    const url = API + path;
    const config = { credentials: 'same-origin', headers: {}, ...opts };
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
        config.headers['Content-Type'] = 'application/json';
        config.body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, config);
    if (res.status === 401 && !path.includes('/login') && !path.includes('/setup') && !path.includes('/check-setup')) {
        showLogin();
        throw new Error('Session expired');
    }
    return res;
}

function toast(msg, type = 'success') {
    const c = document.getElementById('toastContainer');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', info: 'fa-circle-info' };
    el.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i> ${msg}`;
    c.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

function $(id) { return document.getElementById(id); }

// ── Init ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await api('/check-setup');
        const data = await res.json();
        if (!data.admin_exists) {
            isSetupMode = true;
            $('loginSubtitle').textContent = 'Create your admin account to get started';
            $('loginBtnText').textContent = 'Create Account';
            $('setupConfirmGroup').style.display = 'block';
        }
    } catch(e) { /* ignore */ }

    // Check if already logged in
    try {
        const res = await api('/me');
        if (res.ok) {
            const me = await res.json();
            enterApp(me.username);
            return;
        }
    } catch(e) { /* not logged in */ }

    showLogin();

    // Mobile Sidebar Drawer Triggers
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    if (mobileMenuBtn && sidebar && sidebarOverlay) {
        mobileMenuBtn.addEventListener('click', () => {
            sidebar.classList.add('open');
            sidebarOverlay.classList.add('active');
        });

        sidebarOverlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            sidebarOverlay.classList.remove('active');
        });

        // Close sidebar when nav item is clicked
        document.querySelectorAll('.sidebar .nav-item').forEach(item => {
            item.addEventListener('click', () => {
                sidebar.classList.remove('open');
                sidebarOverlay.classList.remove('active');
            });
        });
    }

    // Quick Action Tab Switching
    document.querySelectorAll('[data-tab-target]').forEach(btn => {
        btn.addEventListener('click', () => {
            switchTab(btn.dataset.tabTarget);
        });
    });

    // Modal Cancel Trigger
    $('btnCancelModal')?.addEventListener('click', closeModal);
});

// ── Auth ─────────────────────────────────────────────────────

function showLogin() {
    $('loginView').style.display = 'flex';
    $('appShell').classList.remove('active');
}

function enterApp(username) {
    $('loginView').style.display = 'none';
    $('appShell').classList.add('active');
    $('userLabel').textContent = username;
    $('userAvatar').textContent = username.charAt(0).toUpperCase();
    loadDashboard();
}

$('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('loginUser').value.trim();
    const password = $('loginPass').value;

    if (isSetupMode) {
        const confirm = $('loginPassConfirm').value;
        if (password !== confirm) { toast('Passwords do not match', 'error'); return; }
        if (password.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
        try {
            const res = await api('/setup', { method: 'POST', body: { username, password } });
            if (res.ok) {
                toast('Admin account created!');
                isSetupMode = false;
                enterApp(username);
            } else {
                const err = await res.json();
                toast(err.detail || 'Setup failed', 'error');
            }
        } catch(e) { toast('Connection error', 'error'); }
        return;
    }

    // Normal login
    const totp_code = $('loginTotp').value.trim();
    try {
        const res = await api('/login', { method: 'POST', body: { username, password, totp_code } });
        const data = await res.json();
        if (data.requires_totp) {
            $('totpGroup').style.display = 'block';
            $('loginTotp').focus();
            toast('Enter your authenticator code', 'info');
            return;
        }
        if (res.ok) {
            toast('Welcome back!');
            enterApp(data.username);
        } else {
            toast(data.detail || 'Login failed', 'error');
        }
    } catch(e) { toast('Connection error', 'error'); }
});

$('logoutBtn').addEventListener('click', async () => {
    await api('/logout', { method: 'POST' });
    showLogin();
    $('loginUser').value = ''; $('loginPass').value = '';
    toast('Logged out', 'info');
});

// ── Tab Navigation ───────────────────────────────────────────

document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab(item.dataset.tab);
    });
});

function switchTab(tab) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`.nav-item[data-tab="${tab}"]`)?.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    $(`tab-${tab}`)?.classList.add('active');

    const loaders = { dashboard: loadDashboard, entra: loadEntra, apps: loadApps, portal: loadPortal, settings: loadSettings, security: loadSecurity, logs: loadLogs };
    loaders[tab]?.();
}

// ── Dashboard ────────────────────────────────────────────────

async function loadDashboard() {
    try {
        const res = await api('/status');
        const data = await res.json();
        $('statsGrid').innerHTML = `
            <div class="stat-card" style="--stat-accent:${data.entra_connected ? 'var(--success)' : 'var(--danger)'}">
                <div class="stat-icon"><i class="fa-brands fa-microsoft"></i></div>
                <div class="stat-value">${data.entra_connected ? 'Connected' : 'Not Set'}</div>
                <div class="stat-label">Entra ID Status</div>
            </div>
            <div class="stat-card" style="--stat-accent:var(--primary)">
                <div class="stat-icon"><i class="fa-solid fa-cubes"></i></div>
                <div class="stat-value">${data.app_count}</div>
                <div class="stat-label">Applications</div>
            </div>
            <div class="stat-card" style="--stat-accent:#8b5cf6">
                <div class="stat-icon"><i class="fa-solid fa-users"></i></div>
                <div class="stat-value">${data.active_user_sessions}</div>
                <div class="stat-label">Active Sessions</div>
            </div>
            <div class="stat-card" style="--stat-accent:var(--warning)">
                <div class="stat-icon"><i class="fa-solid fa-clock"></i></div>
                <div class="stat-value">${data.session_timeout_minutes}m</div>
                <div class="stat-label">Inactivity Timeout</div>
            </div>
        `;
    } catch(e) { console.error(e); }
}

// ── Entra ID ─────────────────────────────────────────────────

async function loadEntra() {
    try {
        const res = await api('/entra');
        const data = await res.json();
        $('entraTenant').value = data.tenant_id || '';
        $('entraClient').value = data.client_id || '';
        $('entraSecret').value = '';
        $('entraSecret').placeholder = data.client_secret_set ? '••••••• (saved — leave blank to keep)' : 'Enter client secret';
        const statusEl = $('entraStatus');
        if (data.connection_verified) {
            statusEl.innerHTML = `<span class="badge-status badge-success"><i class="fa-solid fa-circle-check"></i> Connected — verified ${data.last_verified_at ? new Date(data.last_verified_at).toLocaleString() : ''}</span>`;
        } else if (data.tenant_id) {
            statusEl.innerHTML = `<span class="badge-status badge-warning"><i class="fa-solid fa-triangle-exclamation"></i> Not verified — test connection</span>`;
        } else {
            statusEl.innerHTML = `<span class="badge-status badge-danger"><i class="fa-solid fa-circle-xmark"></i> Not configured</span>`;
        }
    } catch(e) { console.error(e); }
}

$('entraForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = { tenant_id: $('entraTenant').value, client_id: $('entraClient').value };
    const secret = $('entraSecret').value;
    if (secret) body.client_secret = secret;
    try {
        const res = await api('/entra', { method: 'POST', body });
        if (res.ok) { toast('Entra ID credentials saved'); loadEntra(); }
        else { const d = await res.json(); toast(d.detail || 'Save failed', 'error'); }
    } catch(e) { toast('Error saving', 'error'); }
});

$('testEntraBtn').addEventListener('click', async () => {
    const resultsEl = $('testResults');
    resultsEl.innerHTML = '<div class="test-steps"><div class="test-step pending"><div class="step-icon"><span class="spinner spinner-dark"></span></div><div>Testing connection…</div></div></div>';
    try {
        const res = await api('/entra/test', { method: 'POST' });
        const data = await res.json();
        let html = '<div class="test-steps">';
        for (const step of data.steps) {
            const icon = step.status === 'ok' ? 'fa-circle-check' : step.status === 'error' ? 'fa-circle-xmark' : 'fa-triangle-exclamation';
            html += `<div class="test-step ${step.status}"><div class="step-icon"><i class="fa-solid ${icon}"></i></div><div><strong>${step.step}</strong><div class="step-detail">${step.detail}</div></div></div>`;
        }
        html += '</div>';
        if (data.verified) html += '<p style="color:var(--success);margin-top:0.5rem;font-weight:600"><i class="fa-solid fa-check"></i> Connection verified!</p>';
        resultsEl.innerHTML = html;
        if (data.verified) loadEntra();
    } catch(e) { resultsEl.innerHTML = '<p style="color:var(--danger)">Connection test failed</p>'; }
});

// ── Applications ─────────────────────────────────────────────

async function loadApps() {
    try {
        const res = await api('/apps');
        const apps = await res.json();
        if (apps.length === 0) {
            $('appsList').innerHTML = `<div class="card" style="grid-column:1/-1;text-align:center;padding:3rem"><i class="fa-solid fa-cubes" style="font-size:2.5rem;color:var(--text-muted);margin-bottom:1rem"></i><p style="color:var(--text-secondary)">No applications configured yet</p><button class="btn btn-primary btn-sm" style="margin-top:1rem" data-action="add-app"><i class="fa-solid fa-plus"></i> Add First App</button></div>`;
            return;
        }
        $('appsList').innerHTML = apps.map(a => `
            <div class="app-card-admin" style="--card-accent:${a.color}">
                <div class="app-header">
                    <span class="app-icon">${a.icon}</span>
                    ${a.is_enabled
                        ? '<span class="badge-status badge-success">Active</span>'
                        : '<span class="badge-status badge-danger">Disabled</span>'}
                </div>
                <h3>${esc(a.name)}</h3>
                <p class="app-desc">${esc(a.description || 'No description')}</p>
                <div class="app-meta">
                    <span class="meta-tag">${esc(a.upstream_scheme || 'http')}://${esc(a.upstream_ip)}:${a.upstream_port}</span>
                    <span class="meta-tag">/app/${esc(a.slug)}/</span>
                </div>
                <div class="app-actions">
                    <button class="btn btn-outline btn-sm" data-action="edit-app" data-slug="${esc(a.slug)}"><i class="fa-solid fa-pen"></i> Edit</button>
                    <button class="btn btn-danger btn-sm" data-action="delete-app" data-slug="${esc(a.slug)}" data-name="${esc(a.name)}"><i class="fa-solid fa-trash"></i></button>
                </div>
            </div>
        `).join('');
    } catch(e) { console.error(e); }
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

$('addAppBtn').addEventListener('click', () => openAppModal());

$('appsList').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === 'add-app') openAppModal();
    else if (action === 'edit-app') editApp(btn.dataset.slug);
    else if (action === 'delete-app') deleteApp(btn.dataset.slug, btn.dataset.name);
});

function openAppModal(app = null) {
    $('appModalTitle').textContent = app ? 'Edit Application' : 'Add Application';
    $('appEditSlug').value = app ? app.slug : '';
    $('appName').value = app ? app.name : '';
    $('appSlug').value = app ? app.slug : '';
    $('appSlug').disabled = !!app;
    $('appDesc').value = app ? app.description : '';
    $('appIcon').value = app ? app.icon : '🔧';
    $('appGroupId').value = app ? app.group_id : '';
    $('appUpstreamScheme').value = app ? (app.upstream_scheme || 'http') : 'http';
    $('appUpstreamIp').value = app ? app.upstream_ip : '127.0.0.1';
    $('appUpstreamPort').value = app ? app.upstream_port : '';
    $('appColor').value = app ? app.color : '#1F4E79';
    $('appEnabled').checked = app ? app.is_enabled : true;
    $('appTlsVerify').checked = app ? (app.tls_verify !== false) : true;
    $('appModal').classList.add('active');
}

function closeModal() { $('appModal').classList.remove('active'); }

$('appModal').addEventListener('click', (e) => { if (e.target === $('appModal')) closeModal(); });

async function editApp(slug) {
    const res = await api('/apps');
    const apps = await res.json();
    const app = apps.find(a => a.slug === slug);
    if (app) openAppModal(app);
}

async function deleteApp(slug, name) {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    try {
        const res = await api(`/apps/${slug}`, { method: 'DELETE' });
        if (res.ok) { toast('Application deleted'); loadApps(); }
        else { toast('Delete failed', 'error'); }
    } catch(e) { toast('Error', 'error'); }
}

$('appForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const editSlug = $('appEditSlug').value;
    const color = $('appColor').value;
    const body = {
        name: $('appName').value.trim(),
        slug: $('appSlug').value.trim(),
        description: $('appDesc').value.trim(),
        icon: $('appIcon').value,
        group_id: $('appGroupId').value.trim(),
        upstream_scheme: $('appUpstreamScheme').value,
        upstream_ip: $('appUpstreamIp').value.trim(),
        upstream_port: parseInt($('appUpstreamPort').value),
        color: color,
        gradient: `linear-gradient(135deg, ${color} 0%, ${lightenColor(color, 20)} 100%)`,
        is_enabled: $('appEnabled').checked,
        tls_verify: $('appTlsVerify').checked,
    };

    try {
        const method = editSlug ? 'PUT' : 'POST';
        const path = editSlug ? `/apps/${editSlug}` : '/apps';
        const res = await api(path, { method, body });
        if (res.ok) {
            toast(editSlug ? 'Application updated' : 'Application added');
            closeModal();
            loadApps();
        } else {
            const d = await res.json();
            toast(d.detail || 'Save failed', 'error');
        }
    } catch(e) { toast('Error saving', 'error'); }
});

function lightenColor(hex, pct) {
    let r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
    r = Math.min(255, r + Math.round((255-r)*pct/100));
    g = Math.min(255, g + Math.round((255-g)*pct/100));
    b = Math.min(255, b + Math.round((255-b)*pct/100));
    return `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`;
}

// ── Portal ───────────────────────────────────────────────────

async function loadPortal() {
    try {
        const res = await api('/portal');
        const data = await res.json();
        $('portalOrgName').value = data.org_name || '';
        $('portalOrgSub').value = data.org_subtext || '';
        $('portalLogoMode').value = data.logo_mode || 'none';
        $('portalLogoUrl').value = data.logo_url || '';
        $('portalPrimary').value = data.primary_color || '#1f6b9a';
        $('portalAccent').value = data.accent_color || '#9b59b6';
        $('portalFooter').value = data.footer_text || '';
        updateLogoFields();
        updatePreview();
    } catch(e) { console.error(e); }
}

$('portalLogoMode').addEventListener('change', updateLogoFields);
function updateLogoFields() {
    const mode = $('portalLogoMode').value;
    $('logoFileGroup').style.display = mode === 'file' ? 'block' : 'none';
    $('logoUrlGroup').style.display = mode === 'url' ? 'block' : 'none';
}

['portalOrgName', 'portalOrgSub', 'portalPrimary', 'portalAccent', 'portalFooter', 'portalLogoUrl'].forEach(id => {
    $(id)?.addEventListener('input', updatePreview);
});

function updatePreview() {
    $('previewOrg').textContent = $('portalOrgName').value || 'My Organization';
    $('previewFooter').textContent = '© 2026 IntraGate. All rights reserved. | Secured by Active Directory SSO';
    const primary = $('portalPrimary').value;
    $('previewOrg').style.color = primary;
    // Logo preview
    const mode = $('portalLogoMode').value;
    const logo = $('previewLogo');
    if (mode === 'url' && $('portalLogoUrl').value) {
        logo.src = $('portalLogoUrl').value;
        logo.style.display = 'block';
    } else { logo.style.display = 'none'; }
}

$('portalForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    // Handle file upload first if needed
    const mode = $('portalLogoMode').value;
    if (mode === 'file' && $('portalLogoFile').files.length > 0) {
        const fd = new FormData();
        fd.append('file', $('portalLogoFile').files[0]);
        try {
            const res = await fetch(API + '/portal/logo', { method: 'POST', body: fd, credentials: 'same-origin' });
            if (!res.ok) { toast('Logo upload failed', 'error'); return; }
        } catch(e) { toast('Upload error', 'error'); return; }
    }
    const body = {
        org_name: $('portalOrgName').value.trim(),
        org_subtext: $('portalOrgSub').value.trim(),
        logo_mode: mode,
        logo_url: $('portalLogoUrl').value.trim(),
        primary_color: $('portalPrimary').value,
        accent_color: $('portalAccent').value,
        footer_text: $('portalFooter').value.trim(),
    };
    try {
        const res = await api('/portal', { method: 'PUT', body });
        if (res.ok) { toast('Portal settings saved'); }
        else { toast('Save failed', 'error'); }
    } catch(e) { toast('Error', 'error'); }
});

// ── Settings ─────────────────────────────────────────────────

async function loadSettings() {
    try {
        const res = await api('/settings');
        const data = await res.json();
        $('settingsBaseUrl').value = data.gateway_base_url || '';
        $('settingsLifetime').value = data.session_lifetime_hours || 12;
        $('settingsTimeout').value = data.session_timeout_minutes || 60;
    } catch(e) { console.error(e); }
}

$('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {
        gateway_base_url: $('settingsBaseUrl').value.trim(),
        session_lifetime_hours: parseInt($('settingsLifetime').value),
        session_timeout_minutes: parseInt($('settingsTimeout').value),
        setup_complete: true,
    };
    try {
        const res = await api('/settings', { method: 'PUT', body });
        if (res.ok) { toast('Settings saved'); }
        else { toast('Save failed', 'error'); }
    } catch(e) { toast('Error', 'error'); }
});

// ── Security / TOTP ──────────────────────────────────────────

async function loadSecurity() {
    try {
        const res = await api('/me');
        const me = await res.json();
        const statusEl = $('totpStatus');
        const setupEl = $('totpSetupArea');
        if (me.totp_enabled) {
            statusEl.innerHTML = '<span class="badge-status badge-success"><i class="fa-solid fa-shield-halved"></i> TOTP Enabled</span>';
            setupEl.innerHTML = '<button class="btn btn-danger btn-sm" style="margin-top:1rem" id="disableTotpBtn"><i class="fa-solid fa-shield-xmark"></i> Disable TOTP</button>';
            $('disableTotpBtn').addEventListener('click', async () => {
                if (!confirm('Disable two-factor authentication?')) return;
                const res = await api('/totp/disable', { method: 'POST' });
                if (res.ok) { toast('TOTP disabled'); loadSecurity(); }
            });
        } else {
            statusEl.innerHTML = '<span class="badge-status badge-warning"><i class="fa-solid fa-shield-xmark"></i> TOTP Not Enabled</span>';
            setupEl.innerHTML = '<button class="btn btn-success btn-sm" style="margin-top:1rem" id="enableTotpBtn"><i class="fa-solid fa-mobile-screen"></i> Enable TOTP</button>';
            $('enableTotpBtn').addEventListener('click', startTotpSetup);
        }
    } catch(e) { console.error(e); }
}

async function startTotpSetup() {
    try {
        const res = await api('/totp/setup', { method: 'POST' });
        const data = await res.json();
        const setupEl = $('totpSetupArea');
        setupEl.innerHTML = `
            <div class="qr-container"><img src="data:image/png;base64,${data.qr_code}" alt="TOTP QR Code"></div>
            <p style="color:var(--text-secondary);font-size:0.85rem;text-align:center">Scan with your authenticator app</p>
            <div class="totp-secret">Secret: ${data.secret}</div>
            <div class="form-group">
                <label>Enter verification code</label>
                <input type="text" id="totpVerifyCode" placeholder="6-digit code" maxlength="6">
            </div>
            <button class="btn btn-success btn-sm" id="confirmTotpBtn"><i class="fa-solid fa-check"></i> Verify & Enable</button>
        `;
        $('confirmTotpBtn').addEventListener('click', async () => {
            const code = $('totpVerifyCode').value.trim();
            if (!code) return;
            const res = await api('/totp/confirm', { method: 'POST', body: { code } });
            if (res.ok) { toast('TOTP enabled!'); loadSecurity(); }
            else { toast('Invalid code', 'error'); }
        });
    } catch(e) { toast('Setup failed', 'error'); }
}

// Password Change Validation
const newPasswordInput = $('newPassword');
const confirmPasswordInput = $('confirmPassword');
const strengthBar = $('strengthBar');
const strengthLabel = $('strengthLabel');
const confirmMessage = $('confirmMessage');
const submitPasswordBtn = $('submitPasswordBtn');

function validatePassword() {
    const pwd = newPasswordInput.value;
    const cpwd = confirmPasswordInput.value;
    
    // Check complexity
    let score = 0;
    const reqs = {
        length: pwd.length >= 8,
        case: /[a-z]/.test(pwd) && /[A-Z]/.test(pwd),
        number: /[0-9]/.test(pwd),
        special: /[^A-Za-z0-9]/.test(pwd)
    };
    
    // Update checklist icons
    for (const [key, met] of Object.entries(reqs)) {
        const item = $(`req-${key}`);
        if (item) {
            const icon = item.querySelector('i');
            if (met) {
                item.style.color = 'var(--success)';
                icon.className = 'fa-regular fa-circle-check';
                score++;
            } else {
                item.style.color = pwd.length > 0 ? 'var(--danger)' : 'var(--text-muted)';
                icon.className = 'fa-regular fa-circle';
            }
        }
    }
    
    // Update strength meter
    const pct = pwd.length > 0 ? (score / 4) * 100 : 0;
    strengthBar.style.width = `${pct}%`;
    
    if (pwd.length === 0) {
        strengthLabel.textContent = 'Strength: Empty';
        strengthLabel.style.color = 'var(--text-secondary)';
        strengthBar.style.background = 'var(--danger)';
    } else if (score <= 1) {
        strengthLabel.textContent = 'Strength: Weak';
        strengthLabel.style.color = 'var(--danger)';
        strengthBar.style.background = 'var(--danger)';
    } else if (score <= 3) {
        strengthLabel.textContent = 'Strength: Medium';
        strengthLabel.style.color = 'var(--warning)';
        strengthBar.style.background = 'var(--warning)';
    } else {
        strengthLabel.textContent = 'Strength: Strong';
        strengthLabel.style.color = 'var(--success)';
        strengthBar.style.background = 'var(--success)';
    }
    
    // Check confirmation matching
    let confirmOk = false;
    if (cpwd.length === 0) {
        confirmMessage.textContent = '';
    } else if (pwd === cpwd) {
        confirmMessage.textContent = 'Passwords match';
        confirmMessage.style.color = 'var(--success)';
        confirmOk = true;
    } else {
        confirmMessage.textContent = 'Passwords do not match';
        confirmMessage.style.color = 'var(--danger)';
    }
    
    // Enable/disable submit button
    const allMet = score === 4 && confirmOk;
    submitPasswordBtn.disabled = !allMet;
}

if (newPasswordInput && confirmPasswordInput) {
    newPasswordInput.addEventListener('input', validatePassword);
    confirmPasswordInput.addEventListener('input', validatePassword);
}

$('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = { old_password: $('oldPassword').value, new_password: $('newPassword').value };
    try {
        const res = await api('/change-password', { method: 'POST', body });
        if (res.ok) { 
            toast('Password changed successfully'); 
            $('oldPassword').value = ''; 
            $('newPassword').value = ''; 
            $('confirmPassword').value = '';
            validatePassword();
        } else { 
            const d = await res.json(); 
            toast(d.detail || 'Failed to update password', 'error'); 
        }
    } catch(e) { toast('Error changing password', 'error'); }
});


// ── Audit Logs ────────────────────────────────────────────────

let logsOffset = 0;
const logsLimit = 25;

async function loadLogs() {
    const email = $('filterEmail').value.trim();
    const event = $('filterEvent').value;
    try {
        const url = `/logs?limit=${logsLimit}&offset=${logsOffset}&event_type=${event}&user_email=${encodeURIComponent(email)}`;
        const res = await api(url);
        const data = await res.json();
        
        const tbody = $('logsTableBody');
        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No logs found matching filters.</td></tr>`;
            $('logsPaginationInfo').textContent = 'Showing 0 to 0 of 0 entries';
            $('btnPrevLogs').disabled = true;
            $('btnNextLogs').disabled = true;
            return;
        }
        
        tbody.innerHTML = data.logs.map(log => {
            const dateStr = log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A';
            const eventLabel = log.event_type.toUpperCase().replace(/_/g, ' ');
            
            let badgeClass = 'badge-status';
            if (log.event_type === 'access_denied') {
                badgeClass += ' badge-danger';
            } else if (log.event_type === 'login' || log.event_type === 'admin_login') {
                badgeClass += ' badge-success';
            } else if (log.event_type === 'app_access') {
                badgeClass += ' badge-success';
            } else {
                badgeClass += ' badge-warning';
            }
            
            let details = esc(log.details || '');
            if (log.app_name) {
                details = `<strong>${esc(log.app_name)}</strong> — ${details}`;
            }
            
            return `
                <tr>
                    <td style="color: var(--text-secondary); font-size: 0.8rem; white-space: nowrap;">${esc(dateStr)}</td>
                    <td><span class="${badgeClass}" style="font-size: 0.7rem; font-weight: 700; text-transform: uppercase;">${esc(eventLabel)}</span></td>
                    <td style="font-family: monospace; font-size: 0.8rem;">${esc(log.user_email || 'unknown')}</td>
                    <td style="font-size: 0.8rem; color: var(--text-secondary);">${esc(log.ip_address || 'N/A')}</td>
                    <td style="font-size: 0.85rem; color: var(--text-secondary); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${esc(log.details || '')}">${details}</td>
                </tr>
            `;
        }).join('');
        
        const start = logsOffset + 1;
        const end = Math.min(logsOffset + data.logs.length, data.total_count);
        $('logsPaginationInfo').textContent = `Showing ${start} to ${end} of ${data.total_count} entries`;
        
        $('btnPrevLogs').disabled = logsOffset === 0;
        $('btnNextLogs').disabled = logsOffset + logsLimit >= data.total_count;
    } catch (e) {
        console.error(e);
        $('logsTableBody').innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 2rem;">Error loading logs.</td></tr>`;
    }
}

// Attach listeners for logs filter, clear, pagination, and exports
document.addEventListener('DOMContentLoaded', () => {
    $('btnFilterLogs')?.addEventListener('click', () => {
        logsOffset = 0;
        loadLogs();
    });
    
    $('btnClearLogs')?.addEventListener('click', () => {
        $('filterEmail').value = '';
        $('filterEvent').value = 'all';
        logsOffset = 0;
        loadLogs();
    });
    
    $('btnPrevLogs')?.addEventListener('click', () => {
        if (logsOffset >= logsLimit) {
            logsOffset -= logsLimit;
            loadLogs();
        }
    });
    
    $('btnNextLogs')?.addEventListener('click', () => {
        logsOffset += logsLimit;
        loadLogs();
    });
    
    $('btnExportCSV')?.addEventListener('click', () => {
        const email = $('filterEmail').value.trim();
        const event = $('filterEvent').value;
        window.location.href = `${API}/logs/export/csv?event_type=${event}&user_email=${encodeURIComponent(email)}`;
    });
    
    $('btnExportPDF')?.addEventListener('click', () => {
        const email = $('filterEmail').value.trim();
        const event = $('filterEvent').value;
        window.location.href = `${API}/logs/export/pdf?event_type=${event}&user_email=${encodeURIComponent(email)}`;
    });
});
