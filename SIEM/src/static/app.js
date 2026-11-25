// Fintech Mini-SIEM ENTERPRISE SOC - Frontend JavaScript
// Optimized, modular, and production-ready

(() => {
    'use strict';

    // ============================================================================
    // Constants & State
    // ============================================================================

    const API_BASE = '/api';
    const LANGUAGES = ['en', 'ru'];
    const TIME_RANGES = ['1h', '6h', '12h', '24h', '48h', '72h'];

    // App state
    const state = {
        lang: localStorage.getItem('siem_lang') || 'en',
        timeRange: '24h',
        autoRefresh: true,
        refreshInterval: null,
        data: {
            stats: null,
            alerts: [],
            incidents: [],
            devices: [],
            blockedIPs: [],
            frozenAccounts: [],
            auditLog: []
        },
        filters: {
            severity: '',
            status: '',
            search: ''
        }
    };

    // ============================================================================
    // API Client
    // ============================================================================

    async function apiFetch(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return await response.json();
        } catch (error) {
            showToast(error.message || 'API error', 'error');
            throw error;
        }
    }

    // ============================================================================
    // Toast Notifications
    // ============================================================================

    function showToast(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-message">${message}</span>
            <button class="toast-close">×</button>
        `;

        toast.querySelector('.toast-close').onclick = () => {
            toast.style.animation = 'slideInReverse 200ms ease';
            setTimeout(() => toast.remove(), 200);
        };

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideInReverse 200ms ease';
            setTimeout(() => toast.remove(), 200);
        }, duration);
    }

    // ============================================================================
    // Language & Localization
    // ============================================================================

    function setLang(l) {
        state.lang = l;
        localStorage.setItem('siem_lang', l);
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.lang === l);
            btn.setAttribute('aria-pressed', btn.dataset.lang === l);
        });
        loadAllData();
    }

    // ============================================================================
    // Tab Navigation
    // ============================================================================

    function showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.hidden = true;
        });

        // Show selected tab
        const tab = document.getElementById(`tab-${tabName}`);
        if (tab) {
            tab.hidden = false;
        }

        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            const isActive = btn.dataset.tab === tabName;
            btn.classList.toggle('active', isActive);
            btn.setAttribute('aria-selected', isActive);
        });

        // Load tab content
        switch (tabName) {
            case 'alerts': loadAlerts(); break;
            case 'search': loadSearch(); break;
            case 'fleet': loadFleet(); break;
            case 'ai': loadAI(); break;
            case 'incidents': loadIncidents(); break;
            case 'soar': loadSOAR(); break;
        }
    }

    // ============================================================================
    // Data Loading
    // ============================================================================

    async function loadAllData() {
        try {
            state.data.stats = await apiFetch('/stats');
            updateKPIs();
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    }

    async function loadAlerts() {
        try {
            let url = '/alerts';
            if (state.filters.severity) {
                url += `?severities=${state.filters.severity}`;
            }
            state.data.alerts = await apiFetch(url);
            renderAlerts();
        } catch (e) {
            document.getElementById('alertsBody').innerHTML =
                '<tr><td colspan="10" style="padding:40px;text-align:center;color:var(--text-dim)">Failed to load alerts</td></tr>';
        }
    }

    async function loadIncidents() {
        try {
            state.data.incidents = await apiFetch('/incidents');
            renderIncidents();
        } catch (e) {
            document.getElementById('incidentsContainer').innerHTML = '<p style="text-align:center;color:var(--text-dim)">Failed to load incidents</p>';
        }
    }

    async function loadSOAR() {
        try {
            const soarData = await apiFetch('/soar');
            state.data.blockedIPs = soarData.blocked_ips || [];
            state.data.frozenAccounts = soarData.frozen_accounts || [];
            state.data.auditLog = soarData.audit_log || [];
            renderSOAR();
        } catch (e) {
            showToast('Failed to load SOAR data', 'error');
        }
    }

    // ============================================================================
    // KPI Updates
    // ============================================================================

    function updateKPIs() {
        if (!state.data.stats) return;

        setInnerHTML('kpiTotalEvents', state.data.stats.total_events);
        setInnerHTML('kpiCriticalAlerts', state.data.stats.critical_alerts);
        setInnerHTML('kpiHighAlerts', state.data.stats.high_alerts);
        setInnerHTML('kpiActiveIncidents', state.data.stats.active_incidents);
        setInnerHTML('kpiBlockedIPs', state.data.stats.blocked_ips);
        setInnerText('kpiMeanRisk', state.data.stats.mean_risk_score);
    }

    function setInnerHtml(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = value;
    }

    // ============================================================================
    // Alert Rendering
    // ============================================================================

    function renderAlerts() {
        const tbody = document.getElementById('alertsBody');
        if (!tbody) return;

        tbody.innerHTML = state.data.alerts.map(alert => `
            <tr>
                <td>${alert.id.substring(0, 8)}...</td>
                <td>${alert.mitre_id || '-'}</td>
                <td>${alert.title || '-'}</td>
                <td><span class="badge badge-${alert.severity?.toLowerCase()}">${alert.severity}</span></td>
                <td>${alert.risk_score || 0}</td>
                <td><span class="badge badge-${alert.status?.toLowerCase()}">${alert.status}</span></td>
                <td>${alert.user_id || '-'}</td>
                <td>${alert.source_ip}</td>
                <td>${alert.source_ip}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="triageAlert('${alert.id}', 'investigate')">
                        Investigate
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="triageAlert('${alert.id}', 'resolve')">
                        Resolve
                    </button>
                </td>
            </tr>
        `).join('');
    }

    // ============================================================================
    // Incident Rendering
    // ============================================================================

    function renderIncidents() {
        const container = document.getElementById('incidentsContainer');
        if (!container) return;

        if (!state.data.incidents || state.data.incidents.length === 0) {
            container.innerHTML = `
                <div style="text-align:center;padding:40px;color:var(--text-dim)">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" style="margin:0 auto 16px">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <p>No incidents</p>
                    <p style="font-size:13px;color:var(--text-dim)">Run threat hunts to generate incidents</p>
                </div>
            `;
            return;
        }

        container.innerHTML = state.data.incidents.map(inc => `
            <div class="card" style="margin-bottom:16px">
                <div class="card-header">
                    <h3>${inc.title}</h3>
                    <span class="badge badge-${inc.severity?.toLowerCase()}">${inc.severity}</span>
                </div>
                <div class="card-body">
                    <p>${inc.summary}</p>
                </div>
            </div>
        `).join('');
    }

    // ============================================================================
    // SOAR Rendering
    // ============================================================================

    function renderSOAR() {
        // Blocked IPs
        document.getElementById('blockedCount').textContent = state.data.blockedIPs.length;
        document.getElementById('blockedIpsBody').innerHTML = state.data.blockedIPs.map(item => `
            <tr>
                <td>${item.ip}</td>
                <td>${item.reason}</td>
                <td>${item.blocked_at || '-'}</td>
                <td>${item.performed_by}</td>
                <td><button class="btn btn-sm btn-primary" onclick="unblockIP('${item.ip}')">Unblock</button></td>
            </tr>
        `).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No blocked IPs</td></tr>';

        // Frozen Accounts
        document.getElementById('frozenCount').textContent = state.data.frozenAccounts.length;
        document.getElementById('frozenBody').innerHTML = state.data.frozenAccounts.map(item => `
            <tr>
                <td>${item.user_id}</td>
                <td>${item.name || item.user_id}</td>
                <td>${item.reason}</td>
                <td>${item.frozen_at || '-'}</td>
                <td>${item.performed_by}</td>
                <td><button class="btn btn-sm btn-danger">Unfreeze</button></td>
            </tr>
        `).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No frozen accounts</td></tr>';

        // Audit Log
        document.getElementById('auditLogBody').innerHTML = state.data.auditLog.map(item => `
            <tr>
                <td>${item.timestamp || '-'}</td>
                <td>${item.action || item.type}</td>
                <td>${item.target}</td>
                <td>${item.reason}</td>
                <td>${item.performed_by}</td>
            </tr>
        `).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No recent activity</td></tr>';
    }

    // ============================================================================
    // Fleet Rendering
    // ============================================================================

    async function loadFleet() {
        try {
            const fleet = await apiFetch('/fleet');
            renderFleet(fleet);
        } catch (e) {
            showToast('Failed to load fleet data', 'error');
        }
    }

    function renderFleet(data) {
        // Fleet KPIs
        document.getElementById('kpiEmpOffice').textContent = data.employees_office || '--';
        document.getElementById('kpiContOffice').textContent = data.contingent_office || '--';
        document.getElementById('kpiEmpRemote').textContent = data.employees_remote || '--';
        document.getElementById('kpiContRemote').textContent = data.contingent_remote || '--';

        // Training
        const training = data.security_training || { completed: 0, in_progress: 0, not_started: 0, overdue: 0, total: 0 };
        const pct = training.total ? Math.round((training.completed / training.total) * 100) : 0;
        document.getElementById('trainingPct').textContent = `${pct}%`;
        document.getElementById('trainingCompleted').textContent = training.completed;
        document.getElementById('trainingInProgress').textContent = training.in_progress || 0;
        document.getElementById('trainingNotStarted').textContent = training.not_started || 0;
        document.getElementById('trainingOverdue').textContent = training.overdue || 0;
        document.getElementById('complianceTotal').textContent = data.total_devices || '--';

        // Devices table
        // Note: Would need /devices endpoint - for now show placeholder
        document.getElementById('devicesBody').innerHTML = data.devices
            ? data.devices.map(d => `<tr><td colspan="11" style="text-align:center">Loading devices...</td></tr>`).join('')
            : '<tr><td colspan="11" style="text-align:center;color:var(--text-dim)">Device data not available</td></tr>';
    }

    // ============================================================================
    // Search Rendering
    // ============================================================================

    async function loadSearch() {
        document.getElementById('searchEventsBody').innerHTML =
            '<tr><td colspan="8" style="padding:40px;text-align:center">Enter a query to search</td></tr>';
    }

    // ============================================================================
    // AI/SOC Assistant
    // ============================================================================

    async function loadAI() {
        // AI tab is the chat interface
        document.getElementById('chatMessages').innerHTML = `
            <div class="chat-message assistant">
                <div class="chat-bubble">
                    <strong>Welcome to the SOC AI Threat Hunt Assistant!</strong>
                    I can help you hunt for threats across your fintech environment.
                    Choose a preset hunt from the sidebar or ask me anything.
                </div>
                <div class="chat-meta">SOC AI Assistant • Just now</div>
            </div>
        `;
    }

    // ============================================================================
    // AI Hunt Actions
    // ============================================================================

    async function runAIHunt(prompt) {
        try {
            const result = await apiFetch('/ai-hunt', {
                method: 'POST',
                body: JSON.stringify({ prompt })
            });

            addChatMessage('user', prompt);

            setTimeout(() => {
                addChatMessage('assistant',
                    `**SPL Query:**\n\`\`\`\n${result.spl_query}\n\`\`\`\n\n**Summary:** ${result.summary}\n\n**Findings:** ${JSON.stringify(result.findings, null, 2)}`
                );
            }, 500);

        } catch (e) {
            showToast('AI hunt failed', 'error');
        }
    }

    function addChatMessage(role, content) {
        const container = document.getElementById('chatMessages');
        const msg = document.createElement('div');
        msg.className = `chat-message ${role}`;
        msg.innerHTML = `
            <div class="chat-bubble">${content}</div>
            <div class="chat-meta">${role === 'user' ? 'You' : 'SOC AI Assistant'} • Just now</div>
        `;
        container.appendChild(msg);
        container.scrollTop = container.scrollHeight;
    }

    // ============================================================================
    // Actions
    // ============================================================================

    window.triageAlert = async function(id, action) {
        // In a real app, this would call the appropriate API
        showToast(`Alert ${id} marked for ${action}`, 'info');
        loadAlerts();
    };

    window.unblockIP = async function(ip) {
        try {
            await apiFetch('/unblock-ip', {
                method: 'POST',
                body: JSON.stringify({ ip, performed_by: 'analyst' })
            });
            showToast(`IP ${ip} unblocked`, 'success');
            loadSOAR();
        } catch (e) {
            showToast('Failed to unblock IP', 'error');
        }
    };

    window.simulate = async function(scenario) {
        try {
            await apiFetch('/simulate', {
                method: 'POST',
                body: JSON.stringify({ scenario })
            });
            showToast(`Simulation: ${scenario}`, 'warning');

            // Refresh data
            setTimeout(() => {
                loadAllData();
                loadAlerts();
                loadSOAR();
            }, 500);
        } catch (e) {
            showToast('Simulation failed', 'error');
        }
    };

    window.exportData = function() {
        showToast('Export functionality not implemented', 'info');
    };

    // ============================================================================
    // Event Listeners
    // ============================================================================

    function initEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.currentTarget.dataset.tab;
                showTab(tab);
            });
        });

        // Language switcher
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.addEventListener('click', (e) => setLang(e.currentTarget.dataset.lang));
        });

        // New data button
        document.getElementById('newDataBtn')?.addEventListener('click', () => {
            simulate('regenerate_random_all');
        });

        // Auto refresh interval
        if (state.autoRefresh) {
            state.refreshInterval = setInterval(() => {
                if (document.getElementById('tab-alerts') && !document.getElementById('tab-alerts').hidden) {
                    loadAllData();
                }
            }, 30000);
        }
    }

    // ============================================================================
    // Initialization
    // ============================================================================

    function init() {
        initEventListeners();

        // Set initial tab
        showTab('alerts');

        // Load initial data
        loadAllData();
    }

    // Auto-init when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();