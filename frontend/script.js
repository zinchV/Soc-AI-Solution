// ========================================
// SOC AI Command Center - JavaScript
// ========================================

const API_BASE = 'http://localhost:8080/api/v1';

// State
let alerts = [];
let incidents = [];
let currentView = 'dashboard';

// ========================================
// Initialization
// ========================================

// ========================= TRAINING MODE FUNCTIONS =========================

// Check if training mode is enabled
function isTrainingMode() {
    const toggle = document.getElementById('training-mode-toggle');
    return toggle ?  toggle.checked : false;
}

// Toggle training content visibility
function toggleTrainingContent(button) {
    const content = button.nextElementSibling;
    
    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        button.innerHTML = '<span>📖</span> Show Detailed Analysis <span>▼</span>';
    } else {
        content.classList.add('expanded');
        button.innerHTML = '<span>📖</span> Hide Detailed Analysis <span>▲</span>';
    }
}

// Quiz answer checker
function checkQuizAnswer(element, selectedIndex, correctIndex) {
    const options = element.parentElement.querySelectorAll('.quiz-option');
    
    // Disable further clicks
    options.forEach(opt => {
        opt.style.pointerEvents = 'none';
    });
    
    // Mark correct and incorrect
    options. forEach((opt, idx) => {
        if (idx === correctIndex) {
            opt.classList.add('correct');
        } else if (idx === selectedIndex && selectedIndex !== correctIndex) {
            opt.classList.add('incorrect');
        }
    });
    
    // Show notification
    if (selectedIndex === correctIndex) {
        showNotification('🎉 Correct! Great job!', 'success');
    } else {
        showNotification('❌ Not quite.  Review the explanation above.', 'error');
    }
}

// Generate training HTML for an incident
function generateTrainingHTML(training) {
    if (!training) return '';
    
    return `
        <div class="training-section">
            <div class="training-section-header">
                <span>🎓</span>
                <h4>Training Explanation</h4>
            </div>
            
            <button class="training-toggle-btn" onclick="toggleTrainingContent(this)">
                <span>📖</span> Show Detailed Analysis <span>▼</span>
            </button>
            
            <div class="training-content">
                <!-- Correlation Reasoning -->
                <div class="reasoning-block">
                    <h5>🔗 Why These Alerts Were Grouped</h5>
                    <p>${training.correlation_reasoning || 'No explanation available.'}</p>
                </div>
                
                <!-- Severity Reasoning -->
                <div class="reasoning-block">
                    <h5>⚠️ Why This Severity Level</h5>
                    <p>${training.severity_reasoning || 'No explanation available.'}</p>
                </div>
                
                <!-- MITRE ATT&CK Mapping -->
                <div class="reasoning-block">
                    <h5>🎯 MITRE ATT&CK Mapping</h5>
                    <div class="mitre-tags">
                        ${(training.mitre_mapping || []).map(m => `
                            <span class="mitre-tag" title="${m.explanation || ''}">
                                ${m. technique_id}:  ${m.technique_name}
                                <span class="tactic">(${m.tactic})</span>
                            </span>
                        `).join('')}
                    </div>
                </div>
                
                <!-- Actions Reasoning -->
                <div class="reasoning-block">
                    <h5>🛠️ Why These Actions Are Recommended</h5>
                    <p>${training.recommended_actions_reasoning || 'No explanation available.'}</p>
                </div>
                
                <!-- Learning Points -->
                <div class="reasoning-block">
                    <h5>💡 Key Learning Points</h5>
                    <ul class="learning-points">
                        ${(training. learning_points || []).map(point => `
                            <li>${point}</li>
                        `).join('')}
                    </ul>
                </div>
                
                <!-- Quiz -->
                ${training.quiz_question ? `
                    <div class="quiz-section">
                        <h5>📝 Knowledge Check</h5>
                        <p class="quiz-question">${training. quiz_question}</p>
                        <div class="quiz-options">
                            ${(training. quiz_options || []).map((option, index) => `
                                <div class="quiz-option" onclick="checkQuizAnswer(this, ${index}, ${training.quiz_answer})">
                                    <span class="option-letter">${String.fromCharCode(65 + index)}</span>
                                    <span>${option}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUpload();
    initChat();
    initButtons();
    checkHealth();
    loadDashboard();
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        if (currentView === 'dashboard') {
            loadDashboard();
        }
    }, 30000);
});

// ========================================
// Navigation
// ========================================

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
        });
    });
}

function switchView(viewName) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewName);
    });
    
    // Update views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.toggle('active', view.id === `${viewName}-view`);
    });
    
    // Update title
    const titles = {
        dashboard: { title: 'Dashboard', subtitle: 'Real-time security operations overview' },
        alerts: { title: 'Security Alerts', subtitle: 'All uploaded security alerts' },
        incidents: { title: 'Incidents', subtitle: 'AI-detected security incidents' },
        chat: { title: 'AI Assistant', subtitle: 'Ask questions about your security data' },
        'threat-center': { title: 'Threat Center', subtitle: 'Threat Intelligence & Proactive Hunting' },
        assets: { title: 'Asset Inventory', subtitle: 'Manage and monitor your assets' },
        'threat-intel': { title: 'Threat Intelligence', subtitle: 'CISA KEV & Detection Rules' },
        'threat-hunting': { title: 'Threat Hunting', subtitle: 'Proactive Hunting & Response Actions' },
        'investigations': { title: 'Investigations', subtitle: 'Hunt escalations requiring investigation' },
        'vmg': { title: 'Vulnerability Management', subtitle: 'AI-Powered Risk Prioritization & Remediation' }
    };
    
    const titleInfo = titles[viewName] || { title: viewName, subtitle: '' };
    document.getElementById('page-title').textContent = titleInfo.title;
    document.getElementById('page-subtitle').textContent = titleInfo.subtitle;
    
    currentView = viewName;
    
    // Load view data
    if (viewName === 'alerts') loadAlerts();
    if (viewName === 'incidents') loadIncidents();
    if (viewName === 'investigations') loadInvestigations();
    if (viewName === 'threat-center') {
        // Legacy - redirect to threat-intel
        switchView('threat-intel');
        return;
    }
    if (viewName === 'threat-intel') {
        loadThreatIntel();
        loadThreatIntelPendingRules();
        loadThreatIntelApprovedRules();
    }
    if (viewName === 'threat-hunting') {
        loadPendingHunts();
        loadPendingActions();
        loadHuntResults();
    }
    if (viewName === 'assets') loadAssets();
    if (viewName === 'vmg') loadVMGDashboard();
}

// ========================================
// Health Check
// ========================================

async function checkHealth() {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.connection-status span');
    const apiStatus = document.querySelector('.api-status span');
    
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        statusDot.classList.remove('error');
        statusDot.classList.add('connected');
        statusText.textContent = 'Backend Connected';
        
        if (data.gemini === 'configured') {
            apiStatus.textContent = 'Gemini: Configured';
            apiStatus.style.color = '#10b981';
        } else {
            apiStatus.textContent = 'Gemini: Not Configured';
            apiStatus.style.color = '#f59e0b';
        }
    } catch (error) {
        statusDot.classList.remove('connected');
        statusDot.classList.add('error');
        statusText.textContent = 'Backend Disconnected';
        apiStatus.textContent = 'Gemini: Unknown';
    }
}

// ========================================
// Dashboard
// ========================================

async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/metrics/dashboard`);
        const data = await response.json();
        
        if (data.success) {
            const metrics = data.data;
            
            // Animate stats
            animateValue('stat-alerts', metrics.total_alerts);
            animateValue('stat-incidents', metrics.active_incidents);
            animateValue('stat-time', metrics.time_saved_hours);
            animateValue('stat-actions', metrics.actions_executed);
            animateValue('stat-reduction', metrics.reduction_percentage);
            
            // Update badges
            document.getElementById('alerts-badge').textContent = metrics.total_alerts;
            document.getElementById('incidents-badge').textContent = metrics.active_incidents;
            
            // Update severity bars
            const total = metrics.total_alerts || 1;
            const sev = metrics.severity_breakdown || {};
            
            updateSeverityBar('critical', sev.Critical || 0, total);
            updateSeverityBar('high', sev.High || 0, total);
            updateSeverityBar('medium', sev.Medium || 0, total);
            updateSeverityBar('low', sev.Low || 0, total);
        }
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

function animateValue(elementId, endValue) {
    const el = document.getElementById(elementId);
    const startValue = parseInt(el.textContent) || 0;
    const duration = 500;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const current = Math.floor(startValue + (endValue - startValue) * progress);
        el.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

function updateSeverityBar(severity, count, total) {
    const percentage = (count / total) * 100;
    document.getElementById(`sev-${severity}`).style.width = `${percentage}%`;
    document.getElementById(`sev-${severity}-count`).textContent = count;
}

// ========================================
// File Upload
// ========================================

function initUpload() {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    
    uploadZone.addEventListener('click', () => fileInput.click());
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
    });
    
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleFile(file);
    });
}

async function handleFile(file) {
    if (!file.name.endsWith('.csv')) {
        showToast('Please upload a CSV file', 'error');
        return;
    }
    
    const uploadZone = document.getElementById('upload-zone');
    const uploadProgress = document.getElementById('upload-progress');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    
    uploadZone.style.display = 'none';
    uploadProgress.style.display = 'block';
    progressText.textContent = 'Reading file...';
    progressFill.style.width = '10%';
    
    try {
        const text = await file.text();
        progressText.textContent = 'Parsing CSV...';
        progressFill.style.width = '30%';
        
        const alerts = parseCSV(text);
        
        if (alerts.length === 0) {
            throw new Error('No valid alerts found in CSV');
        }
        
        progressText.textContent = `Uploading ${alerts.length} alerts...`;
        progressFill.style.width = '50%';
        
        const response = await fetch(`${API_BASE}/alerts/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alerts })
        });
        
        const data = await response.json();
        
        progressText.textContent = 'Indexing in ChromaDB...';
        progressFill.style.width = '80%';
        
        await new Promise(r => setTimeout(r, 500));
        
        progressFill.style.width = '100%';
        progressText.textContent = 'Upload complete!';
        
        showToast(`Successfully uploaded ${data.data.count} alerts`, 'success');
        
        setTimeout(() => {
            uploadZone.style.display = 'flex';
            uploadProgress.style.display = 'none';
            progressFill.style.width = '0%';
            loadDashboard();
        }, 1000);
        
    } catch (error) {
        showToast(`Upload failed: ${error.message}`, 'error');
        uploadZone.style.display = 'flex';
        uploadProgress.style.display = 'none';
    }
}

function parseCSV(text) {
    const lines = text.trim().split('\n');
    if (lines.length < 2) return [];
    
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
    const alerts = [];
    
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        if (values.length >= headers.length) {
            const alert = {};
            headers.forEach((header, index) => {
                alert[header] = values[index];
            });
            alerts.push(alert);
        }
    }
    
    return alerts;
}

function parseCSVLine(line) {
    const values = [];
    let current = '';
    let inQuotes = false;
    
    for (let char of line) {
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            values.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    values.push(current.trim());
    
    return values;
}

// ========================================
// Demo Mode
// ========================================

async function loadDemo() {
    showLoading('Loading demo data...');
    
    try {
        await fetch(`${API_BASE}/data/reset`, { method: 'DELETE' });    
        // Fetch sample alerts
        const csvResponse = await fetch(`${API_BASE}/sample_alerts.csv`);
        const csvText = await csvResponse.text();
        
        const alerts = parseCSV(csvText);
        
        if (alerts.length === 0) {
            throw new Error('No demo data found');
        }
        
        // Upload alerts
        document.getElementById('loading-text').textContent = `Uploading ${alerts.length} alerts...`;
        
        const uploadResponse = await fetch(`${API_BASE}/alerts/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alerts })
        });
        
        await uploadResponse.json();
        
        // Run analysis
        document.getElementById('loading-text').textContent = 'Running AI analysis with Gemini...';
        
        const analyzeResponse = await fetch(`${API_BASE}/agent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: "Analyze all alerts and create security incidents. Group related alerts, assess severity, and recommend response actions."
            })
        });
        
        const analyzeData = await analyzeResponse.json();
        
        hideLoading();
        
        if (!analyzeData.success) {
            showToast(`Demo loaded but AI analysis failed: ${analyzeData.error}`, 'warning');
        } else {
            showToast(`Demo loaded! AI analysis complete.`, 'success');
        }
        
        loadDashboard();
        
    } catch (error) {
        
        hideLoading();
        showToast(`Failed to load demo: ${error.message}`, 'error');
    }
}

// ========================================
// Alerts
// ========================================

async function loadAlerts() {
    const tbody = document.getElementById('alerts-table-body');
    
    try {
        const response = await fetch(`${API_BASE}/alerts?limit=100`);
        const data = await response.json();
        
        if (data.success && data.data.alerts.length > 0) {
            alerts = data.data.alerts;
            renderAlerts(alerts);
        } else {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No alerts loaded. Upload a CSV or load demo data.</td></tr>';
        }
    } catch (error) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="6">Failed to load alerts. Check backend connection.</td></tr>';
    }
}

function renderAlerts(alertsToRender) {
    const tbody = document.getElementById('alerts-table-body');
    
    tbody.innerHTML = alertsToRender.map(alert => `
        <tr>
            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${formatTimestamp(alert.timestamp)}</td>
            <td><span class="severity-tag ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
            <td>${alert.event_type || 'Unknown'}</td>
            <td style="font-family: var(--font-mono);">${alert.source_ip || '-'}</td>
            <td>${alert.user || '-'}</td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${alert.description}</td>
        </tr>
    `).join('');
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    const date = new Date(ts);
    return date.toLocaleString();
}

// ========================================
// AI Analysis
// ========================================

// ========================================
// AI Analysis
// ========================================

async function runAnalysis() {
    const trainingMode = isTrainingMode();

    console.log('=== DEBUG ===');
    console.log('Training Mode:', trainingMode);
    
    showLoading('Analyzing alerts with Gemini AI...');
    
    try {
        // Use the agent endpoint with appropriate message based on mode
        const message = trainingMode 
            ? "Analyze all alerts and create security incidents with detailed training explanations. Include MITRE ATT&CK mappings, correlation reasoning, severity explanations, and quiz questions for each incident."
            : "Analyze all alerts and create security incidents. Group related alerts, assess severity, and recommend response actions.";

        const response = await fetch(`${API_BASE}/agent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        const data = await response.json();
        
        console.log('API Response:', data);
        
        hideLoading();

        // Check if successful
        if (!data.success) {
            showToast(`Analysis failed: ${data.error || 'Unknown error'}`, 'error');
            return;
        }

        // Agent returns a response string - we need to reload incidents from the DB
        const message_result = trainingMode
            ? `🎓 Training analysis complete! Check incidents for detailed explanations.`
            : `AI analysis complete! Check incidents panel for results.`;
        showToast(message_result, 'success');
        
        // Reload incidents from database
        await loadIncidents();
        switchView('incidents');
        loadDashboard();
        
    } catch (error) {
        hideLoading();
        console.error('Analysis error:', error);
        showToast(`Analysis failed: ${error.message}`, 'error');
    }
}
// ========================================
// Incidents
// ========================================

async function loadIncidents() {
    try {
        const response = await fetch(`${API_BASE}/incidents`);
        const data = await response.json();
        
        if (data.success && data.data.incidents.length > 0) {
            // Filter OUT hunt escalations - they go to Investigations page
            const alertIncidents = data.data.incidents.filter(inc => 
                !inc.title.startsWith('[Hunt Escalation]')
            );
            
            // Update badge with only alert-based incidents
            const badge = document.getElementById('incidents-badge');
            if (badge) badge.textContent = alertIncidents.length;
            
            incidents = alertIncidents;
            
            if (alertIncidents.length > 0) {
                renderIncidents(alertIncidents);
            } else {
                document.getElementById('incidents-grid').innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <h3>No Incidents Yet</h3>
                        <p>Upload alerts and run AI analysis to detect security incidents</p>
                    </div>
                `;
            }
        } else {
            document.getElementById('incidents-grid').innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    <h3>No Incidents Yet</h3>
                    <p>Upload alerts and run AI analysis to detect security incidents</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Failed to load incidents:', error);
    }
}

function renderIncidents(incidentsToRender) {

    console.log('=== RENDER DEBUG ===');
    console.log('Number of incidents:', incidentsToRender.length);
    console.log('First incident:', incidentsToRender[0]);
    console.log('Has training? ', !!incidentsToRender[0]?.training);
    const grid = document.getElementById('incidents-grid');
    
    grid.innerHTML = incidentsToRender.map(incident => `
        <div class="incident-card ${incident.severity.toLowerCase()}" data-id="${incident.id}">
            <div class="incident-header">
                <div>
                    <h4 class="incident-title">
                        ${incident.title}
                        ${incident.training ? '<span class="training-mode-badge">🎓 Training</span>' : ''}
                    </h4>
                    <div class="incident-meta">
                        <span class="severity-tag ${incident.severity.toLowerCase()}">${incident.severity}</span>
                        <span>📊 ${incident.alert_count || incident.alert_ids?.length || 0} alerts</span>
                        <span>🎯 ${Math.round((incident.confidence || 0) * 100)}% confidence</span>
                        ${incident.attack_stage ? `<span>⚔️ ${incident.attack_stage}</span>` : ''}
                    </div>
                </div>
            </div>
            <div class="incident-body">
                <p class="incident-summary">${incident.summary}</p>
                
                <!-- Grouped Alerts Section -->
                ${renderGroupedAlerts(incident)}
                
                ${incident.indicators ? `
                    <div class="incident-indicators">
                        ${incident.indicators.slice(0, 5).map(ind => `<span class="indicator-tag">${ind}</span>`).join('')}
                    </div>
                ` : ''}
                <div class="incident-actions">
                    ${(incident.actions || incident.recommended_actions || []).slice(0, 3).map((action, idx) => `
                        <div class="action-item">
                            <div class="action-info">
                                <div class="action-title">${typeof action === 'string' ? action : action.title}</div>
                                <div class="action-urgency ${(typeof action === 'object' && action.urgency || 'soon').toLowerCase()}">${typeof action === 'object' ? action.urgency || 'Soon' : 'Soon'}</div>
                            </div>
                            <button class="action-execute-btn ${typeof action === 'object' && action.executed ? 'executed' : ''}" 
                                    onclick="executeAction(${typeof action === 'object' ? action.id : idx}, this)"
                                    ${typeof action === 'object' && action.executed ? 'disabled' : ''}>
                                ${typeof action === 'object' && action.executed ? '✓ Done' : 'Execute'}
                            </button>
                        </div>
                    `).join('')}
                </div>
                
                <!-- Training Section -->
                ${incident.training ? generateTrainingHTML(incident.training) : ''}
                
                <div class="timeline-panel" id="timeline-${incident.id}">
                    <div class="timeline" id="timeline-content-${incident.id}">
                        <!-- Timeline will be loaded here -->
                    </div>
                </div>
            </div>
            <div class="incident-footer">
                <div class="incident-status">
                    <select class="status-select" onchange="updateIncidentStatus(${incident.id}, this.value)">
                        <option value="active" ${incident.status === 'active' ? 'selected' : ''}>Active</option>
                        <option value="investigating" ${incident.status === 'investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="resolved" ${incident.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                    </select>
                    <input type="text" class="assign-input" placeholder="Assign to..." 
                           value="${incident.assigned_to || ''}"
                           onchange="updateIncidentAssignment(${incident.id}, this.value)">
                </div>
                <button class="view-timeline-btn" onclick="toggleTimeline(${incident.id})">View Timeline</button>
            </div>
        </div>
    `).join('');
}

// Render grouped alerts for an incident
function renderGroupedAlerts(incident) {
    const alertIds = incident.alert_ids || [];
    if (alertIds.length === 0) return '';
    
    return `
        <div class="grouped-alerts-section">
            <button class="grouped-alerts-toggle" onclick="toggleGroupedAlerts(this, ${incident.id})">
                <span>🔗</span> View Grouped Alerts (${alertIds.length}) <span class="toggle-arrow">▼</span>
            </button>
            <div class="grouped-alerts-content" id="grouped-alerts-${incident.id}">
                <div class="loading-alerts">Loading alert details...</div>
            </div>
        </div>
    `;
}

// Toggle grouped alerts visibility and load data
async function toggleGroupedAlerts(button, incidentId) {
    const content = button.nextElementSibling;
    const arrow = button.querySelector('.toggle-arrow');
    
    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        arrow.textContent = '▼';
    } else {
        content.classList.add('expanded');
        arrow.textContent = '▲';
        
        // Load alert details if not already loaded
        if (content.querySelector('.loading-alerts')) {
            await loadGroupedAlertDetails(incidentId);
        }
    }
}

// Fetch and display alert details for an incident
async function loadGroupedAlertDetails(incidentId) {
    const container = document.getElementById(`grouped-alerts-${incidentId}`);
    
    try {
        // Fetch incident details which includes full alert info
        const response = await fetch(`${API_BASE}/incidents/${incidentId}`);
        const data = await response.json();
        
        if (data.success && data.data.alerts) {
            const alertsHtml = data.data.alerts.map(alert => `
                <div class="grouped-alert-row ${(alert.severity || 'medium').toLowerCase()}">
                    <div class="alert-id">#${alert.id}</div>
                    <div class="alert-severity">
                        <span class="severity-badge ${(alert.severity || 'medium').toLowerCase()}">${alert.severity || 'Unknown'}</span>
                    </div>
                    <div class="alert-source">${alert.source_ip || '-'}</div>
                    <div class="alert-type">${alert.event_type || '-'}</div>
                    <div class="alert-desc" title="${alert.description || ''}">${alert.description || 'No description'}</div>
                    <div class="alert-time">${formatAlertTime(alert.timestamp)}</div>
                </div>
            `).join('');
            
            container.innerHTML = `
                <div class="grouped-alerts-header">
                    <div>ID</div>
                    <div>Severity</div>
                    <div>Source IP</div>
                    <div>Event Type</div>
                    <div>Description</div>
                    <div>Time</div>
                </div>
                <div class="grouped-alerts-body">
                    ${alertsHtml}
                </div>
            `;
        } else {
            container.innerHTML = '<div class="no-alerts">No alert details available</div>';
        }
    } catch (error) {
        console.error('Error loading alert details:', error);
        container.innerHTML = '<div class="error-alerts">Failed to load alert details</div>';
    }
}

// Format timestamp for alert display
function formatAlertTime(timestamp) {
    if (!timestamp) return '-';
    try {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
        return timestamp;
    }
}

async function executeAction(actionId, button) {
    if (button.classList.contains('executed')) return;
    
    button.textContent = '...';
    button.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/agent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: `Execute action ${actionId}`
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            button.textContent = '✓ Done';
            button.classList.add('executed');
            showToast('Action executed successfully', 'success');
            loadDashboard();
        } else {
            throw new Error(data.error || 'Execution failed');
        }
    } catch (error) {
        button.textContent = 'Execute';
        button.disabled = false;
        showToast('Failed to execute action', 'error');
    }
}

async function updateIncidentStatus(incidentId, status) {
    try {
        await fetch(`${API_BASE}/incidents/${incidentId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        showToast(`Incident status updated to ${status}`, 'info');
        loadDashboard();
    } catch (error) {
        showToast('Failed to update status', 'error');
    }
}

async function updateIncidentAssignment(incidentId, assignedTo) {
    try {
        await fetch(`${API_BASE}/incidents/${incidentId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ assigned_to: assignedTo })
        });
        showToast(`Incident assigned to ${assignedTo || 'nobody'}`, 'info');
    } catch (error) {
        showToast('Failed to update assignment', 'error');
    }
}

async function toggleTimeline(incidentId) {
    const panel = document.getElementById(`timeline-${incidentId}`);
    const content = document.getElementById(`timeline-content-${incidentId}`);
    
    if (panel.classList.contains('active')) {
        panel.classList.remove('active');
        return;
    }
    
    // Load timeline data
    try {
        const response = await fetch(`${API_BASE}/incidents/${incidentId}`);
        const data = await response.json();
        
        if (data.success && data.data.alerts) {
            content.innerHTML = data.data.alerts.map(alert => `
                <div class="timeline-item ${alert.severity.toLowerCase()}">
                    <div class="timeline-time">${formatTimestamp(alert.timestamp)}</div>
                    <div class="timeline-content">
                        <strong>${alert.event_type}</strong> - ${alert.description}
                    </div>
                </div>
            `).join('');
        }
        
        panel.classList.add('active');
    } catch (error) {
        showToast('Failed to load timeline', 'error');
    }
}

// ========================================
// Chat
// ========================================

function initChat() {
    const input = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    const sampleBtns = document.querySelectorAll('.sample-btn');
    
    sendBtn.addEventListener('click', sendMessage);
    
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
    
    sampleBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            input.value = btn.dataset.question;
            sendMessage();
        });
    });
}

async function sendMessage() {
    const input = document.getElementById('chat-input');
    const messagesContainer = document.getElementById('chat-messages');
    const question = input.value.trim();
    
    if (!question) return;
    
    // Hide welcome
    const welcome = messagesContainer.querySelector('.chat-welcome');
    if (welcome) welcome.style.display = 'none';
    
    // Add user message
    addChatMessage(question, 'user');
    input.value = '';
    
    // Add loading message
    const loadingId = 'loading-' + Date.now();
    addChatMessage('Thinking...', 'ai', loadingId);
    
    try {
        const response = await fetch(`${API_BASE}/agent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: question })
        });
        
        const data = await response.json();
        
        // Remove loading message
        const loadingEl = document.getElementById(loadingId);
        if (loadingEl) loadingEl.remove();
        
        if (data.success) {
            addChatMessage(data.data.response, 'ai');
        } else {
            addChatMessage(`Sorry, I encountered an error: ${data.error}`, 'ai');
        }
        
    } catch (error) {
        const loadingEl = document.getElementById(loadingId);
        if (loadingEl) loadingEl.remove();
        addChatMessage('Failed to connect to the backend. Please check your connection.', 'ai');
    }
}

function addChatMessage(text, sender, id = null, sources = null) {
    const container = document.getElementById('chat-messages');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${sender}`;
    if (id) messageDiv.id = id;
    
    const avatarSvg = sender === 'ai' 
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
    
    let sourcesHtml = '';
    if (sources && sources.length > 0) {
        sourcesHtml = `<div class="message-sources">📎 Based on ${sources.length} alert${sources.length > 1 ? 's' : ''}</div>`;
    }
    
    messageDiv.innerHTML = `
        <div class="message-avatar">${avatarSvg}</div>
        <div class="message-content">
            <div class="message-text">${text}</div>
            ${sourcesHtml}
        </div>
    `;
    
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

// ========================================
// Buttons
// ========================================

function initButtons() {
    document.getElementById('demo-btn').addEventListener('click', loadDemo);
    document.getElementById('analyze-btn').addEventListener('click', runAnalysis);
    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadDashboard();
        loadAlerts();
        loadIncidents();
        checkHealth();
        showToast('Data refreshed', 'info');
    });
    document.getElementById('reset-btn').addEventListener('click', resetData);
    
    // Filters
    document.getElementById('severity-filter').addEventListener('change', filterAlerts);
    document.getElementById('type-filter').addEventListener('change', filterAlerts);
}

function filterAlerts() {
    const severity = document.getElementById('severity-filter').value;
    const type = document.getElementById('type-filter').value;
    
    let filtered = alerts;
    
    if (severity) {
        filtered = filtered.filter(a => a.severity === severity);
    }
    if (type) {
        filtered = filtered.filter(a => a.event_type === type);
    }
    
    renderAlerts(filtered);
}

async function resetData() {
    if (!confirm('Are you sure you want to reset all data? This cannot be undone.')) return;
    
    showLoading('Resetting data...');
    
    try {
        await fetch(`${API_BASE}/data/reset`, { method: 'DELETE' });
        hideLoading();
        showToast('All data has been reset', 'success');
        loadDashboard();
        loadAlerts();
        loadIncidents();
    } catch (error) {
        hideLoading();
        showToast('Failed to reset data', 'error');
    }
}

// ========================================
// UI Helpers
// ========================================

function showLoading(text = 'Loading...') {
    document.getElementById('loading-text').textContent = text;
    document.getElementById('loading-overlay').classList.add('active');
}

function hideLoading() {
    document.getElementById('loading-overlay').classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    
    const icons = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
        </button>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}


// ==================== PROACTIVE FUNCTIONS ====================

// ==================== PROACTIVE SOC FUNCTIONS ====================
// Add these to the END of your script.js file
// Replace any existing proactive functions with these

// Helper functions that might be missing
function showSuccess(message) {
    showToast(message, 'success');
    hideLoading();
}

function showError(message) {
    showToast(message, 'error');
    hideLoading();
}

function showNotification(message, type = 'info') {
    showToast(message, type);
}

function updateProactiveBadge() {
    const actionsCount = parseInt(document.getElementById('pending-actions-count')?.textContent || '0');
    const badge = document.getElementById('proactive-badge');
    if (badge) {
        badge.textContent = actionsCount;
    }
}

// ==================== REFRESH ALL ====================
async function refreshAll() {
    showLoading('Refreshing all data...');
    try {
        await loadThreatIntel();
        await loadPendingActions();
        await loadPendingHunts();
        await loadHuntResults();
        showSuccess('All data refreshed');
    } catch (error) {
        showError('Failed to refresh: ' + error.message);
    }
}

// ==================== PENDING ACTIONS ====================
// Old action functions kept for backwards compatibility

async function approveAction(actionId) {
    const analyst = 'demo_analyst';
    try {
        await fetch(`${API_BASE}/actions/${actionId}/approve?analyst=${analyst}`, { method: 'POST' });
        showSuccess('Action approved');
        await loadPendingActions();
    } catch (error) {
        showError('Approval failed: ' + error.message);
    }
}

async function executeAction(actionId) {
    showLoading('Executing action...');
    try {
        await fetch(`${API_BASE}/actions/${actionId}/execute`, { method: 'POST' });
        showSuccess('Action executed successfully');
        await loadPendingActions();
    } catch (error) {
        showError('Execution failed: ' + error.message);
    }
}

async function rejectAction(actionId) {
    const reason = prompt('Reason for rejection (optional):') || 'Rejected by analyst';
    try {
        await fetch(`${API_BASE}/actions/${actionId}/reject?reason=${encodeURIComponent(reason)}`, { method: 'POST' });
        showSuccess('Action rejected');
        await loadPendingActions();
    } catch (error) {
        showError('Rejection failed: ' + error.message);
    }
}

async function createBlockList(resultId) {
    showLoading('Creating block list action...');
    try {
        await fetch(`${API_BASE}/hunts/results/${resultId}/create-block`, { method: 'POST' });
        showSuccess('Block list action created. Check Pending Actions.');
        await loadPendingActions();
    } catch (error) {
        showError('Failed to create block list: ' + error.message);
    }
}

async function approveHunt(huntId) {
    const analyst = 'demo_analyst';
    showLoading('Approving and executing hunt...');
    try {
        await fetch(`${API_BASE}/hunts/${huntId}/approve?analyst=${analyst}`, { method: 'POST' });
        await fetch(`${API_BASE}/hunts/${huntId}/execute`, { method: 'POST' });
        showSuccess('Hunt executed');
        await loadPendingHunts();
        await loadHuntResults();
    } catch (error) {
        showError('Hunt execution failed: ' + error.message);
    }
}

async function rejectHunt(huntId) {
    const reason = prompt('Reason for rejection (optional):') || 'Not relevant';
    try {
        await fetch(`${API_BASE}/hunts/${huntId}/reject?reason=${encodeURIComponent(reason)}`, { method: 'POST' });
        showSuccess('Hunt rejected');
        await loadPendingHunts();
    } catch (error) {
        showError('Rejection failed: ' + error.message);
    }
}

// Escape function for HTML attributes
function escape(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/'/g, '&#39;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

console.log('SOC AI functions loaded');

// ==================== ASSETS VIEW FUNCTIONS ====================

let allAssets = [];

async function loadAssets() {
    try {
        const response = await fetch(`${API_BASE}/assets`);
        const data = await response.json();
        
        allAssets = data.assets || [];
        updateAssetStats();
        renderAssetsTable(allAssets);
    } catch (error) {
        console.error('Failed to load assets:', error);
        showError('Failed to load assets');
    }
}

function updateAssetStats() {
    const stats = {
        total: allAssets.length,
        critical: allAssets.filter(a => a.criticality === 'critical').length,
        high: allAssets.filter(a => a.criticality === 'high').length,
        medium: allAssets.filter(a => a.criticality === 'medium').length
    };
    
    document.getElementById('total-assets').textContent = stats.total;
    document.getElementById('critical-assets').textContent = stats.critical;
    document.getElementById('high-assets').textContent = stats.high;
    document.getElementById('medium-assets').textContent = stats.medium;
    
    // Update type pills
    document.getElementById('pill-all-count').textContent = stats.total;
    document.getElementById('pill-server-count').textContent = allAssets.filter(a => a.asset_type === 'server').length;
    document.getElementById('pill-workstation-count').textContent = allAssets.filter(a => a.asset_type === 'workstation').length;
    document.getElementById('pill-network-count').textContent = allAssets.filter(a => a.asset_type === 'network').length;
    document.getElementById('pill-security-count').textContent = allAssets.filter(a => a.asset_type === 'security').length;
}

function renderAssetsTable(assets) {
    const tbody = document.getElementById('assets-table-body');
    
    if (!assets || assets.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No assets found</td></tr>';
        return;
    }
    
    tbody.innerHTML = assets.map(asset => `
        <tr>
            <td>
                <div class="asset-name">${asset.hostname}</div>
                <div class="asset-ip">${asset.ip_address}</div>
            </td>
            <td>
                <span class="criticality-badge ${asset.criticality}">${asset.criticality}</span>
            </td>
            <td>${asset.asset_type}</td>
            <td>${asset.os || 'N/A'}</td>
            <td>${asset.owner || 'N/A'}</td>
            <td>
                <div class="software-tags">
                    ${(asset.software || []).slice(0, 4).map(sw => `<span class="software-tag">${sw}</span>`).join('')}
                    ${asset.software && asset.software.length > 4 ? `<span class="software-tag">+${asset.software.length - 4}</span>` : ''}
                </div>
            </td>
            <td>
                <button class="btn btn-sm btn-outline" onclick="viewAssetDetails(${asset.id})">View</button>
            </td>
        </tr>
    `).join('');
}

function filterAssets() {
    const typeFilter = document.getElementById('asset-type-filter').value;
    const criticalityFilter = document.getElementById('asset-criticality-filter').value;
    const searchTerm = document.getElementById('asset-search').value.toLowerCase();
    
    let filtered = allAssets;
    
    if (typeFilter) {
        filtered = filtered.filter(a => a.asset_type === typeFilter);
    }
    
    if (criticalityFilter) {
        filtered = filtered.filter(a => a.criticality === criticalityFilter);
    }
    
    if (searchTerm) {
        filtered = filtered.filter(a => 
            a.hostname.toLowerCase().includes(searchTerm) ||
            a.ip_address.includes(searchTerm) ||
            (a.owner && a.owner.toLowerCase().includes(searchTerm))
        );
    }
    
    renderAssetsTable(filtered);
}

function filterByType(button, type) {
    // Update pills
    document.querySelectorAll('.type-pill').forEach(p => p.classList.remove('active'));
    button.classList.add('active');
    
    // Update filter and re-render
    document.getElementById('asset-type-filter').value = type;
    filterAssets();
}

function viewAssetDetails(assetId) {
    const asset = allAssets.find(a => a.id === assetId);
    if (!asset) return;
    
    showNotification(`Viewing: ${asset.hostname}`, 'info');
    // TODO: Implement asset detail modal
}

// ==================== THREAT CENTER FUNCTIONS ====================

let threatIntelData = [];
let deployedRules = new Set();

async function refreshThreatCenter() {
    showLoading('Refreshing Threat Center...');
    await Promise.all([
        fetchKEV(),
        loadPendingActions(),
        loadPendingHunts(),
        loadHuntResults(),
        loadDeployedRules()
    ]);
    hideLoading();
}

async function loadDeployedRules() {
    try {
        const response = await fetch(`${API_BASE}/rules?status=deployed`);
        const data = await response.json();
        deployedRules = new Set((data.rules || []).map(r => r.source_cve));
    } catch (error) {
        console.error('Failed to load deployed rules:', error);
    }
}

async function fetchKEV(forceFresh = false) {
    const message = forceFresh 
        ? 'Clearing old data and fetching fresh CISA KEV...'
        : 'Fetching CISA KEV data...';
    showLoading(message);
    try {
        const url = forceFresh 
            ? `${API_BASE}/threat-intel/refresh?force_fresh=true`
            : `${API_BASE}/threat-intel/refresh`;
        const response = await fetch(url, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            // Reload threat intel with exposure check
            await loadThreatIntel();
            const freshMsg = forceFresh ? ' (fresh start)' : '';
            showSuccess(`Loaded ${data.count || 0} vulnerabilities from CISA KEV${freshMsg}`);
        } else {
            showError('Failed to fetch KEV: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        showError('Failed to fetch KEV: ' + error.message);
    }
    hideLoading();
}

async function fetchKEVFresh() {
    if (confirm('This will clear all existing threat intel and rules, then fetch fresh data. Continue?')) {
        await fetchKEV(true);
    }
}

async function loadThreatIntel() {
    try {
        // Fetch KEVs with exposure check enabled - API now auto-filters acted-upon CVEs
        const response = await fetch(`${API_BASE}/threat-intel/kevs?check_exposure=true`);
        const data = await response.json();
        
        threatIntelData = data.kevs || [];
        renderThreatIntelList();
        
        // Update badge - only for threat-intel page
        const badge = document.getElementById('threat-intel-badge');
        if (badge) {
            badge.textContent = threatIntelData.length > 0 ? threatIntelData.length : '';
        }
    } catch (error) {
        console.error('Failed to load threat intel:', error);
    }
}

function renderThreatIntelList() {
    const container = document.getElementById('threat-intel-list');
    if (!container) return;
    
    if (!threatIntelData || threatIntelData.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>✅ All threat intel has been addressed!</p>
                <p class="empty-state-hint">Click "Fetch KEV" to load new CISA vulnerabilities, or check Detection Rules for your existing coverage.</p>
            </div>
        `;
        // Hide summary pane
        const summaryPane = document.getElementById('exposure-summary-pane');
        if (summaryPane) summaryPane.style.display = 'none';
        return;
    }
    
    // Sort: exposed + needs action first, stale second, then exposed + covered, then non-exposed
    const sorted = [...threatIntelData].sort((a, b) => {
        const needsAction = (c) => c.is_exposed && (!c.has_local_rule || c.local_rule_status === 'stale_deployed');
        const isStale = (c) => c.local_rule_status === 'stale_deployed';
        // Priority: exposed needs action (4) > stale (3) > exposed with rule (2) > not exposed (0)
        const scoreA = (a.is_exposed ? 2 : 0) + (needsAction(a) ? 2 : 0) + (isStale(a) ? 1 : 0);
        const scoreB = (b.is_exposed ? 2 : 0) + (needsAction(b) ? 2 : 0) + (isStale(b) ? 1 : 0);
        return scoreB - scoreA;
    });
    
    // Render summary pane
    renderExposureSummary();
    
    // Render CVE cards
    container.innerHTML = sorted.map(cve => {
        // Determine button state
        const isExposed = cve.is_exposed === true;
        const hasLocalRule = cve.has_local_rule === true;
        const isDeployed = cve.local_rule_status === 'deployed';
        const isStale = cve.local_rule_status === 'stale_deployed';
        
        // Button logic
        let createDisabled = !isExposed || (hasLocalRule && !isStale);
        let createButtonText = '+ Create Rule';
        let createButtonTitle = '';
        let createButtonClass = 'btn btn-sm btn-primary';
        let buttonAction = '';
        
        if (hasLocalRule) {
            if (isDeployed) {
                createButtonText = '✓ Deployed';
                createButtonTitle = 'Rule verified in Microsoft Sentinel';
                createButtonClass = 'btn btn-sm btn-success disabled';
            } else if (isStale) {
                createButtonText = '🔄 Redeploy';
                createButtonTitle = 'Rule not found in Sentinel — needs redeployment';
                createButtonClass = 'btn btn-sm btn-warning';
                createDisabled = false;
                buttonAction = `redeployRule(${cve.local_rule_id})`;
            } else {
                createButtonText = '✓ Rule Exists';
                createButtonTitle = `Rule exists (${cve.local_rule_status})`;
                createButtonClass = 'btn btn-sm btn-outline disabled';
            }
        } else if (!isExposed) {
            createButtonTitle = 'No assets exposed to this vulnerability';
            createButtonClass = 'btn btn-sm btn-primary disabled';
        }
        
        if (!buttonAction && !createDisabled) {
            buttonAction = `createRule('${cve.cve_id}')`;
        }
        
        // Exposure badge
        let exposureBadge = '';
        if (cve.is_exposed === true) {
            exposureBadge = `<span class="exposure-badge exposed">⚠️ ${cve.exposed_count} Asset${cve.exposed_count > 1 ? 's' : ''} Exposed</span>`;
        } else if (cve.is_exposed === false) {
            exposureBadge = `<span class="exposure-badge safe">✅ No Exposure</span>`;
        }
        
        // Coverage badge
        let coverageBadge = '';
        if (isDeployed) {
            coverageBadge = `<span class="coverage-badge covered">🛡️ SIEM Coverage</span>`;
        } else if (isStale) {
            coverageBadge = `<span class="coverage-badge stale">⚠️ Not in Sentinel</span>`;
        } else if (hasLocalRule) {
            coverageBadge = `<span class="coverage-badge pending">⏳ Rule ${cve.local_rule_status}</span>`;
        } else if (isExposed) {
            coverageBadge = `<span class="coverage-badge no-coverage">❌ No Coverage</span>`;
        }
        
        return `
            <div class="cve-card ${isDeployed ? 'has-rule' : ''} ${isStale ? 'is-stale' : ''} ${isExposed ? 'is-exposed' : ''}" 
                 id="cve-card-${cve.cve_id}" onclick="showCVEDetail('${cve.cve_id}')">
                <div class="cve-header">
                    <span class="cve-id">${cve.cve_id}</span>
                    <span class="cve-severity ${(cve.severity || 'critical').toLowerCase()}">${cve.severity || 'CRITICAL'}</span>
                </div>
                <div class="cve-product">${cve.vendor || 'Unknown'} - ${cve.product || 'Unknown'}</div>
                <div class="cve-description">${cve.description || 'No description available'}</div>
                
                <div class="cve-badges">
                    ${exposureBadge}
                    ${coverageBadge}
                </div>
                
                ${cve.due_date ? `<div class="cve-due-date">🚨 Due: ${new Date(cve.due_date).toLocaleDateString()}</div>` : ''}
                
                <div class="cve-actions" onclick="event.stopPropagation()">
                    <button class="btn btn-sm btn-outline" onclick="checkExposure('${cve.cve_id}', '${escape(cve.vendor || '')}', '${escape(cve.product || '')}')">
                        🔍 View Assets
                    </button>
                    <button class="${createButtonClass}" 
                            ${createDisabled ? 'disabled' : ''} 
                            title="${createButtonTitle}"
                            onclick="${buttonAction}">
                        ${createButtonText}
                    </button>
                </div>
            </div>
        `;
    }).join('');
}


function renderExposureSummary() {
    const summaryPane = document.getElementById('exposure-summary-pane');
    if (!summaryPane || !threatIntelData || threatIntelData.length === 0) return;
    
    // Calculate stats — only count as "covered" if truly verified in Sentinel
    const total = threatIntelData.length;
    const exposed = threatIntelData.filter(c => c.is_exposed === true);
    const covered = threatIntelData.filter(c => c.local_rule_status === 'deployed');
    const stale = exposed.filter(c => c.local_rule_status === 'stale_deployed');
    const needAction = exposed.filter(c => !c.has_local_rule || c.local_rule_status === 'stale_deployed');
    
    // Update stat values
    document.querySelector('#summary-total .summary-stat-value').textContent = total;
    document.querySelector('#summary-exposed .summary-stat-value').textContent = exposed.length;
    document.querySelector('#summary-covered .summary-stat-value').textContent = covered.length;
    document.querySelector('#summary-action .summary-stat-value').textContent = needAction.length;
    
    // Render exposed CVE quick list
    const listContainer = document.getElementById('exposed-cve-list');
    
    if (exposed.length === 0) {
        listContainer.innerHTML = '<p class="summary-safe-msg">✅ No assets are exposed to any fetched CVEs</p>';
    } else {
        listContainer.innerHTML = exposed.map(cve => {
            const isDeployed = cve.local_rule_status === 'deployed';
            const isStale = cve.local_rule_status === 'stale_deployed';
            const hasRule = cve.has_local_rule === true;
            const isPending = hasRule && !isDeployed && !isStale;
            
            let statusBadge = '';
            let actionButton = '';
            
            if (isDeployed) {
                statusBadge = '<span class="summary-status deployed">🛡️ Deployed</span>';
            } else if (isStale) {
                statusBadge = '<span class="summary-status stale">⚠️ Not in Sentinel</span>';
                actionButton = `<button class="btn btn-xs btn-warning" onclick="event.stopPropagation(); redeployRule(${cve.local_rule_id})">🔄 Redeploy</button>`;
            } else if (isPending) {
                statusBadge = `<span class="summary-status pending">⏳ ${cve.local_rule_status}</span>`;
                actionButton = `<button class="btn btn-xs btn-outline" onclick="event.stopPropagation(); viewRule(${cve.local_rule_id})">View Rule</button>`;
            } else {
                statusBadge = '<span class="summary-status no-rule">❌ No Rule</span>';
                actionButton = `<button class="btn btn-xs btn-primary" onclick="event.stopPropagation(); createRule('${cve.cve_id}')">+ Create Rule</button>`;
            }
            
            return `
                <div class="exposed-cve-item ${isDeployed ? 'covered' : isStale ? 'stale' : isPending ? 'pending' : 'needs-action'}" 
                     onclick="scrollToCVE('${cve.cve_id}')">
                    <div class="exposed-cve-info">
                        <span class="exposed-cve-id">${cve.cve_id}</span>
                        <span class="exposed-cve-product">${cve.vendor} - ${cve.product}</span>
                        <span class="exposed-cve-count">⚠️ ${cve.exposed_count} asset${cve.exposed_count > 1 ? 's' : ''}</span>
                    </div>
                    <div class="exposed-cve-actions">
                        ${statusBadge}
                        ${actionButton}
                    </div>
                </div>
            `;
        }).join('');
    }
    
    // Show the pane
    summaryPane.style.display = 'block';
}


function scrollToCVE(cveId) {
    const card = document.getElementById(`cve-card-${cveId}`);
    if (card) {
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        // Flash highlight
        card.classList.add('highlight-flash');
        setTimeout(() => card.classList.remove('highlight-flash'), 2000);
    }
}

function showCVEDetail(cveId) {
    const cve = threatIntelData.find(c => c.cve_id === cveId);
    if (!cve) return;
    
    const modal = document.getElementById('cve-modal');
    const title = document.getElementById('cve-modal-title');
    const body = document.getElementById('cve-modal-body');
    
    // Determine states
    const isExposed = cve.is_exposed === true;
    const hasLocalRule = cve.has_local_rule === true;
    const isDeployed = cve.local_rule_status === 'deployed';
    const createDisabled = !isExposed || hasLocalRule;
    
    title.textContent = cve.cve_id;
    body.innerHTML = `
        <div class="cve-detail-section">
            <h4>Product</h4>
            <p>${cve.vendor || 'Unknown'} - ${cve.product || 'Unknown'}</p>
        </div>
        ${cve.vulnerability_name ? `
        <div class="cve-detail-section">
            <h4>Vulnerability Name</h4>
            <p>${cve.vulnerability_name}</p>
        </div>` : ''}
        <div class="cve-detail-section">
            <h4>Description</h4>
            <p>${cve.description || 'No description available'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Severity</h4>
            <span class="cve-severity ${(cve.severity || 'critical').toLowerCase()}">${cve.severity || 'CRITICAL'}</span>
        </div>
        
        <!-- Exposure Status -->
        <div class="cve-detail-section">
            <h4>Asset Exposure</h4>
            ${isExposed ? `
                <div class="exposure-summary-inline">
                    <span class="exposure-badge exposed">⚠️ ${cve.exposed_count} Asset${cve.exposed_count > 1 ? 's' : ''} at Risk</span>
                    ${cve.critical_count > 0 ? `<span class="stat-mini critical">${cve.critical_count} Critical</span>` : ''}
                    ${cve.high_count > 0 ? `<span class="stat-mini high">${cve.high_count} High</span>` : ''}
                </div>
                <div class="exposed-assets-preview">
                    ${(cve.exposed_assets || []).slice(0, 3).map(a => `
                        <div class="asset-mini">${a.hostname} (${a.ip})</div>
                    `).join('')}
                    ${cve.exposed_count > 3 ? `<div class="asset-mini more">+${cve.exposed_count - 3} more...</div>` : ''}
                </div>
            ` : `
                <span class="exposure-badge safe">✅ No assets exposed to this vulnerability</span>
            `}
        </div>
        
        <!-- Coverage Status -->
        <div class="cve-detail-section">
            <h4>SIEM Coverage</h4>
            ${isDeployed ? `
                <span class="coverage-badge covered">🛡️ Rule Deployed to Sentinel</span>
                <p style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--text-secondary);">
                    Rule ID: ${cve.sentinel_rule_id || 'N/A'}
                </p>
            ` : hasLocalRule ? `
                <span class="coverage-badge pending">⏳ Rule ${cve.local_rule_status} (ID: ${cve.local_rule_id})</span>
            ` : isExposed ? `
                <span class="coverage-badge no-coverage">❌ No detection rule - action required</span>
            ` : `
                <span class="coverage-badge safe">✅ No coverage needed (no exposure)</span>
            `}
        </div>
        
        ${cve.date_added ? `
        <div class="cve-detail-section">
            <h4>Date Added to KEV</h4>
            <p>${new Date(cve.date_added).toLocaleDateString()}</p>
        </div>` : ''}
        ${cve.due_date ? `
        <div class="cve-detail-section">
            <h4>Remediation Due Date</h4>
            <p style="color: var(--critical);">⚠️ ${new Date(cve.due_date).toLocaleDateString()}</p>
        </div>` : ''}
        ${cve.ransomware_use ? `
        <div class="cve-detail-section">
            <h4>⚠️ Ransomware Use</h4>
            <p style="color: var(--critical);">Known to be used in ransomware campaigns</p>
        </div>` : ''}
        
        <div class="cve-actions" style="margin-top: 1.5rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
            ${isExposed ? `
                <button class="btn btn-outline" onclick="checkExposure('${cve.cve_id}', '${escape(cve.vendor || '')}', '${escape(cve.product || '')}'); closeCVEModal();">
                    🔍 View Exposed Assets
                </button>
            ` : ''}
            ${hasLocalRule ? `
                <button class="btn btn-outline" onclick="viewRule(${cve.local_rule_id}); closeCVEModal();">
                    👁️ View Rule
                </button>
            ` : ''}
            <button class="btn btn-primary ${createDisabled ? 'disabled' : ''}" 
                    ${createDisabled ? 'disabled' : ''}
                    onclick="${createDisabled ? '' : `createRule('${cve.cve_id}'); closeCVEModal();`}">
                ${isDeployed ? '✓ Already Deployed' : hasLocalRule ? '✓ Rule Exists' : '+ Create Detection Rule'}
            </button>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeCVEModal() {
    document.getElementById('cve-modal').style.display = 'none';
}

async function checkExposure(cveId, vendor, product) {
    showLoading(`Checking exposure for ${cveId}...`);
    try {
        const response = await fetch(`${API_BASE}/threat-intel/exposure?vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}`);
        const data = await response.json();
        
        if (data.exposed && data.exposed_count > 0) {
            showExposedAssetsModal(cveId, data);
        } else {
            showSuccess(`No exposed assets found for ${cveId}`);
        }
    } catch (error) {
        showError('Failed to check exposure: ' + error.message);
    }
    hideLoading();
}

function showExposedAssetsModal(cveId, data) {
    const modal = document.getElementById('exposed-assets-modal');
    const title = document.getElementById('exposed-assets-title');
    const body = document.getElementById('exposed-assets-body');
    
    title.textContent = `Exposed Assets - ${cveId}`;
    
    body.innerHTML = `
        <div class="exposure-summary has-exposure">
            <div class="exposure-stats">
                <div class="exposure-stat">
                    <span class="exposure-stat-value total">${data.exposed_count}</span>
                    <span class="exposure-stat-label">Total Exposed</span>
                </div>
                <div class="exposure-stat">
                    <span class="exposure-stat-value critical">${data.critical_count || 0}</span>
                    <span class="exposure-stat-label">Critical</span>
                </div>
                <div class="exposure-stat">
                    <span class="exposure-stat-value high">${data.high_count || 0}</span>
                    <span class="exposure-stat-label">High</span>
                </div>
            </div>
        </div>
        <table class="exposed-assets-table">
            <thead>
                <tr>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Criticality</th>
                    <th>Matched Software</th>
                </tr>
            </thead>
            <tbody>
                ${(data.assets || []).map(asset => `
                    <tr>
                        <td><strong>${asset.hostname}</strong></td>
                        <td style="font-family: var(--font-mono);">${asset.ip}</td>
                        <td><span class="criticality-badge ${asset.criticality}">${asset.criticality}</span></td>
                        <td><span class="software-tag">${asset.matched_software}</span></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        <div style="margin-top: 1.5rem; text-align: right;">
            <button class="btn btn-primary" onclick="createRule('${cveId}'); closeExposedAssetsModal();">
                + Create Detection Rule
            </button>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeExposedAssetsModal() {
    document.getElementById('exposed-assets-modal').style.display = 'none';
}

async function createRule(cveId) {
    showLoading(`Creating detection rule for ${cveId}...`);
    try {
        const response = await fetch(`${API_BASE}/threat-intel/${cveId}/create-rule`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        
        if (data.success) {
            const mitreInfo = data.mitre_technique ? ` (${data.mitre_tactic}: ${data.mitre_technique})` : '';
            showSuccess(`Rule created for ${cveId}${mitreInfo}. Check Pending Actions.`);
            // Reload both threat intel (to update badges) and pending actions
            await loadThreatIntel();
            await loadPendingActions();
        } else {
            if (data.existing_rule_id) {
                showNotification(`Rule already exists for ${cveId} (Status: ${data.existing_rule_status})`, 'warning');
            } else {
                showError('Failed to create rule: ' + (data.error || 'Unknown error'));
            }
        }
    } catch (error) {
        showError('Failed to create rule: ' + error.message);
    }
    hideLoading();
}

async function viewRule(ruleId) {
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}`);
        const data = await response.json();
        
        if (data.success && data.rule) {
            showRuleModal(data.rule);
        } else {
            showError('Rule not found');
        }
    } catch (error) {
        showError('Failed to load rule: ' + error.message);
    }
}

function showRuleModal(rule) {
    const modal = document.getElementById('rule-modal');
    const title = document.getElementById('rule-modal-title');
    const body = document.getElementById('rule-modal-body');
    
    title.textContent = rule.title || 'Detection Rule';
    
    body.innerHTML = `
        <div class="cve-detail-section">
            <h4>Description</h4>
            <p>${rule.description || 'No description'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Source CVE</h4>
            <p>${rule.source_cve || 'N/A'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Severity</h4>
            <span class="cve-severity ${(rule.severity || 'high').toLowerCase()}">${rule.severity || 'HIGH'}</span>
        </div>
        <div class="cve-detail-section">
            <h4>MITRE Techniques</h4>
            <p>${(rule.mitre_techniques || []).join(', ') || 'N/A'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>KQL Query (for Sentinel)</h4>
            <pre class="rule-code">${rule.kql_query || 'No KQL query available'}</pre>
        </div>
        ${rule.sigma_rule ? `
        <div class="cve-detail-section">
            <h4>Sigma Rule</h4>
            <pre class="rule-code">${rule.sigma_rule}</pre>
        </div>` : ''}
        <div class="cve-detail-section">
            <h4>Status</h4>
            <span class="cve-severity ${rule.status === 'deployed' ? 'low' : rule.status === 'approved' ? 'medium' : 'high'}">${rule.status}</span>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeRuleModal() {
    document.getElementById('rule-modal').style.display = 'none';
}

async function approveRule(ruleId) {
    showLoading('Approving rule...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved_by: 'analyst' })
        });
        const data = await response.json();
        
        if (data.success) {
            showSuccess('Rule approved!');
            // Refresh all relevant views
            await loadPendingActions();
            await loadThreatIntel();  // Update threat intel badges
            await loadThreatIntelPendingRules();  // Refresh pending rules
            await loadThreatIntelApprovedRules();  // Refresh approved rules
        } else {
            showError('Failed to approve: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to approve: ' + error.message);
    }
    hideLoading();
}

async function rejectRule(ruleId) {
    const reason = prompt('Rejection reason (optional):');
    showLoading('Rejecting rule...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason || 'Rejected by analyst' })
        });
        const data = await response.json();
        
        if (data.success) {
            showSuccess('Rule rejected');
            // Refresh all relevant views
            await loadPendingActions();
            await loadThreatIntel();  // Update threat intel badges
        } else {
            showError('Failed to reject: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to reject: ' + error.message);
    }
    hideLoading();
}

async function deployRule(ruleId) {
    showLoading('Deploying to Microsoft Sentinel...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/deploy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        
        if (data.success) {
            if (data.simulated) {
                showNotification(`⚠️ Rule saved locally (simulated). Sentinel integration not configured.`, 'warning');
            } else {
                showSuccess(`✅ Rule deployed to Sentinel! ID: ${data.sentinel_rule_id || 'N/A'}`);
            }
            // Refresh all relevant views
            await loadPendingActions();
            await loadDeployedRules();
            await loadThreatIntel();  // Update threat intel badges to show "Deployed"
            await loadThreatIntelApprovedRules();  // Refresh approved rules list
        } else {
            let errorMsg = data.error || 'Unknown error';
            if (data.suggestion) {
                errorMsg += `\n\n💡 ${data.suggestion}`;
            }
            if (data.import_error) {
                errorMsg = '❌ sentinel_integration.py not found in backend folder';
            }
            if (data.config_error) {
                errorMsg = '❌ Azure credentials not configured. Check .env file.';
            }
            showError(errorMsg);
        }
    } catch (error) {
        showError('Deployment failed: ' + error.message);
    }
    hideLoading();
}

async function redeployRule(ruleId) {
    if (!confirm('This rule exists locally but is NOT in Sentinel.\n\nRe-approve and deploy it now?')) return;
    
    showLoading('Re-approving and deploying to Sentinel...');
    try {
        // Step 1: Reset rule status to approved
        const approveResponse = await fetch(`${API_BASE}/rules/${ruleId}/approve?analyst=soc_analyst`, {
            method: 'POST'
        });
        const approveData = await approveResponse.json();
        
        if (!approveData.success) {
            // If approve fails (maybe rule is already in a state that allows deploy), try deploying directly
            console.log('Re-approve response:', approveData);
        }
        
        // Step 2: Deploy to Sentinel
        const deployResponse = await fetch(`${API_BASE}/rules/${ruleId}/deploy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await deployResponse.json();
        
        if (data.success) {
            showSuccess(`✅ Rule redeployed to Sentinel! ID: ${data.sentinel_rule_id || 'N/A'}`);
            await loadThreatIntel();  // Reload everything with fresh Sentinel check
        } else {
            let errorMsg = data.error || 'Redeployment failed';
            if (data.suggestion) errorMsg += `\n\n💡 ${data.suggestion}`;
            showError(errorMsg);
        }
    } catch (error) {
        showError('Redeployment failed: ' + error.message);
    }
    hideLoading();
}

async function loadPendingActions() {
    try {
        // Load pending detection rules
        
        // Load pending hunts (implemented but not yet approved)
        const pendingHuntsResponse = await fetch(`${API_BASE}/hunts?status=pending`);
        const pendingHunts = await pendingHuntsResponse.json();
        
        // Load approved hunts (ready to execute)
        const approvedHuntsResponse = await fetch(`${API_BASE}/hunts?status=approved`);
        const approvedHunts = await approvedHuntsResponse.json();
        
        // Load hunt-generated response actions (block IPs, investigate hosts, etc.)
        const huntActionsResponse = await fetch(`${API_BASE}/pending-actions?status=pending`);
        const huntActions = await huntActionsResponse.json();
        
        const allRules = [];
        const allHunts = [...(pendingHunts.hunts || []), ...(approvedHunts.hunts || [])];
        const allHuntActions = huntActions.actions || [];
        
        const container = document.getElementById('pending-actions-list');
        const countEl = document.getElementById('pending-actions-count');
        
        const totalCount = allRules.length + allHunts.length + allHuntActions.length;
        if (countEl) countEl.textContent = totalCount;
        
        if (!container) return;
        
        if (totalCount === 0) {
            container.innerHTML = '<p class="empty-state">No pending actions. Create detection rules or execute hunts to see recommended actions here.</p>';
            return;
        }
        
        // Render hunt-generated response actions (block IPs, investigate hosts, etc.)
        const huntActionsHtml = allHuntActions.map(action => {
            const actionIcons = {
                'block_ips': '🚫',
                'investigate_hosts': '🔍',
                'escalate_incident': '🚨',
                'isolate_host': '🔒',
                'collect_forensics': '📁'
            };
            const icon = actionIcons[action.action_type] || '⚡';
            
            return `
            <div class="pending-action-card response-action-card ${action.priority?.toLowerCase() || 'high'}">
                <div class="pending-action-header">
                    <span class="action-type-badge response-badge">${icon} RESPONSE ACTION</span>
                    <span class="cve-severity ${(action.priority || 'high').toLowerCase()}">${action.priority || 'HIGH'}</span>
                    <span class="status-badge pending">PENDING</span>
                </div>
                <div class="pending-action-title">${action.title}</div>
                <div class="pending-action-description">${action.description || ''}</div>
                <div class="pending-action-meta">
                    <span>Type: ${action.action_type}</span>
                    <span>Source: Hunt #${action.source_id}</span>
                </div>
                <div class="pending-action-actions">
                    <button class="btn btn-sm btn-approve" onclick="approveResponseAction(${action.id})">✓ Approve & Execute</button>
                    <button class="btn btn-sm btn-reject" onclick="rejectResponseAction(${action.id})">✗ Reject</button>
                </div>
            </div>
        `}).join('');
        
        // Render rules
        const rulesHtml = allRules.map(rule => `
            <div class="pending-action-card">
                <div class="pending-action-header">
                    <span class="action-type-badge">🛡️ DETECTION RULE</span>
                    <span class="cve-severity ${(rule.severity || 'high').toLowerCase()}">${rule.severity || 'HIGH'}</span>
                    <span class="status-badge ${rule.status}">${rule.status.toUpperCase()}</span>
                </div>
                <div class="pending-action-title">${rule.title}</div>
                <div class="pending-action-description">${rule.description || ''}</div>
                <div class="pending-action-meta">
                    <span>CVE: ${rule.source_cve || 'N/A'}</span>
                    <span>MITRE: ${(rule.mitre_techniques || []).join(', ') || 'N/A'}</span>
                </div>
                <div class="pending-action-actions">
                    <button class="btn btn-sm btn-outline" onclick="viewRule(${rule.id})">👁️ View Rule</button>
                    ${rule.status === 'pending' ? `
                        <button class="btn btn-sm btn-approve" onclick="approveRule(${rule.id})">✓ Approve</button>
                        <button class="btn btn-sm btn-reject" onclick="rejectRule(${rule.id})">✗ Reject</button>
                    ` : `
                        <button class="btn btn-sm btn-primary" onclick="deployRule(${rule.id})">🚀 Deploy to Sentinel</button>
                    `}
                </div>
            </div>
        `).join('');
        
        // Render hunts
        const huntsHtml = allHunts.map(hunt => `
            <div class="pending-action-card hunt-action-card">
                <div class="pending-action-header">
                    <span class="action-type-badge hunt-badge">🎯 THREAT HUNT</span>
                    <span class="cve-severity ${(hunt.priority || 'high').toLowerCase()}">${(hunt.priority || 'HIGH').toUpperCase()}</span>
                    <span class="status-badge ${hunt.status}">${hunt.status.toUpperCase()}</span>
                </div>
                <div class="pending-action-title">${hunt.title}</div>
                <div class="pending-action-description">${hunt.hypothesis || hunt.description || ''}</div>
                <div class="pending-action-meta">
                    <span>🎯 MITRE: ${hunt.mitre_technique || 'N/A'}</span>
                    ${hunt.related_cve ? `<span>🔗 ${hunt.related_cve}</span>` : ''}
                </div>
                <div class="pending-action-actions">
                    <button class="btn btn-sm btn-outline" onclick="viewHuntDetails(${hunt.id})">👁️ View Query</button>
                    ${hunt.status === 'pending' ? `
                        <button class="btn btn-sm btn-approve" onclick="approveHunt(${hunt.id})">✓ Approve</button>
                        <button class="btn btn-sm btn-reject" onclick="rejectHunt(${hunt.id})">✗ Reject</button>
                    ` : `
                        <button class="btn btn-sm btn-primary" onclick="executeHunt(${hunt.id})">🚀 Execute Hunt</button>
                    `}
                </div>
            </div>
        `).join('');
        
        // Show hunt actions first (most urgent), then rules, then hunts
        container.innerHTML = huntActionsHtml + rulesHtml + huntsHtml;
    } catch (error) {
        console.error('Failed to load pending actions:', error);
    }
}

// Functions to handle response actions from hunt analysis
async function approveResponseAction(actionId) {
    if (!confirm('Approve and execute this response action?')) return;
    
    showLoading('Executing response action...');
    try {
        const response = await fetch(`${API_BASE}/pending-actions/${actionId}/execute`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`✅ Action executed: ${data.result?.message || 'Completed'}`);
            await loadPendingActions();
        } else {
            showError('Failed to execute action: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to execute action: ' + error.message);
    }
    hideLoading();
}

async function rejectResponseAction(actionId) {
    const reason = prompt('Reason for rejection (optional):');
    
    showLoading('Rejecting action...');
    try {
        const response = await fetch(`${API_BASE}/pending-actions/${actionId}/reject`, { 
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reason: reason || 'Rejected by analyst'})
        });
        const data = await response.json();
        
        if (data.success) {
            showNotification('Action rejected', 'info');
            await loadPendingActions();
        } else {
            showError('Failed to reject action: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to reject action: ' + error.message);
    }
    hideLoading();
}

async function loadPendingHunts() {
    try {
        // Load hunts that are actionable (recommended, pending_approval, approved)
        // API now auto-filters out executed/completed/dismissed hunts
        const response = await fetch(`${API_BASE}/hunts`);
        const data = await response.json();
        
        const container = document.getElementById('hunt-recommendations-list');
        if (!container) return;
        
        // Filter to only show 'recommended' status in this panel
        const hunts = (data.hunts || []).filter(h => h.status === 'recommended');
        
        // Update badge
        const badge = document.getElementById('threat-hunting-badge');
        if (badge) {
            badge.textContent = hunts.length > 0 ? hunts.length : '';
        }
        
        if (hunts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>✅ All hunt recommendations have been addressed!</p>
                    <p class="empty-state-hint">Click "Generate Hunts" to create new AI-powered hunt hypotheses from latest threat intelligence.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = hunts.map(hunt => `
            <div class="hunt-recommendation-card" id="hunt-rec-${hunt.id}">
                <div class="hunt-rec-header">
                    <span class="action-type-badge">🎯 AI RECOMMENDATION</span>
                    <span class="cve-severity ${(hunt.priority || 'medium').toLowerCase()}">${(hunt.priority || 'MEDIUM').toUpperCase()}</span>
                </div>
                <div class="hunt-rec-title">${hunt.title}</div>
                <div class="hunt-rec-hypothesis">${hunt.hypothesis || hunt.description || ''}</div>
                ${hunt.rationale ? `<div class="hunt-rationale"><strong>Why hunt:</strong> ${hunt.rationale}</div>` : ''}
                <div class="hunt-rec-meta">
                    <span>🎯 MITRE: ${hunt.mitre_technique || 'N/A'}</span>
                    ${hunt.related_cve ? `<span>🔗 ${hunt.related_cve}</span>` : ''}
                </div>
                <div class="hunt-rec-actions">
                    <button class="btn btn-sm btn-outline" onclick="viewHuntDetails(${hunt.id})">👁️ View Query</button>
                    <button class="btn btn-sm btn-primary" onclick="implementHunt(${hunt.id})">
                        ➡️ Implement Hunt
                    </button>
                    <button class="btn btn-sm btn-ghost" onclick="dismissHunt(${hunt.id})">✗ Dismiss</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load hunt recommendations:', error);
    }
}

async function implementHunt(huntId) {
    showLoading('Moving hunt to pending actions for approval...');
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}/implement`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess('✅ Hunt moved to Pending Actions for approval');
            await loadPendingHunts();
            await loadPendingActions();
        } else {
            showError('Failed to implement hunt: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to implement hunt: ' + error.message);
    }
    hideLoading();
}

async function dismissHunt(huntId) {
    if (!confirm('Dismiss this hunt recommendation?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}/dismiss`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showNotification('Hunt dismissed', 'info');
            await loadPendingHunts();
        }
    } catch (error) {
        showError('Failed to dismiss hunt: ' + error.message);
    }
}

async function loadHuntResults() {
    try {
        // API now auto-filters out escalated results by default
        const response = await fetch(`${API_BASE}/hunts/results`);
        const data = await response.json();
        
        const container = document.getElementById('hunt-results-list');
        const countEl = document.getElementById('hunt-results-count');
        
        if (!container) return;
        
        const results = data.results || [];
        if (countEl) countEl.textContent = results.length > 0 ? results.length : '';
        
        if (results.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>✅ All hunt results have been addressed!</p>
                    <p class="empty-state-hint">Execute approved hunts to see new findings, or check Investigations for escalated results.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = results.map(result => {
            const severityClass = result.findings_count > 20 ? 'critical' : result.findings_count > 10 ? 'high' : 'medium';
            const hasFindings = result.findings_count > 0;
            
            return `
                <div class="hunt-result-card ${severityClass}">
                    <div class="hunt-result-header">
                        <span class="hunt-result-title">Hunt #${result.hunt_id}</span>
                        <span class="findings-badge ${severityClass}">${result.findings_count} findings</span>
                    </div>
                    <div class="hunt-result-summary">${result.findings_summary || 'Hunt completed'}</div>
                    ${result.malicious_ips && result.malicious_ips.length > 0 ? `
                        <div class="hunt-result-iocs">
                            <strong>🚨 Malicious IPs:</strong> ${result.malicious_ips.join(', ')}
                        </div>
                    ` : ''}
                    ${result.affected_hosts && result.affected_hosts.length > 0 ? `
                        <div class="hunt-result-hosts">
                            <strong>💻 Affected Hosts:</strong> ${result.affected_hosts.join(', ')}
                        </div>
                    ` : ''}
                    <div class="hunt-result-actions">
                        ${hasFindings ? `
                            <button class="btn btn-sm btn-warning" onclick="escalateHuntResult(${result.id})">⚠️ Escalate to Investigation</button>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load hunt results:', error);
    }
}

async function generateHunts(fresh = false) {
    const message = fresh 
        ? 'Clearing old hunts and regenerating from latest threat intel...'
        : 'AI is analyzing threat intelligence and generating hunt hypotheses...';
    showLoading(message);
    try {
        const url = fresh 
            ? `${API_BASE}/hunts/generate?fresh=true`
            : `${API_BASE}/hunts/generate`;
        const response = await fetch(url, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            const count = data.count || 0;
            if (count > 0) {
                showSuccess(`🎯 Generated ${count} hunt recommendations from latest CVEs (prioritized by year: 2026 > 2025 > 2024)`);
            } else {
                showNotification('No new hunts to generate. All threats already have hunt recommendations.', 'info');
            }
            await loadPendingHunts();
        } else {
            showError('Failed to generate hunts: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to generate hunts: ' + error.message);
    }
    hideLoading();
}

async function regenerateHunts() {
    if (confirm('This will clear all existing hunts and regenerate from the latest threat intel. Continue?')) {
        await generateHunts(true);
    }
}

async function approveHunt(huntId) {
    showLoading('Approving hunt...');
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}/approve`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess('✅ Hunt approved! Ready for execution.');
            await loadPendingActions();
        } else {
            showError('Failed to approve hunt: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to approve hunt: ' + error.message);
    }
    hideLoading();
}

async function rejectHunt(huntId) {
    const reason = prompt('Reason for rejection (optional):');
    
    showLoading('Rejecting hunt...');
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}/reject?reason=${encodeURIComponent(reason || 'Rejected by analyst')}`, { 
            method: 'POST' 
        });
        const data = await response.json();
        
        if (data.success) {
            showNotification('Hunt rejected', 'info');
            await loadPendingActions();
        } else {
            showError('Failed to reject hunt: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to reject hunt: ' + error.message);
    }
    hideLoading();
}

async function executeHunt(huntId) {
    if (!confirm('Execute this threat hunt? This will query the SIEM for potential indicators.')) {
        return;
    }
    
    showLoading('Executing threat hunt and analyzing results...');
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}/execute`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            const result = data.result || {};
            const findings = result.findings_count || 0;
            const agentAnalysis = data.agent_analysis || {};
            
            if (findings > 10) {
                showSuccess(`🚨 Hunt completed: ${findings} findings detected! ${agentAnalysis.actions_created || 0} response actions recommended.`);
            } else if (findings > 0) {
                showSuccess(`✅ Hunt completed: ${findings} findings. Review results.`);
            } else {
                showNotification('Hunt completed with no findings.', 'info');
            }
            
            // Refresh all relevant panes
            await loadPendingActions();  // Show new recommended actions
            await loadPendingHunts();
            await loadHuntResults();
        } else {
            showError('Failed to execute hunt: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to execute hunt: ' + error.message);
    }
    hideLoading();
}

async function escalateHuntResult(resultId) {
    if (!confirm('Escalate these hunt findings to a formal incident?')) {
        return;
    }
    
    showLoading('Escalating to incident...');
    try {
        const response = await fetch(`${API_BASE}/hunts/results/${resultId}/escalate`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`🚨 Escalated to Incident #${data.incident_id}`);
            await loadHuntResults();
        } else {
            showError('Failed to escalate: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to escalate: ' + error.message);
    }
    hideLoading();
}

async function viewHuntDetails(huntId) {
    try {
        const response = await fetch(`${API_BASE}/hunts/${huntId}`);
        const data = await response.json();
        
        if (!data.success) {
            showError('Failed to load hunt details');
            return;
        }
        
        const hunt = data.hunt;
        
        // Reuse the rule modal for hunt details
        const modal = document.getElementById('rule-modal');
        const title = document.getElementById('rule-modal-title');
        const body = document.getElementById('rule-modal-body');
        
        title.textContent = `Hunt: ${hunt.title}`;
        body.innerHTML = `
            <div class="rule-detail-section">
                <h4>Hypothesis</h4>
                <p>${hunt.hypothesis || 'N/A'}</p>
            </div>
            <div class="rule-detail-section">
                <h4>Rationale</h4>
                <p>${hunt.rationale || 'N/A'}</p>
            </div>
            <div class="rule-detail-section">
                <h4>Hunt Query (KQL)</h4>
                <pre class="kql-code">${hunt.hunt_query || 'No query defined'}</pre>
            </div>
            <div class="rule-detail-section">
                <h4>Details</h4>
                <p><strong>Status:</strong> ${hunt.status}</p>
                <p><strong>Priority:</strong> ${hunt.priority}</p>
                <p><strong>MITRE Technique:</strong> ${hunt.mitre_technique}</p>
                ${hunt.related_cve ? `<p><strong>Related CVE:</strong> ${hunt.related_cve}</p>` : ''}
                ${hunt.approved_by ? `<p><strong>Approved by:</strong> ${hunt.approved_by}</p>` : ''}
            </div>
        `;
        
        modal.style.display = 'flex';
    } catch (error) {
        showError('Failed to load hunt details: ' + error.message);
    }
}

// Close modals when clicking outside
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.style.display = 'none';
    }
});

// Close modals with Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.style.display = 'none';
        });
    }
});

console.log('Threat Center & Assets functions loaded');

// ========================================
// Threat Intelligence Page Functions
// ========================================

async function refreshThreatIntel() {
    showLoading('Refreshing threat intelligence...');
    await loadThreatIntel();
    await loadThreatIntelPendingRules();
    await loadThreatIntelApprovedRules();
    hideLoading();
    showNotification('Threat intelligence refreshed', 'success');
}

async function loadThreatIntelPendingRules() {
    try {
        const response = await fetch(`${API_BASE}/rules`);
        const data = await response.json();
        const rules = data.rules || [];
        
        // Filter pending rules only
        const pendingRules = rules.filter(r => r.status === 'pending');
        
        const container = document.getElementById('ti-pending-rules-list');
        const countEl = document.getElementById('ti-pending-rules-count');
        
        if (!container) return;
        
        if (countEl) countEl.textContent = pendingRules.length;
        
        // Update sidebar badge (total of pending rules)
        const badge = document.getElementById('threat-intel-badge');
        if (badge) badge.textContent = pendingRules.length > 0 ? pendingRules.length : '';
        
        if (pendingRules.length === 0) {
            container.innerHTML = '<p class="empty-state">No pending detection rules. Generate rules from CVEs above.</p>';
            return;
        }
        
        container.innerHTML = pendingRules.map(rule => `
            <div class="pending-item rule-item">
                <div class="pending-item-header">
                    <span class="pending-badge rule-badge">📜 Detection Rule</span>
                    <span class="pending-priority ${rule.severity?.toLowerCase() || 'medium'}">${rule.severity || 'Medium'}</span>
                </div>
                <div class="pending-item-title">${rule.title || 'Detection Rule'}</div>
                <div class="pending-item-meta">
                    <span>📌 ${rule.source_cve || 'N/A'}</span>
                    <span>🎯 ${(rule.mitre_techniques || []).join(', ') || 'N/A'}</span>
                </div>
                <div class="pending-item-actions">
                    <button class="btn btn-sm btn-approve" onclick="approveRule(${rule.id})">✓ Approve</button>
                    <button class="btn btn-sm btn-outline" onclick="viewRule(${rule.id})">View</button>
                    <button class="btn btn-sm btn-reject" onclick="rejectRule(${rule.id})">✗ Reject</button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Failed to load pending rules:', error);
    }
}

async function loadThreatIntelApprovedRules() {
    try {
        const response = await fetch(`${API_BASE}/rules`);
        const data = await response.json();
        const rules = data.rules || [];
        
        // Filter approved rules only (approved but not deployed)
        const approvedRules = rules.filter(r => r.status === 'approved');
        
        const container = document.getElementById('ti-approved-rules-list');
        const countEl = document.getElementById('ti-approved-rules-count');
        
        if (!container) return;
        
        if (countEl) countEl.textContent = approvedRules.length;
        
        if (approvedRules.length === 0) {
            container.innerHTML = '<p class="empty-state">No approved rules awaiting deployment.</p>';
            return;
        }
        
        container.innerHTML = approvedRules.map(rule => `
            <div class="pending-item rule-item approved-item">
                <div class="pending-item-header">
                    <span class="pending-badge approved-badge">✅ Approved Rule</span>
                    <span class="pending-priority ${rule.severity?.toLowerCase() || 'medium'}">${rule.severity || 'Medium'}</span>
                </div>
                <div class="pending-item-title">${rule.title || 'Detection Rule'}</div>
                <div class="pending-item-meta">
                    <span>📌 ${rule.source_cve || 'N/A'}</span>
                    <span>🎯 ${(rule.mitre_techniques || []).join(', ') || 'N/A'}</span>
                    <span>👤 Approved by: ${rule.approved_by || 'System'}</span>
                </div>
                <div class="pending-item-actions">
                    <button class="btn btn-sm btn-primary" onclick="deployRule(${rule.id})">🚀 Deploy to Sentinel</button>
                    <button class="btn btn-sm btn-outline" onclick="viewRule(${rule.id})">👁️ View</button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Failed to load approved rules:', error);
    }
}

// ========================================
// Threat Hunting Page Functions  
// ========================================

async function refreshThreatHunting() {
    showLoading('Refreshing threat hunting data...');
    await loadPendingHunts();
    await loadPendingActions();
    await loadHuntResults();
    hideLoading();
    showNotification('Threat hunting data refreshed', 'success');
}

// ========================================
// Investigations Page Functions
// ========================================

async function loadInvestigations() {
    try {
        const response = await fetch(`${API_BASE}/incidents`);
        const data = await response.json();
        
        const grid = document.getElementById('investigations-grid');
        if (!grid) return;
        
        if (data.success && data.data.incidents.length > 0) {
            // Filter to ONLY hunt escalations
            const investigations = data.data.incidents.filter(inc => 
                inc.title.startsWith('[Hunt Escalation]')
            );
            
            // Update badge
            const badge = document.getElementById('investigations-badge');
            if (badge) badge.textContent = investigations.length > 0 ? investigations.length : '';
            
            if (investigations.length > 0) {
                renderInvestigations(investigations);
            } else {
                grid.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <circle cx="11" cy="11" r="8"/>
                            <path d="M21 21l-4.35-4.35"/>
                        </svg>
                        <h3>No Investigations Yet</h3>
                        <p>Hunt escalations will appear here when threat hunts find suspicious activity</p>
                    </div>
                `;
            }
        } else {
            grid.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="M21 21l-4.35-4.35"/>
                    </svg>
                    <h3>No Investigations Yet</h3>
                    <p>Hunt escalations will appear here when threat hunts find suspicious activity</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Failed to load investigations:', error);
    }
}

function renderInvestigations(investigations) {
    const grid = document.getElementById('investigations-grid');
    
    grid.innerHTML = investigations.map(inv => {
        // Extract CVE from title if present
        const cveMatch = inv.title.match(/CVE-\d{4}-\d+/);
        const cve = cveMatch ? cveMatch[0] : 'N/A';
        
        // Clean up title for display
        const displayTitle = inv.title.replace('[Hunt Escalation] ', '');
        
        return `
            <div class="investigation-card ${inv.severity?.toLowerCase() || 'medium'}">
                <div class="investigation-card-header">
                    <h4 class="investigation-card-title">${displayTitle}</h4>
                    <span class="investigation-badge hunt">🔍 Hunt Finding</span>
                </div>
                
                <div class="investigation-card-meta">
                    <span class="severity-tag ${inv.severity?.toLowerCase() || 'medium'}">${inv.severity || 'MEDIUM'}</span>
                    <span>📌 ${cve}</span>
                    <span>📊 ${inv.alert_count || 0} indicators</span>
                    <span>⚔️ ${inv.attack_stage || 'detected'}</span>
                </div>
                
                <div class="investigation-card-summary">
                    ${inv.summary || 'Hunt findings require investigation.'}
                </div>
                
                <div class="investigation-card-findings">
                    <div class="finding-stat ${inv.alert_count > 20 ? 'critical' : 'warning'}">
                        <span class="finding-stat-value">${inv.alert_count || 0}</span>
                        <span class="finding-stat-label">Findings</span>
                    </div>
                    <div class="finding-stat">
                        <span class="finding-stat-value">${inv.severity?.charAt(0) || 'M'}</span>
                        <span class="finding-stat-label">Severity</span>
                    </div>
                </div>
                
                <div class="investigation-card-actions">
                    <select class="investigation-status-select" onchange="updateInvestigationStatus(${inv.id}, this.value)">
                        <option value="active" ${inv.status === 'active' ? 'selected' : ''}>Active</option>
                        <option value="investigating" ${inv.status === 'investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="contained" ${inv.status === 'contained' ? 'selected' : ''}>Contained</option>
                        <option value="resolved" ${inv.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="false_positive" ${inv.status === 'false_positive' ? 'selected' : ''}>False Positive</option>
                    </select>
                    <input type="text" class="assign-input" placeholder="Assign to..." 
                           value="${inv.assigned_to || ''}"
                           onchange="updateInvestigationAssignment(${inv.id}, this.value)">
                    <button class="btn btn-sm btn-outline" onclick="viewInvestigationDetails(${inv.id})">View Details</button>
                </div>
            </div>
        `;
    }).join('');
}

async function refreshInvestigations() {
    showLoading('Refreshing investigations...');
    await loadInvestigations();
    hideLoading();
    showNotification('Investigations refreshed', 'success');
}

async function updateInvestigationStatus(investigationId, status) {
    try {
        const response = await fetch(`${API_BASE}/incidents/${investigationId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        const data = await response.json();
        if (data.success) {
            showNotification(`Investigation status updated to ${status}`, 'success');
        }
    } catch (error) {
        showError('Failed to update status: ' + error.message);
    }
}

async function updateInvestigationAssignment(investigationId, assignee) {
    try {
        const response = await fetch(`${API_BASE}/incidents/${investigationId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ assigned_to: assignee })
        });
        const data = await response.json();
        if (data.success) {
            showNotification(`Investigation assigned to ${assignee}`, 'success');
        }
    } catch (error) {
        showError('Failed to assign: ' + error.message);
    }
}

function viewInvestigationDetails(investigationId) {
    // For now, switch to incidents view and show details
    // In production, this could open a modal with full details
    showNotification('Opening investigation details...', 'info');
    // Could implement a modal here
}


// ========================================
// VULNERABILITY MANAGEMENT (VMG)
// ========================================

let vmgData = [];

async function runVMGScan() {
    showLoading('Running vulnerability scan (Tenable simulation)...');
    try {
        const response = await fetch(`${API_BASE}/vmg/scan`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`✅ ${data.message}`);
            await loadVMGDashboard();
        } else {
            showError('Scan failed: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        showError('Scan failed: ' + error.message);
    }
    hideLoading();
}

async function loadVMGDashboard() {
    try {
        // Load dashboard stats
        const dashResponse = await fetch(`${API_BASE}/vmg/dashboard`);
        const dashData = await dashResponse.json();
        
        if (dashData.success) {
            updateVMGStats(dashData.stats);
        }
        
        // Load vulnerabilities
        const vulnResponse = await fetch(`${API_BASE}/vmg/vulnerabilities`);
        const vulnData = await vulnResponse.json();
        
        if (vulnData.success) {
            vmgData = vulnData.vulnerabilities || [];
            renderVMGList(vmgData);
            
            // Update badge
            const badge = document.getElementById('vmg-badge');
            if (badge) {
                const fixNowCount = vmgData.filter(v => v.priority === 'FIX NOW').length;
                badge.textContent = fixNowCount > 0 ? fixNowCount : '';
            }
        }
    } catch (error) {
        console.error('Failed to load VMG dashboard:', error);
    }
}

function updateVMGStats(stats) {
    document.getElementById('vmg-total').textContent = stats.total_vulnerabilities || 0;
    document.getElementById('vmg-critical').textContent = stats.by_severity?.Critical || 0;
    document.getElementById('vmg-high').textContent = stats.by_severity?.High || 0;
    document.getElementById('vmg-kev').textContent = stats.kev_count || 0;
    document.getElementById('vmg-fixnow').textContent = stats.fix_now_count || 0;
}

function renderVMGList(vulns) {
    const container = document.getElementById('vmg-list');
    const countDisplay = document.getElementById('vmg-count-display');
    
    if (!container) return;
    
    if (countDisplay) {
        countDisplay.textContent = `(${vulns.length})`;
    }
    
    if (!vulns || vulns.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No vulnerability data. Click "Run Scan" to simulate a Tenable scan.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = vulns.map(vuln => {
        const priorityClass = vuln.priority === 'FIX NOW' ? 'fix-now' : 
                             vuln.priority === 'Fix This Week' ? 'fix-week' : 
                             vuln.priority === 'Fix This Month' ? 'fix-month' : 'scheduled';
        
        const kevBadge = vuln.in_cisa_kev ? '<span class="kev-badge">🚨 CISA KEV</span>' : '';
        const exploitBadge = vuln.exploit_available ? '<span class="exploit-badge">⚠️ Exploit Available</span>' : '';
        
        return `
            <div class="vmg-card ${priorityClass}" data-cve="${vuln.cve_id}">
                <div class="vmg-card-header">
                    <div class="vmg-card-title">
                        <span class="cve-id">${vuln.cve_id}</span>
                        <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        ${kevBadge}
                        ${exploitBadge}
                    </div>
                    <div class="vmg-risk-score">
                        <span class="risk-label">AI Risk Score</span>
                        <span class="risk-value ${priorityClass}">${vuln.ai_risk_score}</span>
                    </div>
                </div>
                
                <div class="vmg-card-body">
                    <div class="vmg-asset-info">
                        <span class="asset-hostname">💻 ${vuln.hostname}</span>
                        <span class="asset-ip">${vuln.ip_address}</span>
                        <span class="asset-criticality ${vuln.asset_criticality}">${vuln.asset_criticality.toUpperCase()}</span>
                    </div>
                    
                    <div class="vmg-plugin-name">${vuln.plugin_name || vuln.description}</div>
                    
                    <div class="vmg-reasoning">
                        <strong>Why prioritized:</strong> ${vuln.risk_reasoning}
                    </div>
                    
                    <div class="vmg-meta">
                        <span>CVSS: ${vuln.cvss_score}</span>
                        <span>EPSS: ${(vuln.epss_score * 100).toFixed(0)}%</span>
                        <span>Owner: ${vuln.asset_owner}</span>
                        <span class="priority-badge ${priorityClass}">${vuln.priority}</span>
                    </div>
                </div>
                
                <div class="vmg-card-actions">
                    <button class="btn btn-sm btn-outline" onclick="viewVMGDetails('${vuln.cve_id}')">
                        📋 Remediation Steps
                    </button>
                    <button class="btn btn-sm btn-outline" onclick="assignVMGVuln('${vuln.cve_id}')">
                        👤 Assign
                    </button>
                    <select class="status-select" onchange="updateVMGStatus('${vuln.cve_id}', this.value)">
                        <option value="Open" ${vuln.status === 'Open' ? 'selected' : ''}>Open</option>
                        <option value="Assigned" ${vuln.status === 'Assigned' ? 'selected' : ''}>Assigned</option>
                        <option value="In Progress" ${vuln.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                        <option value="Remediated" ${vuln.status === 'Remediated' ? 'selected' : ''}>Remediated</option>
                        <option value="Accepted Risk" ${vuln.status === 'Accepted Risk' ? 'selected' : ''}>Accepted Risk</option>
                    </select>
                </div>
            </div>
        `;
    }).join('');
}

function filterVMG() {
    const severity = document.getElementById('vmg-severity-filter').value.toLowerCase();
    const priority = document.getElementById('vmg-priority-filter').value.toLowerCase();
    const kevOnly = document.getElementById('vmg-kev-only').checked;
    
    let filtered = vmgData;
    
    if (severity) {
        filtered = filtered.filter(v => v.severity.toLowerCase() === severity);
    }
    
    if (priority) {
        filtered = filtered.filter(v => v.priority.toLowerCase() === priority);
    }
    
    if (kevOnly) {
        filtered = filtered.filter(v => v.in_cisa_kev);
    }
    
    renderVMGList(filtered);
}

async function viewVMGDetails(cveId) {
    showLoading('Loading remediation guidance...');
    try {
        const response = await fetch(`${API_BASE}/vmg/vulnerability/${cveId}`);
        const data = await response.json();
        
        if (data.success) {
            const vuln = data.vulnerability;
            const remediation = data.remediation;
            
            const modalHtml = `
                <div class="vmg-detail-modal">
                    <h3>${vuln.cve_id} - ${vuln.plugin_name}</h3>
                    
                    <div class="vmg-detail-section">
                        <h4>Vulnerability Details</h4>
                        <p><strong>Severity:</strong> ${vuln.severity} (CVSS ${vuln.cvss_score})</p>
                        <p><strong>AI Risk Score:</strong> ${vuln.ai_risk_score} - ${vuln.priority}</p>
                        <p><strong>Affected Asset:</strong> ${vuln.hostname} (${vuln.ip_address})</p>
                        <p><strong>Description:</strong> ${vuln.description}</p>
                    </div>
                    
                    <div class="vmg-detail-section">
                        <h4>Remediation Steps</h4>
                        <ol>
                            ${remediation.steps ? remediation.steps.map(s => 
                                '<li><strong>' + s.action + ':</strong> ' + s.details + '</li>'
                            ).join('') : '<li>No remediation steps available</li>'}
                        </ol>
                    </div>
                    
                    ${remediation.workaround ? `
                        <div class="vmg-detail-section warning">
                            <h4>⚠️ Workaround (if patching delayed)</h4>
                            <p>${remediation.workaround}</p>
                        </div>
                    ` : ''}
                    
                    <div class="vmg-detail-section">
                        <h4>References</h4>
                        <ul>
                            ${remediation.references ? remediation.references.map(r => 
                                '<li><a href="' + r + '" target="_blank">' + r + '</a></li>'
                            ).join('') : ''}
                        </ul>
                    </div>
                </div>
            `;
            
            showVMGModal(vuln.cve_id, modalHtml);
        } else {
            showError('Failed to load vulnerability details');
        }
    } catch (error) {
        showError('Failed to load details: ' + error.message);
    }
    hideLoading();
}

function showVMGModal(title, content) {
    let modal = document.getElementById('vmg-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'vmg-modal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content vmg-detail-modal-content">
                <div class="modal-header">
                    <h3 id="vmg-modal-title"></h3>
                    <button class="modal-close" onclick="closeVMGModal()">×</button>
                </div>
                <div class="modal-body" id="vmg-modal-body"></div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    document.getElementById('vmg-modal-title').textContent = title;
    document.getElementById('vmg-modal-body').innerHTML = content;
    modal.style.display = 'flex';
}

function closeVMGModal() {
    const modal = document.getElementById('vmg-modal');
    if (modal) modal.style.display = 'none';
}

async function assignVMGVuln(cveId) {
    const assignee = prompt('Assign to (team or person):');
    if (!assignee) return;
    
    const dueDate = prompt('Due date (YYYY-MM-DD, optional):');
    
    try {
        let url = `${API_BASE}/vmg/vulnerability/${cveId}/assign?assigned_to=${encodeURIComponent(assignee)}`;
        if (dueDate) url += `&due_date=${encodeURIComponent(dueDate)}`;
        
        const response = await fetch(url, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`${cveId} assigned to ${assignee}`);
            await loadVMGDashboard();
        } else {
            showError('Failed to assign: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to assign: ' + error.message);
    }
}

async function updateVMGStatus(cveId, status) {
    try {
        const response = await fetch(`${API_BASE}/vmg/vulnerability/${cveId}/status?status=${encodeURIComponent(status)}`, {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`${cveId} status updated to ${status}`);
        } else {
            showError('Failed to update status: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to update status: ' + error.message);
    }
}
