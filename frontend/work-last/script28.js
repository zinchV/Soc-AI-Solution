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
        assets: { title: 'Asset Inventory', subtitle: 'Manage and monitor your assets' }
    };
    
    const titleInfo = titles[viewName] || { title: viewName, subtitle: '' };
    document.getElementById('page-title').textContent = titleInfo.title;
    document.getElementById('page-subtitle').textContent = titleInfo.subtitle;
    
    currentView = viewName;
    
    // Load view data
    if (viewName === 'alerts') loadAlerts();
    if (viewName === 'incidents') loadIncidents();
    if (viewName === 'threat-center') {
        loadThreatIntel();
        loadPendingActions();
        loadPendingHunts();
        loadHuntResults();
    }
    if (viewName === 'assets') loadAssets();
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
            incidents = data.data.incidents;
            renderIncidents(incidents);
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

function updateProactiveBadge() {
    const actionsCount = parseInt(document.getElementById('pending-actions-count')?.textContent || '0');
    const badge = document.getElementById('proactive-badge');
    if (badge) {
        badge.textContent = actionsCount;
    }
}

// ==================== REFRESH ALL ====================
async function refreshAll() {
    showLoading('Refreshing all proactive data...');
    try {
        await refreshThreatIntel();
        await loadPendingActions();
        await loadPendingHunts();
        await loadHuntResults();
        showSuccess('All data refreshed');
    } catch (error) {
        showError('Failed to refresh: ' + error.message);
    }
}

// ==================== THREAT INTELLIGENCE ====================
async function refreshThreatIntel() {
    showLoading('Fetching CISA KEV...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/refresh`, { method: 'POST' });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        await loadThreatIntel();
        showSuccess('Threat intel refreshed');
    } catch (error) {
        showError('Failed to refresh threat intel: ' + error.message);
    }
}

async function loadThreatIntel() {
    try {
        const response = await fetch(`${API_BASE}/threat-intel/kevs?limit=10`);
        const data = await response.json();
        const container = document.getElementById('threat-intel-list');
        
        if (!container) return;
        
        // Handle different response formats
        const threats = data.threats || data.vulnerabilities || [];
        
        if (threats.length === 0) {
            container.innerHTML = '<p class="empty-state">No threats found. Click Fetch KEV to load.</p>';
            return;
        }
        
        container.innerHTML = threats.map(t => `
            <div class="threat-card ${t.ransomware_use ? 'ransomware' : ''}">
                <div class="threat-header">
                    <span class="cve-id">${t.cve_id || t.cveID || 'Unknown CVE'}</span>
                    <span class="badge critical">CRITICAL</span>
                    ${t.ransomware_use ? '<span class="badge ransomware">🔒 RANSOMWARE</span>' : ''}
                </div>
                <div class="threat-body">
                    <strong>${t.vendor || t.vendorProject || 'Unknown'} - ${t.product || 'Unknown'}</strong>
                    <p>${(t.description || t.shortDescription || 'No description').substring(0, 150)}...</p>
                    ${t.due_date ? `<p style="color: var(--warning); font-size: 0.8rem;">⏰ Due: ${t.due_date}</p>` : ''}
                </div>
                <div class="threat-actions">
                    <button class="btn btn-sm" onclick="checkExposure('${escape(t.vendor || t.vendorProject || '')}', '${escape(t.product || '')}')">
                        🔍 Check Exposure
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="createRule('${t.cve_id || t.cveID || ''}')">
                        ➕ Create Rule
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading threat intel:', error);
        const container = document.getElementById('threat-intel-list');
        if (container) {
            container.innerHTML = `<p class="empty-state" style="color: var(--critical);">Error: ${error.message}</p>`;
        }
    }
}

async function checkExposure(vendor, product) {
    showLoading('Checking asset exposure...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/exposure?vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}`);
        const data = await response.json();
        hideLoading();
        
        if (data.exposed) {
            showToast(`⚠️ ${data.exposed_count} assets potentially exposed!`, 'warning');
            // Could show a modal with details
            alert(`Exposure Check Results:\n\n${data.exposed_count} assets potentially affected.\n\nAssets:\n${data.assets?.map(a => `- ${a.hostname} (${a.ip})`).join('\n') || 'See details in console'}`);
        } else {
            showToast('✓ No exposed assets found', 'success');
        }
    } catch (error) {
        showError('Exposure check failed: ' + error.message);
    }
}

async function createRule(cveId) {
    showLoading('Creating detection rule...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/create-rule`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: cveId })
        });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`Rule created for ${cveId}. Check Pending Actions.`);
            await loadPendingActions();
        } else {
            showError('Failed to create rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        showError('Rule creation failed: ' + error.message);
    }
}

// ==================== PENDING ACTIONS ====================
async function loadPendingActions() {
    try {
        const response = await fetch(`${API_BASE}/actions/pending`);
        const data = await response.json();
        
        const countEl = document.getElementById('pending-actions-count');
        if (countEl) {
            countEl.textContent = data.count || data.actions?.length || 0;
        }
        updateProactiveBadge();
        
        const container = document.getElementById('pending-actions-list');
        if (!container) return;
        
        const actions = data.actions || [];
        if (actions.length === 0) {
            container.innerHTML = '<p class="empty-state">No pending actions</p>';
            return;
        }
        
        container.innerHTML = actions.map(a => `
            <div class="action-card priority-${a.priority || 'medium'}">
                <div class="action-header">
                    <span class="action-type">${a.action_type || 'Action'}</span>
                    <span class="badge ${a.priority || 'medium'}">${(a.priority || 'MEDIUM').toUpperCase()}</span>
                </div>
                <div class="action-body">
                    <strong>${a.title || 'Untitled Action'}</strong>
                    <p>${a.description || 'No description'}</p>
                    ${a.cve_id ? `<p style="font-family: var(--font-mono); font-size: 0.8rem;">CVE: ${a.cve_id}</p>` : ''}
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-success" onclick="approveAction(${a.id})">
                        ✓ Approve
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="rejectAction(${a.id})">
                        ✗ Reject
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading pending actions:', error);
    }
}

async function approveAction(actionId) {
    const analyst = 'demo_analyst';
    try {
        await fetch(`${API_BASE}/actions/${actionId}/approve?analyst=${analyst}`, { method: 'POST' });
        showSuccess('Action approved');
        await loadPendingActions();
        
        if (confirm('Execute the action now?')) {
            await executeAction(actionId);
        }
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

// ==================== HUNT RECOMMENDATIONS ====================
async function generateHunts() {
    showLoading('Generating hunt recommendations...');
    try {
        await fetch(`${API_BASE}/hunts/recommend`, { method: 'POST' });
        await loadPendingHunts();
        showSuccess('Hunt recommendations generated');
    } catch (error) {
        showError('Failed to generate hunts: ' + error.message);
    }
}

async function loadPendingHunts() {
    try {
        const response = await fetch(`${API_BASE}/hunts/pending`);
        const data = await response.json();
        
        const container = document.getElementById('hunt-recommendations-list');
        if (!container) return;
        
        const hunts = data.hunts || [];
        if (hunts.length === 0) {
            container.innerHTML = '<p class="empty-state">No hunt recommendations. Click Generate Hunts.</p>';
            return;
        }
        
        container.innerHTML = hunts.map(h => `
            <div class="hunt-card">
                <div class="hunt-header">
                    <strong>${h.title || 'Untitled Hunt'}</strong>
                    <span class="badge ${h.priority || 'medium'}">${(h.priority || 'MEDIUM').toUpperCase()}</span>
                </div>
                <div class="hunt-body">
                    <p>${h.description || 'No description'}</p>
                    ${h.mitre_technique ? `<p style="font-size: 0.8rem;">🎯 MITRE: ${h.mitre_technique}</p>` : ''}
                    ${h.rationale ? `<div class="rationale"><strong>Why now:</strong> ${h.rationale}</div>` : ''}
                </div>
                <div class="hunt-actions">
                    <button class="btn btn-sm btn-success" onclick="approveHunt(${h.id})">
                        ✓ Approve & Run
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="rejectHunt(${h.id})">
                        ✗ Reject
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading hunts:', error);
    }
}

async function approveHunt(huntId) {
    const analyst = 'demo_analyst';
    showLoading('Approving and executing hunt...');
    try {
        // Approve
        await fetch(`${API_BASE}/hunts/${huntId}/approve?analyst=${analyst}`, { method: 'POST' });
        // Execute
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

// ==================== HUNT RESULTS ====================
async function loadHuntResults() {
    try {
        const response = await fetch(`${API_BASE}/hunts/results`);
        const data = await response.json();
        
        const countEl = document.getElementById('hunt-results-count');
        const container = document.getElementById('hunt-results-list');
        
        if (!container) return;
        
        const results = data.results || [];
        if (countEl) {
            countEl.textContent = results.length;
        }
        
        if (results.length === 0) {
            container.innerHTML = '<p class="empty-state">No hunt results yet</p>';
            return;
        }
        
        container.innerHTML = results.map(r => `
            <div class="result-card">
                <div class="result-header">
                    <strong>${r.hunt_title || 'Hunt Result'}</strong>
                    <span class="findings-count">${r.findings_count || 0} findings</span>
                </div>
                <div class="result-body">
                    <p>${r.findings_summary || 'No summary'}</p>
                    ${r.suspicious_ips && r.suspicious_ips.length > 0 ? `
                        <div class="suspicious-ips">
                            <strong>Suspicious IPs:</strong>
                            ${r.suspicious_ips.map(ip => `<span class="ip-tag">${ip}</span>`).join('')}
                        </div>
                    ` : ''}
                    <p style="font-size: 0.75rem; color: var(--text-muted);">
                        Executed: ${r.executed_at || 'Unknown'}
                    </p>
                </div>
                ${r.suspicious_ips && r.suspicious_ips.length > 0 ? `
                    <div class="result-actions">
                        <button class="btn btn-sm btn-primary" onclick="createBlockList(${r.id})">
                            🚫 Create Block List
                        </button>
                    </div>
                ` : ''}
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading hunt results:', error);
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

// ==================== UPDATE NAVIGATION ====================
// Update the switchView function to handle proactive view
const originalSwitchView = switchView;
switchView = function(viewName) {
    // Call original function
    originalSwitchView(viewName);
    
    // Handle proactive view
    if (viewName === 'proactive') {
        document.getElementById('page-title').textContent = 'Proactive SOC';
        document.getElementById('page-subtitle').textContent = 'Threat Intelligence & Proactive Hunting';
        // Load proactive data
        loadThreatIntel();
        loadPendingActions();
        loadPendingHunts();
        loadHuntResults();
    }
};

// Escape function for HTML attributes
function escape(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/'/g, '&#39;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

console.log('Proactive SOC functions loaded');

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

async function fetchKEV() {
    showLoading('Fetching CISA KEV data...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/refresh`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            await loadDeployedRules();
            await loadThreatIntel();
            showSuccess(`Loaded ${data.count || 0} vulnerabilities from CISA KEV`);
        } else {
            showError('Failed to fetch KEV: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        showError('Failed to fetch KEV: ' + error.message);
    }
    hideLoading();
}

async function loadThreatIntel() {
    try {
        const response = await fetch(`${API_BASE}/threat-intel/kevs`);
        const data = await response.json();
        
        threatIntelData = data.kevs || [];
        renderThreatIntelList();
        
        // Update badge
        const badge = document.getElementById('threat-center-badge');
        if (badge) badge.textContent = threatIntelData.length;
    } catch (error) {
        console.error('Failed to load threat intel:', error);
    }
}

function renderThreatIntelList() {
    const container = document.getElementById('threat-intel-list');
    if (!container) return;
    
    if (!threatIntelData || threatIntelData.length === 0) {
        container.innerHTML = '<p class="empty-state">Click "Fetch KEV" to load CISA Known Exploited Vulnerabilities</p>';
        return;
    }
    
    container.innerHTML = threatIntelData.map(cve => {
        const hasRule = deployedRules.has(cve.cve_id);
        return `
            <div class="cve-card ${hasRule ? 'has-rule' : ''}" onclick="showCVEDetail('${cve.cve_id}')">
                <div class="cve-header">
                    <span class="cve-id">${cve.cve_id}</span>
                    <span class="cve-severity ${(cve.severity || 'high').toLowerCase()}">${cve.severity || 'HIGH'}</span>
                </div>
                <div class="cve-product">${cve.vendor || 'Unknown'} - ${cve.product || 'Unknown'}</div>
                <div class="cve-description">${cve.description || 'No description available'}</div>
                ${cve.due_date ? `<div class="cve-due-date">🚨 Due: ${new Date(cve.due_date).toLocaleDateString()}</div>` : ''}
                ${hasRule ? '<span class="rule-deployed-badge">✓ Rule Deployed</span>' : ''}
                <div class="cve-actions" onclick="event.stopPropagation()">
                    <button class="btn btn-sm btn-outline" onclick="checkExposure('${cve.cve_id}', '${escape(cve.vendor)}', '${escape(cve.product)}')">
                        🔍 Check Exposure
                    </button>
                    ${!hasRule ? `<button class="btn btn-sm btn-primary" onclick="createRule('${cve.cve_id}')">+ Create Rule</button>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function showCVEDetail(cveId) {
    const cve = threatIntelData.find(c => c.cve_id === cveId);
    if (!cve) return;
    
    const modal = document.getElementById('cve-modal');
    const title = document.getElementById('cve-modal-title');
    const body = document.getElementById('cve-modal-body');
    
    title.textContent = cve.cve_id;
    body.innerHTML = `
        <div class="cve-detail-section">
            <h4>Product</h4>
            <p>${cve.vendor || 'Unknown'} - ${cve.product || 'Unknown'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Vulnerability Name</h4>
            <p>${cve.vulnerability_name || cve.cve_id}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Description</h4>
            <p>${cve.description || 'No description available'}</p>
        </div>
        <div class="cve-detail-section">
            <h4>Severity</h4>
            <span class="cve-severity ${(cve.severity || 'high').toLowerCase()}">${cve.severity || 'HIGH'}</span>
        </div>
        ${cve.date_added ? `
        <div class="cve-detail-section">
            <h4>Date Added to KEV</h4>
            <p>${new Date(cve.date_added).toLocaleDateString()}</p>
        </div>` : ''}
        ${cve.due_date ? `
        <div class="cve-detail-section">
            <h4>Remediation Due Date</h4>
            <p style="color: var(--critical);">${new Date(cve.due_date).toLocaleDateString()}</p>
        </div>` : ''}
        ${cve.ransomware_use ? `
        <div class="cve-detail-section">
            <h4>⚠️ Ransomware Use</h4>
            <p style="color: var(--critical);">Known to be used in ransomware campaigns</p>
        </div>` : ''}
        <div class="cve-actions" style="margin-top: 1.5rem;">
            <button class="btn btn-outline" onclick="checkExposure('${cve.cve_id}', '${escape(cve.vendor)}', '${escape(cve.product)}'); closeCVEModal();">
                🔍 Check Exposure
            </button>
            <button class="btn btn-primary" onclick="createRule('${cve.cve_id}'); closeCVEModal();">
                + Create Detection Rule
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

async function checkAllExposures() {
    if (!threatIntelData || threatIntelData.length === 0) {
        showError('Please fetch KEV data first');
        return;
    }
    
    showLoading('Checking all exposures...');
    
    const exposedCVEs = [];
    let criticalAssets = 0;
    let highAssets = 0;
    const allExposedAssets = [];
    
    // Only check CVEs that don't already have deployed rules
    const cvsToCheck = threatIntelData.filter(cve => !deployedRules.has(cve.cve_id));
    
    for (const cve of cvsToCheck.slice(0, 10)) { // Limit to 10 for performance
        try {
            const response = await fetch(`${API_BASE}/threat-intel/exposure?vendor=${encodeURIComponent(cve.vendor || '')}&product=${encodeURIComponent(cve.product || '')}`);
            const data = await response.json();
            
            if (data.exposed && data.exposed_count > 0) {
                exposedCVEs.push({
                    cve: cve.cve_id,
                    product: cve.product,
                    count: data.exposed_count,
                    assets: data.assets || []
                });
                criticalAssets += data.critical_count || 0;
                highAssets += data.high_count || 0;
                allExposedAssets.push(...(data.assets || []));
            }
        } catch (error) {
            console.error(`Failed to check ${cve.cve_id}:`, error);
        }
    }
    
    hideLoading();
    
    if (exposedCVEs.length > 0) {
        showExposureSummary({
            exposedCVEs,
            criticalAssets,
            highAssets,
            allExposedAssets
        });
    } else {
        showSuccess('No exposed assets found for checked CVEs');
    }
}

function showExposureSummary(results) {
    const summaryDiv = document.getElementById('exposure-summary');
    if (!summaryDiv) return;
    
    summaryDiv.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h4 style="margin: 0;">⚠️ Exposure Summary</h4>
            <button class="btn btn-sm btn-outline" onclick="hideExposureSummary()">× Close</button>
        </div>
        <div class="exposure-stats">
            <div class="exposure-stat">
                <span class="exposure-stat-value critical">${results.criticalAssets}</span>
                <span class="exposure-stat-label">Critical Assets</span>
            </div>
            <div class="exposure-stat">
                <span class="exposure-stat-value high">${results.highAssets}</span>
                <span class="exposure-stat-label">High Assets</span>
            </div>
            <div class="exposure-stat">
                <span class="exposure-stat-value total">${results.allExposedAssets.length}</span>
                <span class="exposure-stat-label">Total at Risk</span>
            </div>
        </div>
        <div class="exposure-details">
            <strong style="font-size: 0.8rem; color: var(--text-muted);">EXPOSED CVEs:</strong>
            ${results.exposedCVEs.map(cve => `
                <div class="exposure-item ${cve.assets[0]?.criticality || 'high'}">
                    <div>
                        <span class="cve-tag">${cve.cve}</span>
                        <span class="asset-info">${cve.product}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="asset-count">${cve.count} asset${cve.count > 1 ? 's' : ''}</span>
                        <button class="btn btn-sm" onclick="showExposedAssetsModal('${cve.cve}', {exposed_count: ${cve.count}, assets: ${JSON.stringify(cve.assets).replace(/"/g, '&quot;')}})">View</button>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    summaryDiv.style.display = 'block';
    summaryDiv.classList.add('has-exposure');
}

function hideExposureSummary() {
    const summaryDiv = document.getElementById('exposure-summary');
    if (summaryDiv) {
        summaryDiv.style.display = 'none';
    }
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
            showSuccess(`Rule created for ${cveId}. Check Pending Actions.`);
            await loadPendingActions();
        } else {
            showError('Failed to create rule: ' + (data.error || 'Unknown error'));
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
            await loadPendingActions();
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
            await loadPendingActions();
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
            showSuccess(`Rule deployed to Sentinel! ID: ${data.sentinel_rule_id || 'N/A'}`);
            await loadPendingActions();
            await loadDeployedRules();
            renderThreatIntelList();
        } else {
            showError('Deployment failed: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Deployment failed: ' + error.message);
    }
    hideLoading();
}

async function loadPendingActions() {
    try {
        const response = await fetch(`${API_BASE}/rules?status=pending`);
        const pendingRules = await response.json();
        
        const approvedResponse = await fetch(`${API_BASE}/rules?status=approved`);
        const approvedRules = await approvedResponse.json();
        
        const allRules = [...(pendingRules.rules || []), ...(approvedRules.rules || [])];
        
        const container = document.getElementById('pending-actions-list');
        const countEl = document.getElementById('pending-actions-count');
        
        if (countEl) countEl.textContent = allRules.length;
        
        if (!container) return;
        
        if (allRules.length === 0) {
            container.innerHTML = '<p class="empty-state">No pending actions</p>';
            return;
        }
        
        container.innerHTML = allRules.map(rule => `
            <div class="pending-action-card">
                <div class="pending-action-header">
                    <span class="action-type-badge">🛡️ DETECTION RULE</span>
                    <span class="cve-severity ${(rule.severity || 'high').toLowerCase()}">${rule.severity || 'HIGH'}</span>
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
    } catch (error) {
        console.error('Failed to load pending actions:', error);
    }
}

async function loadPendingHunts() {
    try {
        const response = await fetch(`${API_BASE}/hunts?status=pending`);
        const data = await response.json();
        
        const container = document.getElementById('hunt-recommendations-list');
        if (!container) return;
        
        const hunts = data.hunts || [];
        
        if (hunts.length === 0) {
            container.innerHTML = '<p class="empty-state">No hunt recommendations. Click Generate Hunts.</p>';
            return;
        }
        
        container.innerHTML = hunts.map(hunt => `
            <div class="pending-action-card">
                <div class="pending-action-header">
                    <span class="action-type-badge">🎯 HUNT</span>
                    <span class="cve-severity ${(hunt.priority || 'medium').toLowerCase()}">${hunt.priority || 'MEDIUM'}</span>
                </div>
                <div class="pending-action-title">${hunt.title}</div>
                <div class="pending-action-description">${hunt.description || ''}</div>
                <div class="pending-action-meta">
                    <span>MITRE: ${hunt.mitre_technique || 'N/A'}</span>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load hunts:', error);
    }
}

async function loadHuntResults() {
    try {
        const response = await fetch(`${API_BASE}/hunts/results`);
        const data = await response.json();
        
        const container = document.getElementById('hunt-results-list');
        const countEl = document.getElementById('hunt-results-count');
        
        if (!container) return;
        
        const results = data.results || [];
        if (countEl) countEl.textContent = results.length;
        
        if (results.length === 0) {
            container.innerHTML = '<p class="empty-state">No hunt results yet</p>';
            return;
        }
        
        container.innerHTML = results.map(result => `
            <div class="pending-action-card">
                <div class="pending-action-title">Hunt #${result.hunt_id}</div>
                <div class="pending-action-description">${result.findings_summary || 'No findings'}</div>
                <div class="pending-action-meta">
                    <span>Findings: ${result.findings_count || 0}</span>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load hunt results:', error);
    }
}

async function generateHunts() {
    showLoading('Generating hunt recommendations...');
    try {
        const response = await fetch(`${API_BASE}/hunts/generate`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`Generated ${data.count || 0} hunt recommendations`);
            await loadPendingHunts();
        } else {
            showError('Failed to generate hunts: ' + (data.error || 'Unknown'));
        }
    } catch (error) {
        showError('Failed to generate hunts: ' + error.message);
    }
    hideLoading();
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
