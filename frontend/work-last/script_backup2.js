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
        proactive: { title: 'Threat Center', subtitle: 'Threat intelligence, detection rules & hunting' }
    };
    
    const titleInfo = titles[viewName] || { title: viewName, subtitle: '' };
    document.getElementById('page-title').textContent = titleInfo.title;
    document.getElementById('page-subtitle').textContent = titleInfo.subtitle;
    
    currentView = viewName;
    
    // Load view data
    if (viewName === 'alerts') loadAlerts();
    if (viewName === 'incidents') loadIncidents();
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

// Global variable to store loaded threats
let loadedThreats = [];

async function loadThreatIntel() {
    try {
        const response = await fetch(`${API_BASE}/threat-intel/kevs?limit=10`);
        const data = await response.json();
        const container = document.getElementById('threat-intel-list');
        
        if (!container) return;
        
        // Handle different response formats
        const threats = data.threats || data.vulnerabilities || [];
        loadedThreats = threats; // Store globally for Check All function
        
        // Show/hide Check All button
        const checkAllBtn = document.getElementById('check-all-btn');
        if (checkAllBtn) {
            checkAllBtn.style.display = threats.length > 0 ? 'inline-flex' : 'none';
        }
        
        // Hide exposure summary when reloading
        const exposureSummary = document.getElementById('exposure-summary');
        if (exposureSummary) {
            exposureSummary.style.display = 'none';
        }
        
        if (threats.length === 0) {
            container.innerHTML = '<p class="empty-state">No threats found. Click Fetch KEV to load.</p>';
            return;
        }
        
        container.innerHTML = threats.map((t, index) => `
            <div class="threat-card ${t.ransomware_use ? 'ransomware' : ''}" id="threat-card-${index}" data-vendor="${escape(t.vendor || t.vendorProject || '')}" data-product="${escape(t.product || '')}">
                <div class="threat-header">
                    <span class="cve-id">${t.cve_id || t.cveID || 'Unknown CVE'}</span>
                    <span class="badge critical">CRITICAL</span>
                    ${t.ransomware_use ? '<span class="badge ransomware">🔒 RANSOMWARE</span>' : ''}
                    <span class="exposure-badge" id="exposure-status-${index}" style="display:none;"></span>
                </div>
                <div class="threat-body">
                    <strong>${t.vendor || t.vendorProject || 'Unknown'} - ${t.product || 'Unknown'}</strong>
                    <p>${(t.description || t.shortDescription || 'No description').substring(0, 150)}...</p>
                    ${t.due_date ? `<p style="color: var(--warning); font-size: 0.8rem;">⏰ Due: ${t.due_date}</p>` : ''}
                </div>
                <div class="threat-actions">
                    <button class="btn btn-sm" onclick="checkExposure('${escape(t.vendor || t.vendorProject || '')}', '${escape(t.product || '')}', ${index})">
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

async function checkExposure(vendor, product, index = null) {
    showLoading('Checking asset exposure...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/exposure?vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}`);
        const data = await response.json();
        hideLoading();
        
        // Update the individual card's exposure status if index provided
        if (index !== null) {
            const statusBadge = document.getElementById(`exposure-status-${index}`);
            const card = document.getElementById(`threat-card-${index}`);
            if (statusBadge && card) {
                if (data.is_exposed || data.exposed_count > 0) {
                    statusBadge.textContent = `⚠️ ${data.exposed_count} EXPOSED`;
                    statusBadge.className = 'exposure-badge';
                    statusBadge.style.display = 'inline-flex';
                    card.classList.add('exposed');
                } else {
                    statusBadge.textContent = '✓ Safe';
                    statusBadge.className = 'exposure-badge safe';
                    statusBadge.style.display = 'inline-flex';
                    card.classList.remove('exposed');
                }
            }
        }
        
        if (data.is_exposed || data.exposed_count > 0) {
            showToast(`⚠️ ${data.exposed_count} assets potentially exposed to ${product}!`, 'warning');
            // Show details in alert
            const assetList = data.assets?.map(a => 
                `- ${a.hostname} (${a.ip_address || a.ip}) - ${a.criticality?.toUpperCase()}`
            ).join('\n') || 'See console for details';
            alert(`🚨 EXPOSURE DETECTED for ${vendor} ${product}\n\n${data.exposed_count} assets affected:\n\n${assetList}\n\nRecommendation: ${data.recommendation || 'Patch immediately'}`);
        } else {
            showToast(`✓ No exposed assets found for ${product}`, 'success');
        }
        
        return data;
    } catch (error) {
        hideLoading();
        showError('Exposure check failed: ' + error.message);
        return null;
    }
}

// Check all loaded threats for exposure at once
async function checkAllExposures() {
    console.log('checkAllExposures called!');
    console.log('loadedThreats:', loadedThreats);
    
    if (!loadedThreats || loadedThreats.length === 0) {
        alert('No threats loaded. Click "Fetch KEV" first to load threats.');
        showToast('No threats loaded. Click Fetch KEV first.', 'warning');
        return;
    }
    
    alert(`Starting exposure check for ${loadedThreats.length} CVEs...`);
    console.log('🔍 Starting Check All Exposures for', loadedThreats.length, 'threats');
    showLoading(`Checking exposure for ${loadedThreats.length} CVEs...`);
    
    const results = {
        total: loadedThreats.length,
        exposed: 0,
        safe: 0,
        criticalAssets: 0,
        highAssets: 0,
        exposedCVEs: [],
        allExposedAssets: []
    };
    
    try {
        // Check each threat
        for (let i = 0; i < loadedThreats.length; i++) {
            const threat = loadedThreats[i];
            const vendor = threat.vendor || threat.vendorProject || '';
            const product = threat.product || '';
            const cveId = threat.cve_id || threat.cveID || 'Unknown';
            
            console.log(`  Checking ${i+1}/${loadedThreats.length}: ${cveId} - ${vendor}/${product}`);
            
            try {
                const response = await fetch(`${API_BASE}/threat-intel/exposure?vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}`);
                const data = await response.json();
                
                console.log(`    Response:`, data);
                
                // Update individual card status
                const statusBadge = document.getElementById(`exposure-status-${i}`);
                const card = document.getElementById(`threat-card-${i}`);
                
                if (data.is_exposed || data.exposed_count > 0) {
                    console.log(`    ⚠️ EXPOSED: ${data.exposed_count} assets`);
                    results.exposed++;
                    results.exposedCVEs.push({
                        cve: cveId,
                        vendor: vendor,
                        product: product,
                        count: data.exposed_count,
                        assets: data.assets || []
                    });
                    
                    // Count by criticality
                    if (data.assets) {
                        data.assets.forEach(a => {
                            if (a.criticality === 'critical') results.criticalAssets++;
                            if (a.criticality === 'high') results.highAssets++;
                            // Avoid duplicates
                            if (!results.allExposedAssets.find(x => x.hostname === a.hostname)) {
                                results.allExposedAssets.push(a);
                            }
                        });
                    }
                    
                    if (statusBadge && card) {
                        statusBadge.textContent = `⚠️ ${data.exposed_count} EXPOSED`;
                        statusBadge.className = 'exposure-badge';
                        statusBadge.style.display = 'inline-flex';
                        card.classList.add('exposed');
                    }
                } else {
                    console.log(`    ✓ Safe`);
                    results.safe++;
                    if (statusBadge && card) {
                        statusBadge.textContent = '✓ Safe';
                        statusBadge.className = 'exposure-badge safe';
                        statusBadge.style.display = 'inline-flex';
                        card.classList.remove('exposed');
                    }
                }
            } catch (e) {
                console.error(`Error checking ${cveId}:`, e);
            }
        }
        
        hideLoading();
        
        console.log('📊 Final Results:', results);
        
        // Show summary
        displayExposureSummary(results);
        
        if (results.exposed > 0) {
            showToast(`⚠️ Found ${results.exposed} CVEs with exposed assets!`, 'warning');
        } else {
            showToast('✓ No exposed assets found for any CVE', 'success');
        }
        
    } catch (error) {
        hideLoading();
        console.error('Check all exposures failed:', error);
        showError('Exposure check failed: ' + error.message);
    }
}

// Display the exposure summary panel
function displayExposureSummary(results) {
    const summaryDiv = document.getElementById('exposure-summary');
    if (!summaryDiv) return;
    
    if (results.exposed === 0) {
        summaryDiv.innerHTML = `
            <div class="exposure-stats">
                <div class="exposure-stat">
                    <span class="exposure-stat-value total">${results.total}</span>
                    <span class="exposure-stat-label">CVEs Checked</span>
                </div>
                <div class="exposure-stat">
                    <span class="exposure-stat-value" style="color: #22c55e;">✓ All Clear</span>
                    <span class="exposure-stat-label">No Exposures Found</span>
                </div>
            </div>
        `;
        summaryDiv.style.display = 'block';
        summaryDiv.classList.remove('has-exposure');
        return;
    }
    
    summaryDiv.innerHTML = `
        <div class="exposure-stats">
            <div class="exposure-stat">
                <span class="exposure-stat-value critical">${results.exposed}</span>
                <span class="exposure-stat-label">CVEs with Exposure</span>
            </div>
            <div class="exposure-stat">
                <span class="exposure-stat-value high">${results.criticalAssets}</span>
                <span class="exposure-stat-label">Critical Assets</span>
            </div>
            <div class="exposure-stat">
                <span class="exposure-stat-value medium">${results.highAssets}</span>
                <span class="exposure-stat-label">High Assets</span>
            </div>
            <div class="exposure-stat">
                <span class="exposure-stat-value total">${results.allExposedAssets.length}</span>
                <span class="exposure-stat-label">Total Assets at Risk</span>
            </div>
        </div>
        <div class="exposure-details">
            <strong style="font-size: 0.8rem; color: var(--text-muted);">EXPOSED ASSETS:</strong>
            ${results.exposedCVEs.map(cve => `
                <div class="exposure-item ${cve.assets[0]?.criticality || 'high'}">
                    <div>
                        <span class="cve-tag">${cve.cve}</span>
                        <span class="asset-info">${cve.product}</span>
                    </div>
                    <span class="asset-count">${cve.count} asset${cve.count > 1 ? 's' : ''}</span>
                </div>
            `).join('')}
        </div>
    `;
    summaryDiv.style.display = 'block';
    summaryDiv.classList.add('has-exposure');
}

async function createRule(cveId) {
    console.log('Creating rule for:', cveId);
    showLoading('Creating detection rule...');
    try {
        const response = await fetch(`${API_BASE}/threat-intel/create-rule`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: cveId })
        });
        const data = await response.json();
        hideLoading();
        
        console.log('Create rule response:', data);
        
        if (data.success) {
            showSuccess(`✅ Detection rule created for ${cveId}!`);
            
            // Show details in alert
            alert(`Detection Rule Created Successfully!\n\n` +
                `📋 Rule: ${data.rule?.title || cveId}\n` +
                `🔒 Status: Pending Approval\n` +
                `⚠️ Severity: ${data.rule?.severity || 'high'}\n\n` +
                `Next Steps:\n` +
                `1. Review the rule in "Pending Actions"\n` +
                `2. Approve to deploy to SIEM\n\n` +
                `The rule includes:\n` +
                `• Sigma rule format\n` +
                `• KQL query for Microsoft Sentinel\n` +
                `• Splunk SPL query`);
            
            // Reload pending actions to show the new rule
            await loadPendingActions();
        } else {
            if (data.existing_rule_id) {
                showToast(`Rule for ${cveId} already exists (ID: ${data.existing_rule_id})`, 'warning');
            } else {
                showError('Failed to create rule: ' + (data.error || 'Unknown error'));
            }
        }
    } catch (error) {
        hideLoading();
        console.error('Create rule error:', error);
        showError('Rule creation failed: ' + error.message);
    }
}

// ==================== PENDING ACTIONS ====================
async function loadPendingActions() {
    try {
        // Fetch pending actions, pending rules, AND approved rules (ready for deployment)
        const [actionsRes, pendingRulesRes, approvedRulesRes] = await Promise.all([
            fetch(`${API_BASE}/actions/pending`),
            fetch(`${API_BASE}/rules?status=pending`),
            fetch(`${API_BASE}/rules?status=approved`)
        ]);
        
        const actionsData = await actionsRes.json();
        const pendingRulesData = await pendingRulesRes.json();
        const approvedRulesData = await approvedRulesRes.json();
        
        const actions = actionsData.actions || [];
        const pendingRules = pendingRulesData.rules || [];
        const approvedRules = approvedRulesData.rules || [];
        
        const totalCount = actions.length + pendingRules.length + approvedRules.length;
        
        const countEl = document.getElementById('pending-actions-count');
        if (countEl) {
            countEl.textContent = totalCount;
        }
        updateProactiveBadge();
        
        const container = document.getElementById('pending-actions-list');
        if (!container) return;
        
        if (totalCount === 0) {
            container.innerHTML = '<p class="empty-state">No pending actions</p>';
            return;
        }
        
        // Render APPROVED rules (ready for deployment) - show these first with Deploy button
        const approvedRulesHtml = approvedRules.map(r => `
            <div class="action-card priority-high" style="border-left: 3px solid #22c55e;">
                <div class="action-header">
                    <span class="action-type" style="background: rgba(34, 197, 94, 0.2); color: #86efac;">✅ Approved Rule</span>
                    <span class="badge" style="background: linear-gradient(135deg, #22c55e, #16a34a); color: white;">READY TO DEPLOY</span>
                </div>
                <div class="action-body">
                    <strong>${r.title || 'Untitled Rule'}</strong>
                    <p>${(r.description || 'No description').substring(0, 100)}...</p>
                    ${r.source_cve ? `<p style="font-family: var(--font-mono); font-size: 0.8rem; color: #f59e0b;">CVE: ${r.source_cve}</p>` : ''}
                    <p style="font-size: 0.75rem; color: var(--text-muted);">Approved by: ${r.approved_by || 'Analyst'}</p>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="viewRule(${r.id})" style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc;">
                        👁️ View Rule
                    </button>
                    <button class="btn btn-sm" onclick="deployRule(${r.id})" style="background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; font-weight: 600;">
                        🚀 Deploy to Sentinel
                    </button>
                </div>
            </div>
        `).join('');

        // Render PENDING detection rules (need approval)
        const pendingRulesHtml = pendingRules.map(r => `
            <div class="action-card priority-high" style="border-left: 3px solid #8b5cf6;">
                <div class="action-header">
                    <span class="action-type" style="background: rgba(139, 92, 246, 0.2); color: #a78bfa;">🛡️ Detection Rule</span>
                    <span class="badge high">${(r.severity || 'HIGH').toUpperCase()}</span>
                </div>
                <div class="action-body">
                    <strong>${r.title || 'Untitled Rule'}</strong>
                    <p>${(r.description || 'No description').substring(0, 100)}...</p>
                    ${r.source_cve ? `<p style="font-family: var(--font-mono); font-size: 0.8rem; color: #f59e0b;">CVE: ${r.source_cve}</p>` : ''}
                    <p style="font-size: 0.75rem; color: var(--text-muted);">MITRE: ${r.mitre_techniques?.join(', ') || 'T1190'}</p>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="viewRule(${r.id})" style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc;">
                        👁️ View Rule
                    </button>
                    <button class="btn btn-sm btn-success" onclick="approveRule(${r.id})">
                        ✓ Approve
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="rejectRule(${r.id})">
                        ✗ Reject
                    </button>
                </div>
            </div>
        `).join('');
        
        // Render pending actions
        const actionsHtml = actions.map(a => `
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
        
        // Show approved rules first (ready to deploy), then pending rules, then actions
        container.innerHTML = approvedRulesHtml + pendingRulesHtml + actionsHtml;
        
    } catch (error) {
        console.error('Error loading pending actions:', error);
    }
}

// View rule details
async function viewRule(ruleId) {
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}`);
        const data = await response.json();
        
        if (data.success && data.rule) {
            const rule = data.rule;
            alert(`Detection Rule Details\n\n` +
                `📋 Title: ${rule.title}\n` +
                `🔒 Severity: ${rule.severity}\n` +
                `📅 Created: ${rule.created_at}\n` +
                `🎯 CVE: ${rule.source_cve || 'N/A'}\n\n` +
                `--- SIGMA RULE ---\n${(rule.sigma_rule || '').substring(0, 500)}...\n\n` +
                `--- KQL QUERY ---\n${(rule.kql_query || '').substring(0, 300)}...`);
        }
    } catch (error) {
        showError('Failed to load rule: ' + error.message);
    }
}

// Approve detection rule
async function approveRule(ruleId) {
    const analyst = prompt('Enter your name to approve:', 'SOC Analyst');
    if (!analyst) return;
    
    showLoading('Approving rule...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approver: analyst })
        });
        const data = await response.json();
        hideLoading();
        
        if (data.success) {
            showSuccess(`✅ Rule approved by ${analyst}! Ready for deployment.`);
            await loadPendingActions();
        } else {
            showError('Failed to approve rule: ' + (data.error || data.detail || 'Unknown error'));
        }
    } catch (error) {
        hideLoading();
        showError('Approval failed: ' + error.message);
    }
}

// Reject detection rule
async function rejectRule(ruleId) {
    const reason = prompt('Enter rejection reason:');
    if (!reason) return;
    
    showLoading('Rejecting rule...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason })
        });
        const data = await response.json();
        hideLoading();
        
        if (data.success) {
            showSuccess('Rule rejected');
            await loadPendingActions();
        } else {
            showError('Failed to reject rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        hideLoading();
        showError('Rejection failed: ' + error.message);
    }
}

// Deploy rule to Microsoft Sentinel
async function deployRule(ruleId) {
    if (!confirm('🚀 Deploy this rule to Microsoft Sentinel?\n\nThis will create a REAL analytics rule in your Azure Sentinel workspace.\n\nContinue?')) {
        return;
    }
    
    showLoading('Deploying rule to Microsoft Sentinel...');
    try {
        const response = await fetch(`${API_BASE}/rules/${ruleId}/deploy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        hideLoading();
        
        if (data.success) {
            // Show success message
            const message = data.simulated 
                ? `✅ Rule deployed (simulated mode)\n\nSentinel Rule ID: ${data.sentinel_rule_id}\n\nNote: Sentinel integration not configured - rule saved locally.`
                : `🎉 SUCCESS!\n\nRule deployed to Microsoft Sentinel!\n\nSentinel Rule ID: ${data.sentinel_rule_id}\n\nThe rule is now ACTIVE and monitoring your environment.`;
            
            alert(message);
            showSuccess('🚀 Rule deployed to Sentinel successfully!');
            
            // Reload to update the UI
            await loadPendingActions();
            await loadThreatIntel();
        } else {
            const errorMsg = `❌ Deployment Failed\n\n${data.error || 'Unknown error'}${data.suggestion ? '\n\nSuggestion: ' + data.suggestion : ''}`;
            alert(errorMsg);
            showError('Deployment failed: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        hideLoading();
        alert(`❌ Deployment Error\n\n${error.message}`);
        showError('Deployment failed: ' + error.message);
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

// ==================== ASSET INVENTORY ====================

let assetSearchTimeout = null;

async function loadAssets() {
    const typeFilter = document.getElementById('asset-type-filter')?.value || '';
    const criticalityFilter = document.getElementById('asset-criticality-filter')?.value || '';
    const searchTerm = document.getElementById('asset-search')?.value || '';
    
    try {
        let url = `${API_BASE}/assets?limit=100`;
        if (typeFilter) url += `&asset_type=${typeFilter}`;
        if (criticalityFilter) url += `&criticality=${criticalityFilter}`;
        if (searchTerm) url += `&search=${encodeURIComponent(searchTerm)}`;
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.success) {
            renderAssetSummary(data.summary, data.total);
            renderAssets(data.assets);
        } else {
            const container = document.getElementById('assets-grid');
            if (container) container.innerHTML = '<p class="empty-state">Failed to load assets</p>';
        }
    } catch (error) {
        console.error('Error loading assets:', error);
        const container = document.getElementById('assets-grid');
        if (container) container.innerHTML = `<p class="empty-state" style="color: var(--critical);">Error: ${error.message}</p>`;
    }
}

function renderAssetSummary(summary, total) {
    const container = document.getElementById('assets-summary');
    if (!container) return;
    
    container.innerHTML = `
        <div class="summary-stats" style="display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem;">
            <div class="stat-card" style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 1rem 1.5rem; text-align: center;">
                <span style="display: block; font-size: 1.75rem; font-weight: 700; color: var(--text-primary);">${total}</span>
                <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Total Assets</span>
            </div>
            <div class="stat-card" style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 10px; padding: 1rem 1.5rem; text-align: center;">
                <span style="display: block; font-size: 1.75rem; font-weight: 700; color: #ef4444;">${summary.by_criticality.critical}</span>
                <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Critical</span>
            </div>
            <div class="stat-card" style="background: rgba(249,115,22,0.1); border: 1px solid rgba(249,115,22,0.3); border-radius: 10px; padding: 1rem 1.5rem; text-align: center;">
                <span style="display: block; font-size: 1.75rem; font-weight: 700; color: #f97316;">${summary.by_criticality.high}</span>
                <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">High</span>
            </div>
            <div class="stat-card" style="background: rgba(234,179,8,0.1); border: 1px solid rgba(234,179,8,0.3); border-radius: 10px; padding: 1rem 1.5rem; text-align: center;">
                <span style="display: block; font-size: 1.75rem; font-weight: 700; color: #eab308;">${summary.by_criticality.medium}</span>
                <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Medium</span>
            </div>
        </div>
        <div class="type-stats" style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem;">
            <span style="padding: 0.35rem 0.75rem; background: rgba(99,102,241,0.15); border-radius: 20px; font-size: 0.8rem; color: #a5b4fc;">🖥️ Servers: ${summary.by_type.server}</span>
            <span style="padding: 0.35rem 0.75rem; background: rgba(34,197,94,0.15); border-radius: 20px; font-size: 0.8rem; color: #86efac;">💻 Workstations: ${summary.by_type.workstation}</span>
            <span style="padding: 0.35rem 0.75rem; background: rgba(249,115,22,0.15); border-radius: 20px; font-size: 0.8rem; color: #fdba74;">🌐 Network: ${summary.by_type.network}</span>
            <span style="padding: 0.35rem 0.75rem; background: rgba(239,68,68,0.15); border-radius: 20px; font-size: 0.8rem; color: #fca5a5;">🔒 Security: ${summary.by_type.security}</span>
        </div>
    `;
}

function renderAssets(assets) {
    const container = document.getElementById('assets-grid');
    if (!container) return;
    
    if (!assets || assets.length === 0) {
        container.innerHTML = '<p class="empty-state">No assets found matching filters</p>';
        return;
    }
    
    const criticalityColors = {
        critical: { border: '#ef4444', bg: 'rgba(239,68,68,0.1)' },
        high: { border: '#f97316', bg: 'rgba(249,115,22,0.1)' },
        medium: { border: '#eab308', bg: 'rgba(234,179,8,0.1)' },
        low: { border: '#22c55e', bg: 'rgba(34,197,94,0.1)' }
    };
    
    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem;">
            ${assets.map(asset => {
                const colors = criticalityColors[asset.criticality] || criticalityColors.medium;
                return `
                <div class="asset-card" style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-left: 3px solid ${colors.border}; border-radius: 12px; padding: 1rem; transition: all 0.2s ease;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                        <span style="font-weight: 600; font-size: 0.95rem; color: var(--text-primary); font-family: monospace;">${asset.hostname}</span>
                        <span class="badge ${asset.criticality}" style="background: ${colors.bg}; color: ${colors.border}; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; text-transform: uppercase;">${asset.criticality}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.75rem;">
                        <p style="margin: 0.25rem 0;"><strong>IP:</strong> ${asset.ip_address}</p>
                        <p style="margin: 0.25rem 0;"><strong>Type:</strong> ${asset.asset_type}</p>
                        <p style="margin: 0.25rem 0;"><strong>OS:</strong> ${asset.os || 'N/A'}</p>
                        <p style="margin: 0.25rem 0;"><strong>Owner:</strong> ${asset.owner}</p>
                        <p style="margin: 0.25rem 0;"><strong>Location:</strong> ${asset.location || 'N/A'}</p>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary);">
                        <strong>Software:</strong>
                        <div style="display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.5rem;">
                            ${asset.software.map(s => `<span style="padding: 0.2rem 0.5rem; background: rgba(99,102,241,0.15); border-radius: 4px; font-size: 0.7rem; font-family: monospace; color: #a5b4fc;">${s}</span>`).join('')}
                        </div>
                    </div>
                </div>
            `}).join('')}
        </div>
    `;
}

function debounceAssetSearch() {
    clearTimeout(assetSearchTimeout);
    assetSearchTimeout = setTimeout(() => loadAssets(), 300);
}

console.log('SOC AI Tool - All functions loaded including Assets');
