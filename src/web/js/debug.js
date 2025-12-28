/**
 * Debug menu functionality for Email Verification Engine
 * This file controls the visibility and actions of the debug menu based on
 * the 'Settings.Debug.Enable' setting in the database.
 */

// Global state for debug functionality
const debug = {
    isEnabled: false,
    isMenuCreated: false,
    settings: null
};

// Initialize debug functionality on document load
document.addEventListener('DOMContentLoaded', function() {
    // First check if debug is enabled
    checkDebugEnabled().then(enabled => {
        debug.isEnabled = enabled;
        
        // If debug is enabled, initialize the debug menu
        if (debug.isEnabled) {
            initializeDebugMenu();
        }
        
        // Add handler for the debug URL hash
        checkDebugHash();
        window.addEventListener('hashchange', checkDebugHash);
    });
});

/**
 * Check if debug is enabled in database settings
 */
async function checkDebugEnabled() {
    try {
        // Call the Python function to check debug setting
        const debugSetting = await eel.get_setting('Settings', 'Debug', 'Enable')();
        return debugSetting === '1';
    } catch (error) {
        console.error('Error checking debug setting:', error);
        return false;
    }
}

/**
 * Check URL hash for debug activation
 */
function checkDebugHash() {
    if (window.location.hash === '#debug') {
        // Debug activated via URL
        if (!debug.isMenuCreated) {
            initializeDebugMenu();
        } else {
            // Menu already exists, make sure it's visible
            document.getElementById('debug-menu-container').style.display = 'block';
        }
        // Remove the hash to clean up URL
        history.replaceState(null, document.title, window.location.pathname + window.location.search);
    }
}

/**
 * Initialize and create the debug menu
 */
function initializeDebugMenu() {
    // Create debug menu only once
    if (debug.isMenuCreated) return;
    
    // Create the menu container - using improved CSS classes
    const menuContainer = document.createElement('div');
    menuContainer.id = 'debug-menu-container';
    menuContainer.className = 'container debug-menu-container';
    menuContainer.style.position = 'fixed';
    menuContainer.style.top = '50px';
    menuContainer.style.right = '10px';
    menuContainer.style.zIndex = '1000';
    menuContainer.style.display = 'none';
    menuContainer.style.maxHeight = '80vh';
    menuContainer.style.overflowY = 'auto';
    menuContainer.style.width = '320px';
    menuContainer.style.boxShadow = '0 4px 15px var(--shadow)';
    
    // Add the debug menu header with proper CSS classes
    const menuHeader = document.createElement('div');
    menuHeader.className = 'flex justify-space-between align-center mb-15';
    menuHeader.innerHTML = `
        <h3 style="margin: 0; color: var(--primary-color);">Debug Menu</h3>
        <button class="btn btn-danger" id="debug-close-btn" style="padding: 4px 8px; font-size: 16px;">×</button>
    `;
    
    // Create menu content with improved CSS structure
    const menuContent = document.createElement('div');
    menuContent.className = 'debug-menu-content';
    
    // Add debug options with proper CSS classes and structure
    menuContent.innerHTML = `
        <div class="debug-section mb-20">
            <h4 class="debug-section-title">Cache Management</h4>
            <div class="flex flex-gap-10 mb-10">
                <button class="btn btn-secondary" data-action="purge-cache" style="flex: 1;">Purge Cache</button>
                <button class="btn btn-secondary" data-action="view-cache" style="flex: 1;">View Stats</button>
            </div>
            <button class="btn btn-danger" data-action="purge-exit" style="width: 100%;">Purge & Exit</button>
        </div>
        
        <div class="debug-section mb-20">
            <h4 class="debug-section-title">System</h4>
            <div class="flex flex-gap-10 mb-10">
                <button class="btn btn-secondary" data-action="log-viewer" style="flex: 1;">Log Viewer</button>
                <button class="btn btn-secondary" data-action="system-info" style="flex: 1;">System Info</button>
            </div>
            
            <div class="flex justify-space-between align-center p-10" style="background-color: var(--surface-alt); border-radius: 4px;">
                <span>Log Monitoring</span>
                <label class="toggle-switch">
                    <input type="checkbox" id="log-monitoring-toggle" data-action="toggle-log-monitoring">
                    <span class="toggle-slider"></span>
                </label>
            </div>
        </div>
        
        <div class="debug-section mb-20">
            <h4 class="debug-section-title">Test Functions</h4>
            <div class="grid-2col flex-gap-10 mb-10">
                <button class="btn btn-secondary" data-action="test-mx">Test MX</button>
                <button class="btn btn-secondary" data-action="test-smtp">Test SMTP</button>
            </div>
            <button class="btn btn-secondary" data-action="test-notification" style="width: 100%;">Test Notifications</button>
        </div>
    `;
    
    // Assemble the menu
    menuContainer.appendChild(menuHeader);
    menuContainer.appendChild(menuContent);
    
    // Add a trigger button with improved styling
    const triggerButton = document.createElement('button');
    triggerButton.id = 'debug-menu-trigger';
    triggerButton.className = 'btn debug-trigger';
    triggerButton.style.position = 'fixed';
    triggerButton.style.bottom = '20px';
    triggerButton.style.right = '20px';
    triggerButton.style.zIndex = '999';
    triggerButton.style.opacity = '0.8';
    triggerButton.style.backgroundColor = 'var(--info-color)';
    triggerButton.style.color = 'white';
    triggerButton.innerHTML = '⚙ Debug';
    triggerButton.onclick = toggleDebugMenu;
    
    // Append to the document
    document.body.appendChild(menuContainer);
    document.body.appendChild(triggerButton);
    
    // Add event listeners for debug buttons
    addDebugButtonListeners();
    
    debug.isMenuCreated = true;
}

/**
 * Toggle debug menu visibility
 */
function toggleDebugMenu() {
    const menu = document.getElementById('debug-menu-container');
    if (!menu) return;
    
    if (menu.style.display === 'block') {
        menu.style.display = 'none';
    } else {
        menu.style.display = 'block';
        updateLogMonitoringButton();
    }
}

/**
 * Add event listeners to debug buttons and toggles
 */
function addDebugButtonListeners() {
    // Close button
    document.getElementById('debug-close-btn')?.addEventListener('click', toggleDebugMenu);
    
    // For buttons
    document.querySelectorAll('button[data-action]').forEach(button => {
        button.addEventListener('click', function() {
            const action = this.getAttribute('data-action');
            handleDebugAction(action);
        });
    });
    
    // For toggle switches
    document.querySelectorAll('input[type="checkbox"][data-action]').forEach(toggle => {
        toggle.addEventListener('change', function() {
            const action = this.getAttribute('data-action');
            handleDebugToggle(action, this.checked);
        });
    });
}

/**
 * Show a notification using the global toast system
 * @param {string} type_name - The notification type: 'success', 'error', 'warning', 'info'
 * @param {string} message - The message to display
 * @param {boolean} persistent - Whether the notification should persist until clicked
 * @param {string} details - Optional additional details to show on hover
 */
function showDebugNotification(type_name, message, persistent = false, details = null) {
    // Always use the global show_message function
    if (typeof window.show_message === 'function') {
        window.show_message(type_name, message, persistent, details);
    } else {
        // Fallback to console if global function isn't available
        console.log(`${type_name.toUpperCase()}: ${message}${details ? ' - ' + details : ''}`);
    }
}

/**
 * Handle debug toggle actions
 */
async function handleDebugToggle(action, isChecked) {
    console.log(`Debug toggle: ${action}, state: ${isChecked}`);
    
    try {
        if (action === 'toggle-log-monitoring') {
            const result = await eel.toggle_log_monitoring(isChecked)();
            
            if (!result.success) {
                // If there was an error, revert the toggle
                document.getElementById('log-monitoring-toggle').checked = !isChecked;
                showDebugNotification('error', `Failed to ${isChecked ? 'start' : 'stop'} log monitoring`, true, result.error);
            }
        }
    } catch (error) {
        console.error(`Error in debug toggle ${action}:`, error);
        // Revert the toggle on error
        document.getElementById('log-monitoring-toggle').checked = !isChecked;
        showDebugNotification('error', `Failed to toggle ${action}`, true, error.message);
    }
}

/**
 * Handle debug menu actions
 */
async function handleDebugAction(action) {
    console.log(`Debug action: ${action}`);
    
    try {
        switch (action) {
            case 'purge-cache':
                showDebugDialog('Are you sure you want to purge all cache?', 
                    'This will clear memory cache, disk cache, and database cache entries.', 
                    async () => {
                        const result = await eel.debug_action('purge-cache')();
                        showDebugNotification('success', 'Cache Purged', false, result);
                    });
                break;
                
            case 'view-cache':
                const cacheStats = await eel.debug_action('view-cache')();
                showDebugMessage('Cache Statistics', cacheStats);
                break;
                
            case 'log-viewer':
                const logs = await eel.debug_action('get-logs')();
                showDebugLogViewer(logs);
                break;
                
            case 'system-info':
                const sysInfo = await eel.debug_action('system-info')();
                showDebugMessage('System Information', sysInfo);
                break;
                
            case 'test-mx':
                showDebugPrompt('Enter domain for MX test:', 'gmail.com', async (domain) => {
                    const mxResult = await eel.debug_action('test-mx', domain)();
                    showDebugMessage('MX Test Results', mxResult);
                });
                break;
                
            case 'test-smtp':
                showDebugPrompt('Enter domain for SMTP test:', 'gmail.com', async (domain) => {
                    const smtpResult = await eel.debug_action('test-smtp', domain)();
                    showDebugMessage('SMTP Test Results', smtpResult);
                });
                break;
                
            case 'test-notification':
                // Test all notification types
                showDebugNotification('info', 'This is a test info notification', false, 'Additional details for info message');
                setTimeout(() => {
                    showDebugNotification('success', 'This is a test success notification', false, 'Task completed successfully');
                }, 1000);
                setTimeout(() => {
                    showDebugNotification('warning', 'This is a test warning notification', true, 'This is a persistent warning with details');
                }, 2000);
                setTimeout(() => {
                    showDebugNotification('error', 'This is a test error notification', true, 'This is a persistent error with details');
                }, 3000);
                break;
                
            case 'purge-exit':
                showPurgeDialog();
                break;
                
            case 'toggle-log-monitoring':
                // This is now handled by handleDebugToggle()
                const status = await eel.get_log_monitoring_status()();
                const isActive = status.active;
                
                const result = await eel.toggle_log_monitoring(!isActive)();
                
                // Update toggle state
                const monitoringToggle = document.getElementById('log-monitoring-toggle');
                if (monitoringToggle) {
                    monitoringToggle.checked = !isActive;
                }
                
                if (!result.success) {
                    showDebugNotification('error', 'Log monitoring toggle failed', true, result.error);
                }
                break;
                
            default:
                console.log(`Unknown debug action: ${action}`);
        }
    } catch (error) {
        console.error(`Error in debug action ${action}:`, error);
        showDebugNotification('error', `Failed to execute ${action}`, true, error.message);
    }
}

/**
 * Show a debug dialog with confirmation using standard dialog classes
 */
function showDebugDialog(title, message, onConfirm) {
    // Create overlay using standard CSS classes
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard CSS classes
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content using standard dialog components with CSS classes
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body mb-20">${message}</div>
        <div class="dialog-buttons">
            <button class="btn confirm">Confirm</button>
            <button class="btn btn-secondary cancel">Cancel</button>
        </div>
    `;
    
    // Add event listeners
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup buttons
    dialog.querySelector('.confirm').addEventListener('click', () => {
        document.body.removeChild(overlay);
        if (onConfirm) onConfirm();
    });
    
    dialog.querySelector('.cancel').addEventListener('click', () => {
        document.body.removeChild(overlay);
    });
}

/**
 * Show a debug prompt to get input with improved styling
 */
function showDebugPrompt(title, defaultValue, onSubmit) {
    // Create overlay using standard CSS classes
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard CSS classes
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content using improved CSS structure
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body mb-20">
            <input type="text" class="debug-input" value="${defaultValue || ''}" style="width: 100%;">
        </div>
        <div class="dialog-buttons">
            <button class="btn confirm">Submit</button>
            <button class="btn btn-secondary cancel">Cancel</button>
        </div>
    `;
    
    // Add event listeners
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    const input = dialog.querySelector('input');
    input.focus();
    input.select();
    
    // Setup buttons
    dialog.querySelector('.confirm').addEventListener('click', () => {
        const value = input.value.trim();
        document.body.removeChild(overlay);
        if (onSubmit && value) onSubmit(value);
    });
    
    dialog.querySelector('.cancel').addEventListener('click', () => {
        document.body.removeChild(overlay);
    });
    
    // Add enter key support
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            dialog.querySelector('.confirm').click();
        }
    });
}

/**
 * Show debug message dialog with enhanced styling and structure
 */
function showDebugMessage(title, message) {
    // Create overlay using standard CSS classes
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard CSS classes with responsive sizing
    const dialog = document.createElement('div');
    dialog.className = 'dialog debug-message-dialog';
    
    // Make dialog responsive based on content type
    if (title === 'System Information') {
        dialog.style.maxWidth = '1000px';
        dialog.style.width = '95%';
    } else {
        dialog.style.maxWidth = '700px';
        dialog.style.width = '80%';
    }
    
    // Enhanced formatting for structured data using CSS classes
    let formattedMessage = '';
    
    if (title === 'Cache Statistics' && typeof message === 'object' && message !== null) {
        // Enhanced display for cache statistics using grid layout
        formattedMessage = `
            <div class="grid-3col flex-gap-10 debug-stats-grid">
                ${formatCacheSection('Memory Cache', message.memory, 'var(--success-color)')}
                ${formatCacheSection('Disk Cache (SQLite)', message.disk, 'var(--warning-color)')}
                ${formatCacheSection('PostgreSQL Cache', message.postgres, 'var(--info-color)')}
            </div>
        `;
    } 
    else if (title === 'System Information' && typeof message === 'object' && message !== null) {
        formattedMessage = `
            <div class="debug-system-grid" style="display: flex; flex-wrap: nowrap; gap: 10px; overflow-x: auto; padding-bottom: 10px; min-width: 850px;">
                ${formatSystemSection('CPU', {
                    '': message.processor
                }, 'var(--info-color)')}
                
                ${formatSystemSection('Memory', message.memory, 'var(--success-color)')}
                
                ${formatSystemSection('Disk', message.disk, 'var(--warning-color)')}
                
                ${formatSystemSection('Software', {
                    '': message.platform,
                    'Python': message.python,
                    'Eel Version': message.eel_version || 'Unknown',
                    'Browser': navigator.userAgent.split(' ').slice(-1)[0]
                }, 'var(--error-color)')}
            </div>
        `;
    }
    else {
        // Default formatting for other messages using code display
        if (typeof message === 'object') {
            formattedMessage = `<pre class="json-display">${JSON.stringify(message, null, 2)}</pre>`;
        } else {
            formattedMessage = `<div class="text-muted">${message}</div>`;
        }
    }
    
    // Add content using standard dialog components with CSS classes
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body" style="max-height: 70vh; overflow-y: auto;">${formattedMessage}</div>
        <div class="dialog-buttons">
            <button class="btn confirm">Close</button>
        </div>
    `;
    
    // Add event listeners
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup button
    dialog.querySelector('.confirm').addEventListener('click', () => {
        document.body.removeChild(overlay);
    });
}

/**
 * Format a system information section with improved CSS styling
 */
function formatSystemSection(title, data, color) {
    if (!data) {
        return `
            <div class="debug-info-card" style="flex: 1 1 200px; min-width: 200px;">
                <h3 class="debug-card-title" style="color: ${color};">${title}</h3>
                <p class="text-muted">No data available</p>
            </div>
        `;
    }
    
    let content = '';
    
    if (typeof data === 'object') {
        Object.entries(data).forEach(([key, value]) => {
            const keyDisplay = key ? `${key}:` : '';
            content += `
                <div class="debug-stat-row">
                    <span class="text-muted">${keyDisplay}</span>
                    <strong>${value}</strong>
                </div>
            `;
        });
    }
    
    return `
        <div class="debug-info-card" style="flex: 1 1 200px; min-width: 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px;">
            <h3 class="debug-card-title" style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px; color: ${color};">${title}</h3>
            ${content}
        </div>
    `;
}

/**
 * Format a cache section with improved CSS styling
 */
function formatCacheSection(title, data, color) {
    if (!data) {
        return `
            <div class="debug-info-card">
                <h3 class="debug-card-title" style="color: ${color};">${title}</h3>
                <p class="text-muted">No data available</p>
            </div>
        `;
    }
    
    if (data.error) {
        return `
            <div class="debug-info-card">
                <h3 class="debug-card-title" style="color: ${color};">${title}</h3>
                <p class="invalid-result">Error: ${data.error}</p>
            </div>
        `;
    }
    
    let content = '';
    
    // Special handling for PostgreSQL categories
    if (title === 'PostgreSQL Cache' && data.categories && data.categories.length > 0) {
        content += `
            <div class="debug-stat-row"><span class="text-muted">Total Entries:</span> <strong>${data.total_entries || 0}</strong></div>
            <div class="debug-stat-row"><span class="text-muted">Valid Entries:</span> <strong>${data.valid_entries || 0}</strong></div>
            <div class="debug-stat-row"><span class="text-muted">Expired Entries:</span> <strong>${data.expired_entries || 0}</strong></div>
            <div class="debug-stat-row"><span class="text-muted">Size:</span> <strong>${data.size_pretty || '0 bytes'}</strong></div>
        `;
        
        content += '<div class="debug-stat-group mt-10"><h4 class="text-muted mb-10">Categories</h4>';
        data.categories.forEach(cat => {
            content += `<div class="debug-stat-row"><span class="text-muted">${cat.category || 'unnamed'}:</span> <strong>${cat.count || 0}</strong></div>`;
        });
        content += '</div>';
    } else {
        // Generic cache stats display
        const statsMap = {
            'size': 'Size',
            'max_size': 'Max Size',
            'utilization': 'Utilization',
            'total_entries': 'Total Entries',
            'valid_entries': 'Valid Entries',
            'expired_entries': 'Expired Entries',
            'size_mb': 'Size'
        };
        
        Object.entries(statsMap).forEach(([key, label]) => {
            if (data[key] !== undefined) {
                content += `<div class="debug-stat-row"><span class="text-muted">${label}:</span> <strong>${data[key]}</strong></div>`;
            }
        });
    }
    
    return `
        <div class="debug-info-card" style="border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px; min-width: 200px;">
            <h3 class="debug-card-title" style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px; color: ${color};">${title}</h3>
            ${content}
        </div>
    `;
}

/**
 * Show debug log viewer with database logs only
 */
function showDebugLogViewer() {
    // Create overlay using standard CSS classes
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog with improved sizing and CSS classes
    const dialog = document.createElement('div');
    dialog.className = 'dialog debug-log-viewer';
    dialog.style.width = '900px';
    dialog.style.height = '80vh';
    dialog.style.maxWidth = '95%';
    
    // Create log viewer content with database-only controls
    dialog.innerHTML = `
        <div class="dialog-title">Database Log Viewer</div>
        <div class="debug-log-controls p-10" style="background-color: var(--surface-alt); border-bottom: 1px solid var(--border-color);">
            <div class="flex flex-gap-10 align-center mb-10">
                <select id="log-level-select" class="debug-log-select">
                    <option value="all">All Levels</option>
                    <option value="ERROR">Errors</option>
                    <option value="WARNING">Warnings</option>
                    <option value="INFO">Info</option>
                    <option value="DEBUG">Debug</option>
                </select>
                <select id="log-limit-select" class="debug-log-select">
                    <option value="100">Last 100</option>
                    <option value="500" selected>Last 500</option>
                    <option value="1000">Last 1000</option>
                    <option value="2000">Last 2000</option>
                </select>
                <input type="text" id="log-search" placeholder="Search logs..." style="flex: 1;">
                <button id="log-refresh" class="btn btn-secondary">Refresh</button>
            </div>
            <div class="flex flex-gap-10 align-center">
                <span class="text-muted" style="font-size: 0.9em;">
                    Source: <span id="log-source-info">PostgreSQL Database (Live)</span>
                </span>
                <span class="text-muted" style="font-size: 0.9em;" id="log-count-info">
                    Entries: Loading...
                </span>
            </div>
        </div>
        <div class="dialog-body debug-log-content" style="height: 60vh; overflow-y: auto; background-color: var(--surface-alt); font-family: monospace; padding: 10px;">
            <div id="log-content">
                <p class="text-center text-muted">Loading database logs...</p>
            </div>
        </div>
        <div class="dialog-buttons">
            <button class="btn confirm">Close</button>
        </div>
    `;
    
    // Add event listeners and initialize log viewer functionality
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup elements and initialize the log viewer
    initializeLogViewer(dialog);
    
    // Setup close button
    dialog.querySelector('.confirm').addEventListener('click', () => {
        document.body.removeChild(overlay);
    });
}

/**
 * Initialize database log viewer functionality
 */
function initializeLogViewer(dialog) {
    const logLevel = dialog.querySelector('#log-level-select');
    const logLimit = dialog.querySelector('#log-limit-select');
    const logSearch = dialog.querySelector('#log-search');
    const logRefresh = dialog.querySelector('#log-refresh');
    const logContent = dialog.querySelector('#log-content');
    const countInfo = dialog.querySelector('#log-count-info');
    
    // State tracking
    let currentLevel = 'all';
    let currentLimit = 500;
    let rawLogLines = [];
    
    // Load initial logs
    loadDatabaseLogs();
    
    // Event listeners
    logLevel.addEventListener('change', function() {
        currentLevel = this.value;
        loadDatabaseLogs();
    });
    
    logLimit.addEventListener('change', function() {
        currentLimit = parseInt(this.value);
        loadDatabaseLogs();
    });
    
    logSearch.addEventListener('input', filterLogContent);
    logRefresh.addEventListener('click', loadDatabaseLogs);
    
    // Load database logs function
    async function loadDatabaseLogs() {
        try {
            logContent.innerHTML = '<p class="text-center text-muted">Loading database logs...</p>';
            countInfo.textContent = 'Entries: Loading...';
            
            const result = await eel.get_db_logs(currentLimit)();
            
            if (result && result.success === false) {
                logContent.innerHTML = `<p class="invalid-result text-center">Database Error: ${result.error}</p>`;
                countInfo.textContent = 'Entries: Error';
                return;
            }
            
            if (!result || result.length === 0) {
                logContent.innerHTML = '<p class="text-center text-muted">No database logs found</p>';
                countInfo.textContent = 'Entries: 0';
                return;
            }
            
            // Filter by level if not 'all'
            let filteredLogs = result;
            if (currentLevel !== 'all') {
                filteredLogs = result.filter(log => {
                    const logLevel = log.level ? log.level.replace(/[\[\]]/g, '').toUpperCase() : '';
                    return logLevel === currentLevel.toUpperCase();
                });
            }
            
            // Convert database logs to the format expected by the display function
            rawLogLines = filteredLogs.map(log => {
                return JSON.stringify({
                    timestamp: formatDbTimestamp(log.timestamp),
                    level: formatLogLevel(log.level),
                    module: log.module || '',
                    function: log.function || '',
                    message: log.message || '',
                    file: log.file || '',
                    line: log.line || '',
                    exception: log.exception || null,
                    trace_id: log.trace_id || null
                });
            });
            
            formatAndDisplayLogContent(rawLogLines);
            filterLogContent();
            countInfo.textContent = `Entries: ${filteredLogs.length}${currentLevel !== 'all' ? ` (${currentLevel} only)` : ''}`;
            
        } catch (error) {
            logContent.innerHTML = `<p class="invalid-result text-center">Error loading database logs: ${error.message}</p>`;
            countInfo.textContent = 'Entries: Error';
            console.error('Database log loading error:', error);
        }
    }
    
    // Format database timestamp for consistency
    function formatDbTimestamp(timestamp) {
        if (!timestamp) return '';
        
        try {
            const date = new Date(timestamp);
            return date.toISOString().replace('T', ' ').substring(0, 23);
        } catch (e) {
            return timestamp;
        }
    }
    
    // Format log level for consistency
    function formatLogLevel(level) {
        if (!level) return '[INFO]';
        
        // If already formatted with brackets, return as-is
        if (level.startsWith('[') && level.endsWith(']')) {
            return level;
        }
        
        // Add brackets if missing
        return `[${level.toUpperCase()}]`;
    }
    
    // Format and display log content
    function formatAndDisplayLogContent(logLines) {
        if (!logLines || logLines.length === 0) {
            logContent.innerHTML = '<p class="text-center text-muted">No logs to display</p>';
            return;
        }
        
        // Show most recent logs first (they're already sorted DESC from database)
        const formattedLines = logLines.map(line => {
            try {
                if (!line.trim()) return '';
                
                const logEntry = JSON.parse(line);
                
                const levelColors = {
                    '[ERROR]': 'var(--error-color)',
                    '[WARNING]': 'var(--warning-color)', 
                    '[INFO]': 'var(--success-color)',
                    '[DEBUG]': 'var(--info-color)',
                    '[EMAIL]': 'var(--primary-color)',
                    '[SQL]': 'var(--text-muted)',
                    '[STATS]': 'var(--text-muted)',
                    '[CRITICAL]': 'var(--error-color)'
                };
                
                const levelColor = levelColors[logEntry.level?.trim()] || 'var(--text-muted)';
                
                return `
                    <div class="debug-log-entry" data-raw='${JSON.stringify(logEntry)}' style="padding: 8px 0; border-bottom: 1px solid var(--surface-border); cursor: pointer;">
                        <div class="debug-log-main" style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                            <span class="text-muted" style="font-size: 0.9em; min-width: 180px;">${logEntry.timestamp}</span>
                            ${logEntry.level ? `<span style="color: ${levelColor}; font-weight: bold; min-width: 70px;">${logEntry.level}</span>` : ''}
                            ${logEntry.module ? `<span style="color: var(--info-color); font-weight: 500;">${logEntry.module}</span>${logEntry.function ? '.' : ''}` : ''}
                            ${logEntry.function ? `<span style="color: var(--success-color); font-weight: 500;">${logEntry.function}()</span>` : ''}
                            <span style="color: var(--text-color); flex: 1;">${logEntry.message}</span>
                            ${logEntry.trace_id ? `<span style="color: var(--primary-color); font-size: 0.8em; font-family: monospace; background: var(--surface-border); padding: 2px 4px; border-radius: 3px;">${logEntry.trace_id.substring(0, 8)}...</span>` : ''}
                        </div>
                        ${logEntry.file && logEntry.line ? `<div style="color: var(--text-muted); font-size: 0.8em; margin-top: 2px; margin-left: 188px;">${logEntry.file}:${logEntry.line}</div>` : ''}
                        ${logEntry.exception ? `<div style="color: var(--error-color); margin-top: 5px; margin-left: 188px; border-left: 3px solid var(--error-color); padding-left: 8px; white-space: pre-wrap; font-size: 0.9em; background: var(--surface-border); padding: 5px 8px; border-radius: 3px;">${logEntry.exception}</div>` : ''}
                    </div>
                `;
            } catch (e) {
                return `<div class="debug-log-entry" style="padding: 8px 0; color: var(--text-muted);">${line}</div>`;
            }
        });
        
        logContent.innerHTML = formattedLines.join('');
        
        // Add click handlers for raw view toggle
        dialog.querySelectorAll('.debug-log-entry').forEach(entry => {
            entry.addEventListener('click', function() {
                try {
                    const rawData = JSON.parse(this.getAttribute('data-raw'));
                    
                    if (this.classList.contains('raw-view')) {
                        // Would need to restore formatted view - for now just reload
                        loadDatabaseLogs();
                    } else {
                        // Show raw view
                        this.innerHTML = '';
                        const preElement = document.createElement('pre');
                        preElement.className = 'json-display';
                        preElement.style.cssText = 'margin: 0; font-size: 0.85em; background: var(--surface-border); padding: 8px; border-radius: 3px; overflow-x: auto;';
                        preElement.textContent = JSON.stringify(rawData, null, 2);
                        this.appendChild(preElement);
                        this.classList.add('raw-view');
                    }
                } catch (e) {
                    console.error('Error toggling log entry format:', e);
                }
            });
        });
    }
    
    // Filter log content
    function filterLogContent() {
        const search = logSearch.value.toLowerCase().trim();
        
        if (rawLogLines.length === 0) return;
        
        if (!search) {
            formatAndDisplayLogContent(rawLogLines);
            countInfo.textContent = `Entries: ${rawLogLines.length}${currentLevel !== 'all' ? ` (${currentLevel} only)` : ''}`;
            return;
        }
        
        const filteredLines = rawLogLines.filter(line => {
            if (!line.trim()) return false;
            return line.toLowerCase().includes(search);
        });
        
        formatAndDisplayLogContent(filteredLines);
        countInfo.textContent = `Entries: ${filteredLines.length} (filtered from ${rawLogLines.length})`;
    }
}

/**
 * Show a dialog with purge options using improved CSS structure
 */
function showPurgeDialog() {
    // Create overlay using standard CSS classes
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard CSS classes
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content with improved CSS structure
    dialog.innerHTML = `
        <div class="dialog-title">Cache Purge & Exit</div>
        <div class="dialog-body mb-20">
            <p class="mb-15">Select items to purge before exit:</p>
            <div class="purge-options">
                <label class="flex align-center mb-10" style="font-weight: bold;">
                    <input type="checkbox" value="all" id="purge-all" checked style="margin-right: 8px;"> 
                    ALL
                </label>
                <label class="flex align-center mb-10">
                    <input type="checkbox" value="memory" class="purge-option" checked style="margin-right: 8px;"> 
                    Memory Cache (RAM)
                </label>
                <label class="flex align-center mb-10">
                    <input type="checkbox" value="disk" class="purge-option" checked style="margin-right: 8px;"> 
                    Disk Cache (.cache/cache.db)
                </label>
                <label class="flex align-center mb-10">
                    <input type="checkbox" value="database" class="purge-option" checked style="margin-right: 8px;"> 
                    Database Cache (PostgreSQL)
                </label>
                <label class="flex align-center mb-10">
                    <input type="checkbox" value="logs" class="purge-option" checked style="margin-right: 8px;"> 
                    Log Files (logs/*.log)
                </label>
            </div>
        </div>
        <div class="dialog-buttons">
            <button class="btn btn-danger purge-button">Purge & Exit</button>
            <button class="btn btn-secondary cancel-button">Cancel</button>
        </div>
    `;
    
    // Add event listeners and setup checkbox logic
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup checkbox logic and purge functionality
    setupPurgeDialog(dialog, overlay);
}

/**
 * Setup purge dialog functionality
 */
function setupPurgeDialog(dialog, overlay) {
    const allCheckbox = dialog.querySelector('#purge-all');
    const optionCheckboxes = dialog.querySelectorAll('.purge-option');
    
    // Checkbox logic
    allCheckbox.addEventListener('change', function() {
        optionCheckboxes.forEach(checkbox => {
            checkbox.checked = allCheckbox.checked;
        });
    });
    
    optionCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            if (!this.checked) {
                allCheckbox.checked = false;
            }
            
            if (Array.from(optionCheckboxes).every(cb => cb.checked)) {
                allCheckbox.checked = true;
            }
        });
    });
    
    // Purge button
    dialog.querySelector('.purge-button').addEventListener('click', function() {
        let selectedOptions = [];
        
        if (allCheckbox.checked) {
            selectedOptions = ['memory', 'disk', 'database', 'logs'];
        } else {
            optionCheckboxes.forEach(checkbox => {
                if (checkbox.checked) {
                    selectedOptions.push(checkbox.value);
                }
            });
        }
        
        if (selectedOptions.length === 0) {
            document.body.removeChild(overlay);
            return;
        }
        
        document.body.removeChild(overlay);
        
        // Show exit overlay with proper CSS styling
        const exitOverlay = document.createElement('div');
        exitOverlay.className = 'dialog-overlay';
        exitOverlay.style.display = 'flex';
        exitOverlay.style.backgroundColor = 'var(--overlay)';
        exitOverlay.innerHTML = `
            <div class="text-center" style="color: var(--text-color); font-size: 24px;">
                Exiting application...
            </div>
        `;
        document.body.appendChild(exitOverlay);
        
        // Call Python function
        eel.purge_and_exit(selectedOptions)(function(response) {
            const messageDiv = exitOverlay.querySelector('.text-center');
            if (!response.success) {
                messageDiv.textContent = `Error: ${response.error}`;
                setTimeout(() => {
                    messageDiv.textContent = 'Cache has been purged. Application backend has been closed. You can now safely close this tab.';
                }, 2000);
            } else {
                setTimeout(function() {
                    window.close();
                    messageDiv.textContent = 'Cache has been purged. Application backend has been closed. You can now safely close this tab.';
                }, 500);
            }
        });
    });
    
    // Cancel button
    dialog.querySelector('.cancel-button').addEventListener('click', function() {
        document.body.removeChild(overlay);
    });
}

/**
 * Update the log monitoring button state
 */
async function updateLogMonitoringButton() {
    try {
        const status = await eel.get_log_monitoring_status()();
        const monitoringToggle = document.getElementById('log-monitoring-toggle');
        
        if (monitoringToggle) {
            monitoringToggle.checked = status.active;
        }
    } catch (error) {
        console.error('Error checking log monitoring status:', error);
    }
}

/**
 * Sanitize string for safe display in the UI
 * @param {string} unsafe - String that might contain unsafe content
 * @return {string} - Sanitized string safe for textContent
 */
function sanitizeContent(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    return String(unsafe);
}