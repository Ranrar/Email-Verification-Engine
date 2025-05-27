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
    
    // Create the menu container - using container class from main css
    const menuContainer = document.createElement('div');
    menuContainer.id = 'debug-menu-container';
    menuContainer.className = 'container';
    menuContainer.style.position = 'fixed';
    menuContainer.style.top = '50px';
    menuContainer.style.right = '10px';
    menuContainer.style.zIndex = '1000';
    menuContainer.style.display = 'none';
    menuContainer.style.maxHeight = '80vh';
    menuContainer.style.overflowY = 'auto';
    menuContainer.style.width = '300px';
    
    // Add the debug menu header - using existing styles
    const menuHeader = document.createElement('div');
    menuHeader.className = 'dialog-title';
    menuHeader.textContent = 'Debug Menu';
    
    // Add close button - using existing button styles
    const closeButton = document.createElement('button');
    closeButton.style.float = 'right';
    closeButton.style.marginTop = '-5px';
    closeButton.innerHTML = '×';
    closeButton.style.fontSize = '20px';
    closeButton.style.padding = '0 5px';
    closeButton.onclick = toggleDebugMenu;
    menuHeader.appendChild(closeButton);
    
    // Create menu content with existing styles
    const menuContent = document.createElement('div');
    menuContent.className = 'dialog-body';
    
    // Add debug options with standard button styling
    menuContent.innerHTML = `
        <div style="margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0; font-size: 14px; border-bottom: 1px solid var(--border-color); padding-bottom: 5px;">Cache Management</h4>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="purge-cache">Purge Cache</button>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="view-cache">View Cache Stats</button>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="purge-exit">Purge & Exit</button>
        </div>
        <div style="margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0; font-size: 14px; border-bottom: 1px solid var(--border-color); padding-bottom: 5px;">System</h4>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="log-viewer">Log Viewer</button>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="system-info">System Info</button>
            
            <!-- Replace button with toggle switch -->
            <div style="display: flex; align-items: center; justify-content: space-between; margin: 10px 0;">
                <span>Log Monitoring</span>
                <label class="toggle-switch">
                    <input type="checkbox" id="log-monitoring-toggle" data-action="toggle-log-monitoring">
                    <span class="toggle-slider round"></span>
                </label>
            </div>
        </div>
        <div style="margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0; font-size: 14px; border-bottom: 1px solid var(--border-color); padding-bottom: 5px;">Test Functions</h4>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="test-mx">Test MX Lookup</button>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="test-smtp">Test SMTP Connection</button>
            <button style="display: block; width: 100%; margin-bottom: 5px;" data-action="test-notification">Test Notifications</button>
        </div>
    `;
    
    // Assemble the menu
    menuContainer.appendChild(menuHeader);
    menuContainer.appendChild(menuContent);
    
    // Add a trigger button in the UI - use standard button but position it
    const triggerButton = document.createElement('button');
    triggerButton.id = 'debug-menu-trigger';
    triggerButton.style.position = 'fixed';
    triggerButton.style.bottom = '20px';
    triggerButton.style.right = '20px';
    triggerButton.style.zIndex = '999';
    triggerButton.style.opacity = '0.8';
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
 * Show a notification using the global notification system
 * @param {string} type_name - The notification type: 'success', 'error', 'warning', 'info'
 * @param {string} message - The message to display
 * @param {boolean} persistent - Whether the notification should persist until clicked
 * @param {string} details - Optional additional details to show on hover
 */
function showDebugNotification(type_name, message, persistent = false, details = null) {
    if (typeof show_message === 'function') {
        // Use the global show_message function exposed by main.js
        // Parameters match notifier.py: type_name, message, persistent, details
        show_message(type_name, message, persistent, details);
    } else {
        // Fallback if show_message isn't available
        console[type_name === 'error' ? 'error' : type_name === 'warning' ? 'warn' : 'log'](message);
        alert(`${type_name.toUpperCase()}: ${message}${details ? '\n' + details : ''}`);
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
            // Success message removed as requested
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
                // We leave this case for compatibility with button clicks if needed
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
    // Create overlay using standard dialog-overlay
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard dialog class
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content using standard dialog components
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body">${message}</div>
        <div class="dialog-buttons">
            <button class="confirm">Confirm</button>
            <button class="cancel">Cancel</button>
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
 * Show a debug prompt to get input with standard dialog styling
 */
function showDebugPrompt(title, defaultValue, onSubmit) {
    // Create overlay using standard dialog-overlay
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard dialog class
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content using standard dialog components
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body">
            <input type="text" style="width: 100%; padding: 8px; border-radius: 3px;" value="${defaultValue || ''}">
        </div>
        <div class="dialog-buttons">
            <button class="confirm">Submit</button>
            <button class="cancel">Cancel</button>
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
 * Show debug message dialog with standard dialog styling
 * Enhanced to better display structured data
 */
function showDebugMessage(title, message) {
    // Create overlay using standard dialog-overlay
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard dialog class - MAKE IT WIDER
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Make dialog wider for System Information
    if (title === 'System Information') {
        dialog.style.maxWidth = '1000px'; // Increased from 700px
        dialog.style.width = '95%';      // Increased from 80%
    } else {
        dialog.style.maxWidth = '700px';
        dialog.style.width = '80%';
    }
    
    // Special formatting for structured data
    let formattedMessage = '';
    
    if (title === 'Cache Statistics' && typeof message === 'object' && message !== null) {
        // Enhanced display for cache statistics
        formattedMessage = `
            <div style="display: flex; flex-wrap: wrap; gap: 10px; justify-content: space-between;">
                ${formatCacheSection('Memory Cache', message.memory, '#4cae4c')}
                ${formatCacheSection('Disk Cache (SQLite)', message.disk, '#FF7043')}
                ${formatCacheSection('PostgreSQL Cache', message.postgres, '#42A5F5')}
            </div>
        `;
    } 
    // New formatting for System Information
    else if (title === 'System Information' && typeof message === 'object' && message !== null) {
        formattedMessage = `
            <div style="display: flex; flex-wrap: nowrap; gap: 10px; overflow-x: auto; padding-bottom: 10px; min-width: 850px;">
                ${formatSystemSection('CPU', {
                    '':message.processor
                }, '#5bc0de')}
                
                ${formatSystemSection('Memory', message.memory, '#4cae4c')}
                
                ${formatSystemSection('Disk', message.disk, '#FF7043')}
                
                ${formatSystemSection('Software', {
                    '':message.platform,
                    'Python': message.python,
                    'Eel Version': message.eel_version || 'Unknown',
                    'Browser': navigator.userAgent.split(' ').slice(-1)[0]
                }, '#9c27b0')}
            </div>
        `;
    }
    else {
        // Default formatting for other messages
        if (typeof message === 'object') {
            formattedMessage = '<pre>' + JSON.stringify(message, null, 2) + '</pre>';
        } else {
            formattedMessage = message;
        }
    }
    
    // Add content using standard dialog components
    dialog.innerHTML = `
        <div class="dialog-title">${title}</div>
        <div class="dialog-body" style="max-height: 70vh; overflow-y: auto;">${formattedMessage}</div>
        <div class="dialog-buttons">
            <button class="confirm">Close</button>
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
 * Format a system information section with the same style as cache sections
 */
// Update the formatSystemSection function to handle empty keys
function formatSystemSection(title, data, color) {
    if (!data) {
        return `
            <div style="flex: 1 1 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px;">
                <h3 style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px;">${title}</h3>
                <p>No data available</p>
            </div>
        `;
    }
    
    // Convert the data object to a series of stat-rows
    let content = '';
    
    if (typeof data === 'object') {
        Object.entries(data).forEach(([key, value]) => {
            // Only add the colon if the key is not empty
            const keyDisplay = key ? `${key}:` : '';
            
            content += `
                <div class="stat-row">
                    <span>${keyDisplay}</span>
                    <strong>${value}</strong>
                </div>
            `;
        });
    }
    
    return `
        <div style="flex: 1 1 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px; min-width: 200px;">
            <h3 style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px;">${title}</h3>
            <style>
                .stat-row {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 5px;
                    padding: 3px 0;
                    border-bottom: 1px dotted rgba(0,0,0,0.1);
                }
            </style>
            ${content}
        </div>
    `;
}

/**
 * Format a cache section for the Cache Statistics display
 */
function formatCacheSection(title, data, color) {
    if (!data) {
        return `
            <div style="flex: 1 1 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px;">
                <h3 style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px;">${title}</h3>
                <p>No data available</p>
            </div>
        `;
    }
    
    if (data.error) {
        return `
            <div style="flex: 1 1 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px;">
                <h3 style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px;">${title}</h3>
                <p style="color: red;">Error: ${data.error}</p>
            </div>
        `;
    }
    
    // Convert the data object to a series of stat-rows
    let content = '';
    
    // Special handling for PostgreSQL categories
    if (title === 'PostgreSQL Cache' && data.categories && data.categories.length > 0) {
        // Main stats first
        content += `
            <div class="stat-row"><span>Total Entries:</span> <strong>${data.total_entries || 0}</strong></div>
            <div class="stat-row"><span>Valid Entries:</span> <strong>${data.valid_entries || 0}</strong></div>
            <div class="stat-row"><span>Expired Entries:</span> <strong>${data.expired_entries || 0}</strong></div>
            <div class="stat-row"><span>Size:</span> <strong>${data.size_pretty || '0 bytes'}</strong></div>
        `;
        
        // Then categories
        content += '<div class="stat-group"><h4 style="margin: 10px 0 5px 0;">Categories</h4>';
        data.categories.forEach(cat => {
            content += `<div class="stat-row"><span>${cat.category || 'unnamed'}:</span> <strong>${cat.count || 0}</strong></div>`;
        });
        content += '</div>';
    } else {
        // Generic cache stats display
        if (data.size !== undefined) {
            content += `<div class="stat-row"><span>Size:</span> <strong>${data.size}</strong></div>`;
        }
        if (data.max_size !== undefined) {
            content += `<div class="stat-row"><span>Max Size:</span> <strong>${data.max_size}</strong></div>`;
        }
        if (data.utilization !== undefined) {
            content += `<div class="stat-row"><span>Utilization:</span> <strong>${data.utilization}</strong></div>`;
        }
        if (data.total_entries !== undefined) {
            content += `<div class="stat-row"><span>Total Entries:</span> <strong>${data.total_entries}</strong></div>`;
        }
        if (data.valid_entries !== undefined) {
            content += `<div class="stat-row"><span>Valid Entries:</span> <strong>${data.valid_entries}</strong></div>`;
        }
        if (data.expired_entries !== undefined) {
            content += `<div class="stat-row"><span>Expired Entries:</span> <strong>${data.expired_entries}</strong></div>`;
        }
        if (data.size_mb !== undefined) {
            content += `<div class="stat-row"><span>Size:</span> <strong>${data.size_mb}</strong></div>`;
        }
    }
    
    return `
        <div style="flex: 1 1 200px; border: 1px solid var(--border-color); border-radius: 5px; padding: 12px; margin-bottom: 10px; min-width: 200px;">
            <h3 style="margin-top: 0; border-bottom: 2px solid ${color}; padding-bottom: 5px;">${title}</h3>
            <style>
                .stat-row {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 5px;
                    padding: 3px 0;
                    border-bottom: 1px dotted rgba(0,0,0,0.1);
                }
                .stat-group {
                    margin-top: 10px;
                    padding-top: 5px;
                    border-top: 1px solid rgba(0,0,0,0.1);
                }
            </style>
            ${content}
        </div>
    `;
}

/**
 * Show debug log viewer with filterable logs
 */
function showDebugLogViewer(logs) {
    // Create overlay using standard dialog-overlay
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard dialog class but make it larger
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    dialog.style.width = '800px'; // Slightly wider
    dialog.style.height = '80vh';
    dialog.style.maxWidth = '90%';
    
    // Get today's date in YYYY-MM-DD format for default selection
    const today = new Date().toISOString().split('T')[0];
    
    // Create log viewer content - simplified layout without file list panel
    dialog.innerHTML = `
        <div class="dialog-title">Log Viewer</div>
        <div style="padding: 10px; background-color: var(--results-container-bg); border-bottom: 1px solid var(--border-color); display: flex;">
            <select id="log-date-select" style="margin-right: 10px; padding: 5px; border: 1px solid var(--border-color); border-radius: 3px;">
                <option value="${today}">${today}</option>
                <!-- Additional dates will be loaded dynamically -->
            </select>
            <select id="log-level-select" style="margin-right: 10px; padding: 5px; border: 1px solid var(--border-color); border-radius: 3px;">
                <option value="all">All Levels</option>
                <option value="error">Errors</option>
                <option value="warning">Warnings</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
                <option value="email">Email</option>
                <option value="sql">SQL</option>
                <option value="stats">Stats</option>
            </select>
            <input type="text" id="log-search" placeholder="Search logs..." style="flex: 1; margin-right: 10px; padding: 5px; border: 1px solid var(--border-color); border-radius: 3px;">
            <button id="log-refresh" class="refresh-button">Refresh</button>
        </div>
        <div class="dialog-body" style="height: 60vh; overflow-y: auto; background-color: var(--results-container-bg); font-family: monospace; padding: 10px;">
            <div id="log-content">
                <p style="text-align: center;">Loading logs...</p>
            </div>
        </div>
        <div class="dialog-buttons">
            <button class="confirm">Close</button>
        </div>
    `;
    
    // Add event listeners
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup elements
    const dateSelect = document.getElementById('log-date-select');
    const logLevel = document.getElementById('log-level-select');
    const logSearch = document.getElementById('log-search');
    const logRefresh = document.getElementById('log-refresh');
    const logContent = document.getElementById('log-content');
    
    // Setup close button
    dialog.querySelector('.confirm').addEventListener('click', () => {
        document.body.removeChild(overlay);
    });
    
    // State to track current log data
    let currentDate = today;
    let currentLevel = 'all';
    let originalLogContent = '';
    let rawLogLines = [];  // Store raw log lines
    let availableDates = [];
    
    // Initial load of log files and dates
    loadAvailableLogs();
    
    // Handle date selection changes
    dateSelect.addEventListener('change', function() {
        currentDate = this.value;
        loadLogByLevelAndDate();
    });
    
    // Handle log level selection changes
    logLevel.addEventListener('change', function() {
        currentLevel = this.value;
        loadLogByLevelAndDate();
    });
    
    // Handle search filtering
    logSearch.addEventListener('input', filterLogContent);
    
    // Handle refresh button
    logRefresh.addEventListener('click', () => {
        loadAvailableLogs();
    });
    
    /**
     * Load available log files and dates
     */
    async function loadAvailableLogs() {
        try {
            // Show loading state
            logContent.innerHTML = '<p style="text-align: center;">Loading logs...</p>';
            
            // Get log files list
            const result = await eel.debug_action('get-logs')();
            
            // If we got a structured response with files
            if (result && typeof result === 'object' && result.files && result.files.length > 0) {
                // Extract available dates from log files
                availableDates = [...new Set(result.files.map(file => file.date))].sort().reverse();
                
                // Update date dropdown
                dateSelect.innerHTML = availableDates.map(date => 
                    `<option value="${date}" ${date === currentDate ? 'selected' : ''}>${date}</option>`
                ).join('');
                
                // Update current date if necessary
                if (!availableDates.includes(currentDate)) {
                    currentDate = availableDates[0];
                }
                
                // Load the log for the current level and date
                loadLogByLevelAndDate();
            } else {
                logContent.innerHTML = '<p style="text-align: center;">No log files found</p>';
            }
        } catch (error) {
            logContent.innerHTML = `<p style="color: red;">Error loading logs: ${error.message}</p>`;
        }
    }
    
    /**
     * Load log file based on selected level and date
     */
    async function loadLogByLevelAndDate() {
        try {
            // Show loading state
            logContent.innerHTML = `<p style="text-align: center;">Loading ${currentLevel} logs for ${currentDate}...</p>`;
            
            // Construct filename based on level and date
            let filename;
            if (currentLevel === 'all') {
                // For "All Levels", load whatever log is available, prioritizing info
                const priorities = ['info', 'debug', 'warning', 'error', 'email', 'stats', 'sql'];
                
                // Try to load logs in order of priority
                for (const level of priorities) {
                    const testFilename = `${level}.${currentDate}.log`;
                    try {
                        const testResult = await eel.debug_action('get-logs', testFilename)();
                        if (!testResult.error) {
                            filename = testFilename;
                            break;
                        }
                    } catch (e) {
                        console.log(`Log file ${testFilename} not available`);
                    }
                }
                
                // If no file was found
                if (!filename) {
                    logContent.innerHTML = `<p style="text-align: center;">No log files found for ${currentDate}</p>`;
                    return;
                }
            } else {
                // For specific level, construct filename directly
                filename = `${currentLevel}.${currentDate}.log`;
            }
            
            // Get log file content
            const result = await eel.debug_action('get-logs', filename)();
            
            if (result.error) {
                logContent.innerHTML = `<p style="color: red;">Error: ${result.error}</p>`;
                return;
            }
            
            // Store original content for filtering
            originalLogContent = result.content || '';
            rawLogLines = originalLogContent.split('\n').filter(line => line.trim());
            
            // Format and display the log content
            formatAndDisplayLogContent(rawLogLines);
            
            // Apply any search filter
            filterLogContent();
        } catch (error) {
            logContent.innerHTML = `<p style="color: red;">Error loading log file: ${error.message}</p>`;
        }
    }
    
    /**
     * Format and display log content in a human-readable way
     */
    function formatAndDisplayLogContent(logLines) {
        // Reverse the array to show newest entries at the top
        const reversedLines = [...logLines].reverse();
        
        // Create a formatted HTML output
        const formattedLines = reversedLines.map(line => {
            try {
                if (!line.trim()) return '';
                
                // Parse JSON log entry
                const logEntry = JSON.parse(line);
                
                // Different log level colors
                const levelColors = {
                    '[ERROR]': '#ff5252',
                    '[WARNING]': '#ffb142',
                    '[INFO]': '#2ed573',
                    '[DEBUG]': '#70a1ff',
                    '[EMAIL]': '#9b59b6',
                    '[SQL]': '#795548',
                    '[STATS]': '#607d8b'
                };
                
                // Get level color or default to gray
                const levelText = logEntry.level || '';
                const levelColor = levelColors[levelText.trim()] || '#808e9b';
                
                // Format the log entry in a human-readable way
                const timestamp = `<span style="color: #7f8c8d;">${logEntry.timestamp}</span>`;
                
                // Format level differently depending on if we're in split logs mode
                const level = logEntry.level 
                    ? `<span style="color: ${levelColor};">${logEntry.level}</span> ` 
                    : '';
                
                const module = logEntry.module 
                    ? `<span style="color: #3498db;">${logEntry.module}</span>.` 
                    : '';
                
                const func = logEntry.function 
                    ? `<span style="color: #2ecc71;">${logEntry.function}</span>` 
                    : '';
                
                const location = (logEntry.file && logEntry.line) 
                    ? `<span style="color: #7f8c8d; font-size: 0.9em;"> (${logEntry.file}:${logEntry.line})</span>` 
                    : '';
                
                // Special handling for message depending on if it might be a stringified object
                let message = '';
                if (logEntry.message) {
                    if (typeof logEntry.message === 'string' && 
                        (logEntry.message.startsWith('{') || logEntry.message.startsWith('['))) {
                        try {
                            // Try to parse and format as JSON
                            const msgObj = JSON.parse(logEntry.message);
                            message = `<span style="color: #ecf0f1;">${JSON.stringify(msgObj, null, 2)}</span>`;
                        } catch (e) {
                            // Just display as regular message
                            message = `<span style="color: #ecf0f1;">${logEntry.message}</span>`;
                        }
                    } else {
                        message = `<span style="color: #ecf0f1;">${logEntry.message}</span>`;
                    }
                }
                
                // Format exception info if present
                const exception = logEntry.exception
                    ? `<div style="color: #ff4757; margin-top: 3px; margin-left: 15px; border-left: 2px solid #ff4757; padding-left: 5px;">${logEntry.exception}</div>`
                    : '';
                
                // Return formatted log entry
                return `<div class="log-entry" data-raw='${JSON.stringify(logEntry)}' style="padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    ${timestamp} ${level}${module}${func}: ${message}${location}${exception}
                </div>`;
            } catch (e) {
                // If parsing fails, return the raw line
                return `<div style="padding: 3px 0;">${line}</div>`;
            }
        });
        
        // Update content
        logContent.innerHTML = formattedLines.join('');
        
        // Add click event to toggle between formatted and raw display
        document.querySelectorAll('.log-entry').forEach(entry => {
            entry.addEventListener('click', function() {
                try {
                    const rawData = JSON.parse(this.getAttribute('data-raw'));
                    
                    // Toggle between raw and formatted view
                    if (this.classList.contains('raw-view')) {
                        // Restore formatted view
                        this.innerHTML = formatLogEntry(rawData);
                        this.classList.remove('raw-view');
                    } else {
                        // Show raw view
                        this.innerHTML = `<pre style="margin: 0;">${JSON.stringify(rawData, null, 2)}</pre>`;
                        this.classList.add('raw-view');
                    }
                } catch (e) {
                    console.error('Error toggling log entry format', e);
                }
            });
        });
    }
    
    /**
     * Format a single log entry
     */
    function formatLogEntry(logEntry) {
        const levelColors = {
            '[ERROR]': '#ff5252',
            '[WARNING]': '#ffb142',
            '[INFO]': '#2ed573',
            '[DEBUG]': '#70a1ff',
            '[EMAIL]': '#9b59b6',
            '[SQL]': '#795548',
            '[STATS]': '#607d8b'
        };
        
        // Get level color or default to gray
        const levelText = logEntry.level || '';
        const levelColor = levelColors[levelText.trim()] || '#808e9b';
        
        // Format the log entry in a human-readable way
        const timestamp = `<span style="color: #7f8c8d;">${logEntry.timestamp}</span>`;
        
        // Format level differently depending on if we're in split logs mode
        const level = logEntry.level 
            ? `<span style="color: ${levelColor};">${logEntry.level}</span> ` 
            : '';
        
        const module = logEntry.module 
            ? `<span style="color: #3498db;">${logEntry.module}</span>.` 
            : '';
        
        const func = logEntry.function 
            ? `<span style="color: #2ecc71;">${logEntry.function}</span>` 
            : '';
        
        const location = (logEntry.file && logEntry.line) 
            ? `<span style="color: #7f8c8d; font-size: 0.9em;"> (${logEntry.file}:${logEntry.line})</span>` 
            : '';
        
        let message = '';
        if (logEntry.message) {
            if (typeof logEntry.message === 'string' && 
                (logEntry.message.startsWith('{') || logEntry.message.startsWith('['))) {
                try {
                    const msgObj = JSON.parse(logEntry.message);
                    message = `<span style="color: #ecf0f1;">${JSON.stringify(msgObj, null, 2)}</span>`;
                } catch (e) {
                    message = `<span style="color: #ecf0f1;">${logEntry.message}</span>`;
                }
            } else {
                message = `<span style="color: #ecf0f1;">${logEntry.message}</span>`;
            }
        }
        
        const exception = logEntry.exception
            ? `<div style="color: #ff4757; margin-top: 3px; margin-left: 15px; border-left: 2px solid #ff4757; padding-left: 5px;">${logEntry.exception}</div>`
            : '';
        
        return `${timestamp} ${level}${module}${func}: ${message}${location}${exception}`;
    }
    
    /**
     * Filter log content based on search input
     */
    function filterLogContent() {
        const search = logSearch.value.toLowerCase();
        
        // If no content to filter
        if (rawLogLines.length === 0) {
            return;
        }
        
        // Apply search filter
        const filteredLines = rawLogLines.filter(line => {
            // Skip empty lines
            if (!line.trim()) return false;
            
            // Apply search filter
            return !search || line.toLowerCase().includes(search);
        });
        
        // Format and display filtered content
        formatAndDisplayLogContent(filteredLines);
    }
}

/**
 * Show a dialog with purge options
 */
function showPurgeDialog() {
    // Create overlay using standard dialog-overlay
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.style.display = 'flex';
    
    // Create dialog using standard dialog class
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    // Add content using standard dialog components
    dialog.innerHTML = `
        <div class="dialog-title">Cache Purge & Exit</div>
        <div class="dialog-body">
            <p>Select items to purge before exit:</p>
            <div style="margin: 10px 0;">
                <label style="display: block; margin-bottom: 8px;">
                    <input type="checkbox" value="all" id="purge-all" checked> 
                    <strong>ALL</strong>
                </label>
                <label style="display: block; margin-bottom: 8px;">
                    <input type="checkbox" value="memory" class="purge-option" checked> 
                    Memory Cache (RAM)
                </label>
                <label style="display: block; margin-bottom: 8px;">
                    <input type="checkbox" value="disk" class="purge-option" checked> 
                    Disk Cache (.cache/cache.db)
                </label>
                <label style="display: block; margin-bottom: 8px;">
                    <input type="checkbox" value="database" class="purge-option" checked> 
                    Database Cache (PostgreSQL)
                </label>
                <label style="display: block; margin-bottom: 8px;">
                    <input type="checkbox" value="logs" class="purge-option" checked> 
                    Log Files (logs/*.log)
                </label>
            </div>
        </div>
        <div class="dialog-buttons">
            <button class="purge-button">Purge & Exit</button>
            <button class="cancel-button">Cancel</button>
        </div>
    `;
    
    // Add event listeners
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    
    // Setup checkboxes logic
    const allCheckbox = dialog.querySelector('#purge-all');
    const optionCheckboxes = dialog.querySelectorAll('.purge-option');
    
    // When "ALL" is clicked, update other checkboxes
    allCheckbox.addEventListener('change', function() {
        optionCheckboxes.forEach(checkbox => {
            checkbox.checked = allCheckbox.checked;
        });
    });
    
    // When individual options change, update "ALL" checkbox
    optionCheckboxes.forEach(checkbox => {
        checkbox.checked = true; // Ensure all are checked by default
        checkbox.addEventListener('change', function() {
            // If any option is unchecked, uncheck "ALL"
            if (!this.checked) {
                allCheckbox.checked = false;
            }
            
            // If all options are checked, check "ALL"
            if (Array.from(optionCheckboxes).every(cb => cb.checked)) {
                allCheckbox.checked = true;
            }
        });
    });
    
    // Setup purge button
    dialog.querySelector('.purge-button').addEventListener('click', function() {
        // Get selected options
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
            // If nothing selected, just close
            document.body.removeChild(overlay);
            return;
        }
        
        // Close the dialog
        document.body.removeChild(overlay);
        
        // Show exit overlay (same style as in main.js)
        const exitOverlay = document.createElement('div');
        exitOverlay.style.position = 'fixed';
        exitOverlay.style.top = 0;
        exitOverlay.style.left = 0;
        exitOverlay.style.width = '100%';
        exitOverlay.style.height = '100%';
        exitOverlay.style.backgroundColor = 'rgba(0,0,0,0.8)';
        exitOverlay.style.zIndex = 1000;
        exitOverlay.style.display = 'flex';
        exitOverlay.style.justifyContent = 'center';
        exitOverlay.style.alignItems = 'center';
        exitOverlay.style.color = '#fff';
        exitOverlay.style.fontSize = '24px';
        exitOverlay.textContent = 'Exiting application...';
        document.body.appendChild(exitOverlay);
        
        // Call Python function to do the purging and exit
        eel.purge_and_exit(selectedOptions)(function(response) {
            if (!response.success) {
                // Update the overlay message for error
                exitOverlay.textContent = `Error: ${response.error}`;
                // Allow user to close manually
                setTimeout(() => {
                    exitOverlay.textContent = 'Cache bas been purged, Application backend has been closed. You can now safely close this tab.';
                }, 2000);
            } else {
                // Try to close the window after a short delay (same as main.js)
                setTimeout(function() {
                    window.close();
                    
                    // If window.close() fails due to browser security
                    exitOverlay.textContent = 'Cache bas been purged, Application backend has been closed. You can now safely close this tab.';
                }, 500);
            }
        });
    });
    
    // Setup cancel button
    dialog.querySelector('.cancel-button').addEventListener('click', function() {
        document.body.removeChild(overlay);
    });
}

/**
 * Update the log monitoring button state based on current status
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