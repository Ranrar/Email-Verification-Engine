/**
 * Ports Configuration module for Email Verification Engine
 * Handles port settings for different connection types
 */

/**
 * Get current theme for applying theme-specific classes
 */
function getCurrentTheme() {
    // Use the global function if available, otherwise fallback
    if (window.getCurrentTheme) {
        return window.getCurrentTheme();
    }
    return document.documentElement.getAttribute('data-theme') || 'light';
}

// Import shared utilities if needed
// import { capitalizeFirstLetter, showNotification } from './utils.js';

/**
 * Capitalize the first letter of a string
 * @param {string} string - The string to capitalize
 * @return {string} The capitalized string
 */
function capitalizeFirstLetter(string) {
    if (!string) return '';
    return string.charAt(0).toUpperCase() + string.slice(1);
}

/**
 * Show a notification to the user
 * @param {string} type_name - The notification type: 'success', 'error', 'warning', 'info'
 * @param {string} message - The message to display
 * @param {boolean} persistent - Whether the notification should persist until clicked
 * @param {string} details - Optional additional details to show on hover
 */
function showNotification(type_name, message, persistent = false, details = null) {
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

// Port-specific state
const portState = {
    portsConfiguration: []
};

/**
 * Load ports configuration from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadPortsConfiguration() {
    try {
        const portsResult = await eel.get_ports_configuration()();
        if (portsResult.success) {
            portState.portsConfiguration = portsResult.settings;
            renderPortsConfiguration();
            return true;
        } else {
            showNotification('error', 'Failed to load ports configuration');
            return false;
        }
    } catch (error) {
        console.error('Error loading ports configuration:', error);
        showNotification('error', 'An error occurred while loading ports configuration');
        return false;
    }
}

/**
 * Render ports configuration
 */
function renderPortsConfiguration() {
    const container = document.getElementById('ports-configuration-content');
    if (!container) return;
    
    // Group by category
    const groupedPorts = {};
    portState.portsConfiguration.forEach(port => {
        if (!groupedPorts[port.category]) {
            groupedPorts[port.category] = [];
        }
        groupedPorts[port.category].push(port);
    });
    
    let html = '';
    for (const category in groupedPorts) {
        html += `<div class="results-container">
                    <h2>${capitalizeFirstLetter(category)} Ports</h2>
                    <div style="display: grid; grid-template-columns: 1fr; gap: 10px;">`;
        
        groupedPorts[category].forEach(port => {
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${port.id}" data-type="port">
                    <div style="flex: 1; padding-right: 15px;">
                        <label style="font-weight: bold; color: var(--text-color);">
                            Port ${port.port}
                        </label>
                        <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                            ${port.description}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center;">
                        <label for="port-enabled-${port.id}" style="margin-right: 8px;">Enabled</label>
                        <label class="toggle-switch">
                            <input type="checkbox" id="port-enabled-${port.id}" 
                                   ${port.enabled ? "checked" : ""}>
                            <span class="toggle-slider round"></span>
                        </label>
                    </div>
                </div>
            `;
        });
        
        html += `</div></div>`;
    }
    
    container.innerHTML = html;
}

/**
 * Save ports configuration
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function savePortsConfiguration() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save port settings
        const portSettings = document.querySelectorAll('div[data-type="port"]');
        for (const settingEl of portSettings) {
            const id = settingEl.dataset.id;
            const enabledEl = document.getElementById(`port-enabled-${id}`);
            
            if (!enabledEl) continue;
            
            const enabled = enabledEl.checked;
            
            // Keep existing priority value by passing 0 (server will preserve current value)
            const result = await eel.update_port(parseInt(id), 0, enabled)();
            result.success ? successCount++ : errorCount++;
        }
    } catch (error) {
        console.error('Error saving port settings:', error);
        showNotification('error', 'An error occurred while saving port settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

/**
 * Update theme classes when theme changes
 */
function updatePortTheme() {
    // Re-apply any theme-specific styling
    const theme = getCurrentTheme();
    // Update any module-specific theme classes here if needed
}

// Listen for theme changes
document.addEventListener('themeChanged', updatePortTheme);

// Expose functions and state to the global window object
window.loadPortsConfiguration = loadPortsConfiguration;
window.savePortsConfiguration = savePortsConfiguration;
window.renderPortsConfiguration = renderPortsConfiguration;
window.portState = portState;