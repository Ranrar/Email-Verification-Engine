/**
 * DNS Settings module for Email Verification Engine
 * Handles DNS server configuration and related settings
 */

// Import shared utilities if needed
// import { capitalizeFirstLetter, formatSettingName, showNotification } from './utils.js';

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
 * Format a setting name for display
 * @param {string} name - The setting name (often in snake_case)
 * @return {string} Formatted setting name
 */
function formatSettingName(name) {
    if (!name) return '';
    return name
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
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

// DNS-specific state
const dnsState = {
    dnsSettings: []
};

/**
 * Load DNS settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadDNSSettings() {
    try {
        const dnsSettingsResult = await eel.get_dns_settings()();
        if (dnsSettingsResult.success) {
            dnsState.dnsSettings = dnsSettingsResult.settings;
            renderDNSSettings();
            return true;
        } else {
            showNotification('error', 'Failed to load DNS settings');
            return false;
        }
    } catch (error) {
        console.error('Error loading DNS settings:', error);
        showNotification('error', 'An error occurred while loading DNS settings');
        return false;
    }
}

/**
 * Render DNS settings
 */
function renderDNSSettings() {
    const container = document.getElementById('dns-settings-content');
    if (!container) return;
    
    let html = '<div class="results-container"><h2>DNS Configuration</h2><div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    dnsState.dnsSettings.forEach(setting => {
        if (setting.name === 'nameservers') {
            // Special handling for nameservers (textarea)
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="dns">
                    <div style="flex: 1; padding-right: 15px;">
                        <label for="dns-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                            DNS Nameservers
                        </label>
                        <div style="font-size: 0.9em; color: var,--text-muted); margin-top: 5px;">
                            ${setting.description}
                        </div>
                    </div>
                    <div>
                        <textarea id="dns-setting-${setting.id}" rows="4"
                            style="width: 250px; padding: 8px; border: 1px solid var(--results-container-border); 
                            border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.value}</textarea>
                    </div>
                </div>
            `;
        } else if (setting.value === "0" || setting.value === "1") {
            // Toggle for boolean settings
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="dns">
                    <div style="flex: 1; padding-right: 15px;">
                        <label for="dns-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                            ${formatSettingName(setting.name)}
                        </label>
                        <div style="font-size: 0.9em; color: var,--text-muted); margin-top: 5px;">
                            ${setting.description}
                        </div>
                        <div style="display: inline-block; font-size: 0.8em; background-color: var(--bg-color); 
                             color: var(--text-color); padding: 2px 6px; border-radius: 10px; margin-top: 5px;">
                            ${setting.is_time ? 'Time (seconds)' : 'Boolean'}
                        </div>
                    </div>
                    <div>
                        <label class="toggle-switch">
                            <input type="checkbox" id="dns-setting-${setting.id}" 
                                   ${setting.value === "1" ? "checked" : ""}>
                            <span class="toggle-slider round"></span>
                        </label>
                    </div>
                </div>
            `;
        } else {
            // Regular number input for other settings
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="dns">
                    <div style="flex: 1; padding-right: 15px;">
                        <label for="dns-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                            ${formatSettingName(setting.name)}
                        </label>
                        <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                            ${setting.description}
                        </div>
                        <div style="display: inline-block; font-size: 0.8em; background-color: var(--bg-color); 
                             color: var,--text-color); padding: 2px 6px; border-radius: 10px; margin-top: 5px;">
                            ${setting.is_time ? 'Time (seconds)' : 'Value'}
                        </div>
                    </div>
                    <div>
                        <input type="number" id="dns-setting-${setting.id}" value="${setting.value}"
                               min="0" ${setting.is_time ? 'step="1"' : 'step="1"'}
                               style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    </div>
                </div>
            `;
        }
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
}

/**
 * Save DNS settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveDNSSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save DNS settings
        const dnsSettings = document.querySelectorAll('div[data-type="dns"]');
        for (const settingEl of dnsSettings) {
            const id = settingEl.dataset.id;
            const inputEl = document.getElementById(`dns-setting-${id}`);
            
            if (!inputEl) continue;
            
            let value;
            if (inputEl.type === 'checkbox') {
                value = inputEl.checked ? "1" : "0";
            } else {
                value = inputEl.value;
            }
            
            const result = await eel.update_dns_setting(parseInt(id), value)();
            result.success ? successCount++ : errorCount++;
        }
    } catch (error) {
        console.error('Error saving DNS settings:', error);
        showNotification('error', 'An error occurred while saving DNS settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    formatSettingName,
    showNotification,
    dnsState,
    loadDNSSettings,
    renderDNSSettings,
    saveDNSSettings
};