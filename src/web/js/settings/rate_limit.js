/**
 * Rate Limit settings module for Email Verification Engine
 * Handles configuration of rate limiting features
 */

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

// State for rate limits
const rateLimitState = {
    rateLimits: []
};

/**
 * Load rate limit settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadRateLimitSettings() {
    try {
        const rateLimitsResult = await eel.get_rate_limits()();
        if (rateLimitsResult.success) {
            rateLimitState.rateLimits = rateLimitsResult.settings;
            renderRateLimits();
            return true;
        } else {
            showNotification('error', 'Failed to load rate limits');
            return false;
        }
    } catch (error) {
        console.error('Error loading rate limits:', error);
        showNotification('error', 'An error occurred while loading rate limits');
        return false;
    }
}

/**
 * Render rate limit settings
 */
function renderRateLimits() {
    const container = document.getElementById('rate-limits-settings-content');
    if (!container) return;
    
    // Group settings by category
    const groupedSettings = {};
    rateLimitState.rateLimits.forEach(setting => {
        if (!groupedSettings[setting.category]) {
            groupedSettings[setting.category] = [];
        }
        groupedSettings[setting.category].push(setting);
    });
    
    // Generate HTML for settings
    let html = '';
    for (const category in groupedSettings) {
        html += `<div class="results-container">
                    <h2>${capitalizeFirstLetter(category)} Rate Limits</h2>
                    <div style="display: grid; grid-template-columns: 1fr; gap: 10px;">`;
        
        groupedSettings[category].forEach(setting => {
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="rate">
                    <div style="flex: 1; padding-right: 15px;">
                        <label for="rate-setting-${setting.id}" style="font-weight: bold; color: var,--text-color);">
                            ${setting.name}
                        </label>
                        <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                            ${setting.description}
                        </div>
                        <div style="display: inline-block; font-size: 0.8em; background-color: var(--bg-color); 
                             color: var(--text-color); padding: 2px 6px; border-radius: 10px; margin-top: 5px;">
                            ${setting.is_time ? 'Time (seconds)' : 'Count'}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <input type="number" id="rate-setting-${setting.id}" value="${setting.value}"
                               min="0" ${setting.is_time ? 'step="1"' : 'step="1"'}
                               style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                        <label class="toggle-switch">
                            <input type="checkbox" id="rate-enabled-${setting.id}" 
                                   ${setting.enabled ? "checked" : ""}>
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
 * Save rate limit settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveRateLimitSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save rate limit settings
        const rateSettings = document.querySelectorAll('div[data-type="rate"]');
        for (const settingEl of rateSettings) {
            const id = settingEl.dataset.id;
            const valueEl = document.getElementById(`rate-setting-${id}`);
            const enabledEl = document.getElementById(`rate-enabled-${id}`);
            
            if (!valueEl || !enabledEl) continue;
            
            const value = valueEl.value;
            const enabled = enabledEl.checked;
            
            const result = await eel.update_rate_limit(parseInt(id), value, enabled)();
            result.success ? successCount++ : errorCount++;
        }
    } catch (error) {
        console.error('Error saving rate limit settings:', error);
        showNotification('error', 'An error occurred while saving rate limit settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    showNotification,
    rateLimitState,
    loadRateLimitSettings,
    renderRateLimits,
    saveRateLimitSettings
};