/**
 * Rate Limit settings module for Email Verification Engine
 * Handles configuration of rate limiting features
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
                    <div class="grid-1col">`;
        
        groupedSettings[category].forEach(setting => {
            html += `
                <div class="settings-item p-10 flex justify-space-between align-center" 
                     data-id="${setting.id}" data-type="rate">
                    <div class="flex-1 pr-15">
                        <label for="rate-setting-${setting.id}" class="settings-label">
                            ${setting.name}
                        </label>
                        <div class="text-muted mt-5">
                            ${setting.description}
                        </div>
                        <div class="mt-5">
                            <span class="input-label">
                                ${setting.is_time ? 'Time (seconds)' : 'Count'}
                            </span>
                        </div>
                    </div>
                    <div class="flex align-center gap-10">
                        <div class="number-input-group">
                            <input type="number" id="rate-setting-${setting.id}" value="${setting.value}"
                                   min="0" ${setting.is_time ? 'step="1"' : 'step="1"'}
                                   class="rate-setting-input">
                            <button type="button" class="number-btn" onclick="incrementValue('rate-setting-${setting.id}')">+</button>
                            <button type="button" class="number-btn" onclick="decrementValue('rate-setting-${setting.id}')">−</button>
                        </div>
                        <div class="checkbox-wrapper" style="padding-left: 8px;">
                            <input type="checkbox" id="rate-enabled-${setting.id}" 
                                   ${setting.enabled ? "checked" : ""}>
                            <label for="rate-enabled-${setting.id}">Enabled</label>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += `</div></div>`;
    }
    
    container.innerHTML = html;
}

/**
 * Increment number input value
 */
function incrementValue(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        const currentValue = parseInt(input.value) || 0;
        const step = parseInt(input.step) || 1;
        input.value = currentValue + step;
        input.dispatchEvent(new Event('change'));
    }
}

/**
 * Decrement number input value
 */
function decrementValue(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        const currentValue = parseInt(input.value) || 0;
        const step = parseInt(input.step) || 1;
        const min = parseInt(input.min) || 0;
        const newValue = Math.max(min, currentValue - step);
        input.value = newValue;
        input.dispatchEvent(new Event('change'));
    }
}

// Make functions global so they can be called from HTML
window.incrementValue = incrementValue;
window.decrementValue = decrementValue;

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

/**
 * Update theme classes when theme changes
 */
function updateRateLimitTheme() {
    // Re-apply any theme-specific styling
    const theme = getCurrentTheme();
    // Update any module-specific theme classes here if needed
}

// Listen for theme changes
document.addEventListener('themeChanged', updateRateLimitTheme);

// Expose functions and state to the global window object
window.loadRateLimitSettings = loadRateLimitSettings;
window.saveRateLimitSettings = saveRateLimitSettings;
window.renderRateLimits = renderRateLimits;
window.rateLimitState = rateLimitState;