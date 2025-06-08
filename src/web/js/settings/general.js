/**
 * General settings module for Email Verification Engine
 * Handles application-wide general settings
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
        show_message(type_name, message, persistent, details);
    } else {
        console[type_name === 'error' ? 'error' : type_name === 'warning' ? 'warn' : 'log'](message);
        alert(`${type_name.toUpperCase()}: ${message}${details ? '\n' + details : ''}`);
    }
}

// State specific to general settings
const generalState = {
    appSettings: []
};

/**
 * Load general application settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadGeneralSettings() {
    try {
        const appSettingsResult = await eel.get_app_settings()();
        if (appSettingsResult.success) {
            generalState.appSettings = appSettingsResult.settings;
            renderAppSettings();
            return true;
        } else {
            showNotification('error', 'Failed to load application settings');
            return false;
        }
    } catch (error) {
        console.error('Error loading general settings:', error);
        showNotification('error', 'An error occurred while loading general settings');
        return false;
    }
}

/**
 * Render application settings
 */
function renderAppSettings() {
    const container = document.getElementById('general-settings-content');
    if (!container) return;
    
    // Group settings by category and sub-category
    const groupedSettings = {};
    generalState.appSettings.forEach(setting => {
        if (!groupedSettings[setting.category]) {
            groupedSettings[setting.category] = {};
        }
        if (!groupedSettings[setting.category][setting.sub_category]) {
            groupedSettings[setting.category][setting.sub_category] = [];
        }
        groupedSettings[setting.category][setting.sub_category].push(setting);
    });
    
    // Fields that should be read-only (cannot be edited by user)
    const readOnlyFields = ['name', 'url', 'version'];
    
    // Generate HTML for settings
    let html = '';
    for (const category in groupedSettings) {
        html += `<div class="results-container">
                    <h2>${capitalizeFirstLetter(category)}</h2>`;
        
        for (const subCategory in groupedSettings[category]) {
            html += `<div style="margin-left: 15px; margin-bottom: 20px;">
                        <h3 style="color: var(--text-color);">${capitalizeFirstLetter(subCategory)}</h3>
                        <div style="display: grid; grid-template-columns: 1fr; gap: 10px;">`;
            
            groupedSettings[category][subCategory].forEach(setting => {
                // Check if this is a read-only field
                const isReadOnly = readOnlyFields.includes(setting.name.toLowerCase());
                
                if (isReadOnly) {
                    // Render as read-only text display - matching normal text styling
                    html += `
                        <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); border-radius: 5px; margin-bottom: 5px;">
                            <div style="flex: 1; padding-right: 15px;">
                                <label style="font-weight: bold; color: var(--text-color);">${setting.name}</label>
                                <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">${setting.description}</div>
                                <div style="display: inline-block; font-size: 0.8em; background-color: var(--bg-color); 
                                     color: var(--text-color); padding: 2px 6px; border-radius: 10px; margin-top: 5px;">
                                    Read-Only
                                </div>
                            </div>
                            <div style="display: flex; align-items: center;">
                                <span style="color: var(--text-color); font-size: 1em;">${setting.value}</span>
                            </div>
                        </div>
                    `;
                } else {
                    // Determine if this should be a toggle (0/1) or text input
                    const isToggle = setting.value === "0" || setting.value === "1";
                    
                    if (isToggle) {
                        html += `
                            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="app">
                                <div style="flex: 1; padding-right: 15px;">
                                    <label for="app-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">${setting.name}</label>
                                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">${setting.description}</div>
                                </div>
                                <div>
                                    <label class="toggle-switch">
                                        <input type="checkbox" id="app-setting-${setting.id}" 
                                               ${setting.value === "1" ? "checked" : ""}>
                                        <span class="toggle-slider round"></span>
                                    </label>
                                </div>
                            </div>
                        `;
                    } else {
                        html += `
                            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="app">
                                <div style="flex: 1; padding-right: 15px;">
                                    <label for="app-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">${setting.name}</label>
                                    <div style="font-size: 0.9em; color: var,--text-muted); margin-top: 5px;">${setting.description}</div>
                                </div>
                                <div>
                                    <input type="text" id="app-setting-${setting.id}" value="${setting.value}" 
                                        style="width: 150px; padding: 8px; border: 1px solid var(--results-container-border); 
                                        border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                                </div>
                            </div>
                        `;
                    }
                }
            });
            
            html += `</div></div>`;
        }
        
        html += `</div>`;
    }
    
    container.innerHTML = html;
}

/**
 * Save general settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveGeneralSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save app settings
        const appSettings = document.querySelectorAll('div[data-type="app"]');
        for (const settingEl of appSettings) {
            const id = settingEl.dataset.id;
            const inputEl = document.getElementById(`app-setting-${id}`);
            
            if (!inputEl) continue;
            
            if (inputEl.type === 'checkbox') {
                const value = inputEl.checked ? "1" : "0";
                const result = await eel.update_app_setting(parseInt(id), value)();
                result.success ? successCount++ : errorCount++;
            } else {
                const value = inputEl.value;
                const result = await eel.update_app_setting(parseInt(id), value)();
                result.success ? successCount++ : errorCount++;
            }
        }
    } catch (error) {
        console.error('Error saving general settings:', error);
        showNotification('error', 'An error occurred while saving general settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

/**
 * Update theme classes when theme changes
 */
function updateGeneralTheme() {
    // Re-apply any theme-specific styling
    const theme = getCurrentTheme();
    // Update any module-specific theme classes here if needed
}

// Listen for theme changes
document.addEventListener('themeChanged', updateGeneralTheme);

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    formatSettingName,
    showNotification,
    generalState,
    loadGeneralSettings,
    renderAppSettings,
    saveGeneralSettings
};