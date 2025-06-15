/**
 * Executor Settings module for Email Verification Engine
 * Handles configuration of execution pools and worker threads
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
        // Use the global show_message function exposed by main.js
        // Parameters match notifier.py: type_name, message, persistent, details
        show_message(type_name, message, persistent, details);
    } else {
        // Fallback if show_message isn't available
        console[type_name === 'error' ? 'error' : type_name === 'warning' ? 'warn' : 'log'](message);
        alert(`${type_name.toUpperCase()}: ${message}${details ? '\n' + details : ''}`);
    }
}

// Executor-specific state
const executorState = {
    settings: [],
    presets: []
};

/**
 * Load executor settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadExecutorSettings() {
    try {
        // Load regular settings
        const executorSettingsResult = await eel.get_executor_settings()();
        if (!executorSettingsResult.success) {
            showNotification('error', 'Failed to load executor settings');
            return false;
        }
        
        executorState.settings = executorSettingsResult.settings;
        
        // Load presets
        const presetsResult = await eel.get_executor_presets()();
        if (!presetsResult.success) {
            showNotification('error', 'Failed to load executor presets');
            return false;
        }
        
        executorState.presets = presetsResult.presets;
        
        renderExecutorSettings();
        return true;
    } catch (error) {
        console.error('Error loading executor settings:', error);
        showNotification('error', 'An error occurred while loading executor settings');
        return false;
    }
}

/**
 * Render executor pool settings
 */
function renderExecutorSettings() {
    const container = document.getElementById('executor-settings-content');
    if (!container) return;
    
    let html = '<div class="results-container"><h2>Executor Pool Configuration</h2>';
    
    // Presets dropdown
    html += `
        <div style="margin-bottom: 20px; padding: 15px; background-color: var(--results-container-bg); border-radius: 5px;">
            <h3 style="margin-top: 0; color: var(--text-color);">Presets</h3>
            <div style="display: flex; align-items: center; gap: 10px;">
                <select id="executor-preset" style="padding: 8px; border-radius: 5px; background-color: var(--bg-color); color: var(--text-color); border: 1px solid var(--results-container-border);">
                    <option value="">Select a preset...</option>`;
    
    executorState.presets.forEach(preset => {
        html += `<option value="${preset.id}">${preset.name} - ${preset.description}</option>`;
    });
    
    html += `
                </select>
                <button id="apply-executor-preset" class="primary-button">Apply Preset</button>
                <button id="run-executor-autotune" class="primary-button">Run Autotune</button>
            </div>
            <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted);">
                Presets provide optimized configurations for different use cases. 
                Autotune will analyze your system and recommend optimal settings.
            </div>
        </div>
    `;
    
    // Executor settings
    html += '<div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    executorState.settings.forEach(setting => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="exe">
                <div style="flex: 1; padding-right: 15px;">
                    <label for="exe-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                        ${formatSettingName(setting.name)}
                    </label>
                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                        ${setting.description}
                    </div>
                </div>`;
        
        if (setting.value === "0" || setting.value === "1") {
            // Toggle switch for boolean settings
            html += `
                <div>
                    <label class="toggle-switch">
                        <input type="checkbox" id="exe-setting-${setting.id}" 
                               ${setting.value === "1" ? "checked" : ""}>
                        <span class="toggle-slider round"></span>
                    </label>
                </div>
            `;
        } else {
            // Number input for numeric settings
            html += `
                <div>
                    <input type="number" id="exe-setting-${setting.id}" value="${setting.value}"
                           min="0" step="1"
                           style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                           border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                </div>
            `;
        }
        
        html += `</div>`;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
    
    // Add event listeners
    document.getElementById('apply-executor-preset')?.addEventListener('click', applyExecutorPreset);
    document.getElementById('run-executor-autotune')?.addEventListener('click', runExecutorAutotune);
}

/**
 * Apply an executor pool preset
 */
async function applyExecutorPreset() {
    const presetSelect = document.getElementById('executor-preset');
    const presetId = presetSelect.value;
    
    if (!presetId) {
        showNotification('warning', 'Please select a preset to apply');
        return;
    }
    
    try {
        const result = await eel.apply_executor_preset(parseInt(presetId))();
        
        if (result.success) {
            showNotification('success', 'Preset applied successfully');
            await loadExecutorSettings(); // Reload to show new values
        } else {
            showNotification('error', 'Failed to apply preset', false, result.error);
        }
    } catch (error) {
        console.error('Error applying preset:', error);
        showNotification('error', 'An error occurred while applying preset');
    }
}

/**
 * Run executor autotune
 */
async function runExecutorAutotune() {
    try {
        showNotification('info', 'Running autotune, please wait...', true);
        
        const result = await eel.run_executor_autotune()();
        
        if (result.success) {
            showNotification('success', 'Autotune completed', false, `Recommended settings have been applied: ${result.details}`);
            await loadExecutorSettings(); // Reload to show new values
        } else {
            showNotification('error', 'Autotune failed', false, result.error);
        }
    } catch (error) {
        console.error('Error running autotune:', error);
        showNotification('error', 'An error occurred during autotune');
    }
}

/**
 * Save executor settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveExecutorSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save executor settings
        const exeSettings = document.querySelectorAll('div[data-type="exe"]');
        for (const settingEl of exeSettings) {
            const id = settingEl.dataset.id;
            const inputEl = document.getElementById(`exe-setting-${id}`);
            
            if (!inputEl) continue;
            
            let value;
            if (inputEl.type === 'checkbox') {
                value = inputEl.checked ? "1" : "0";
            } else {
                value = inputEl.value;
            }
            
            const result = await eel.update_executor_setting(parseInt(id), value)();
            result.success ? successCount++ : errorCount++;
        }
    } catch (error) {
        console.error('Error saving executor settings:', error);
        showNotification('error', 'An error occurred while saving executor settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

/**
 * Update theme classes when theme changes
 */
function updateExecutorTheme() {
    // Re-apply any theme-specific styling
    const theme = getCurrentTheme();
    // Update any module-specific theme classes here if needed
}

// Listen for theme changes
document.addEventListener('themeChanged', updateExecutorTheme);

// Expose functions globally (add this at the end)
window.loadExecutorSettings = loadExecutorSettings;
window.saveExecutorSettings = saveExecutorSettings;
window.renderExecutorSettings = renderExecutorSettings;
window.runExecutorAutotune = runExecutorAutotune;
window.applyExecutorPreset = applyExecutorPreset;
window.executorState = executorState;