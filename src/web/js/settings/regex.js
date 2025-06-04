/**
 * Email Filter Regex module for Email Verification Engine
 * Handles email validation patterns and regex configuration
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

/**
 * Format a date string from PostgreSQL TIMESTAMPTZ format
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    try {
        // Handle the PostgreSQL timestamp format
        // First try normal date parsing
        const date = new Date(dateString);
        
        // Check if date is valid
        if (!isNaN(date.getTime())) {
            // Format as dd-mm-yyyy
            const day = String(date.getDate()).padStart(2, '0');
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const year = date.getFullYear();
            return `${day}-${month}-${year}`;
        }
        
        // If normal parsing fails, try to extract date parts from string format
        // PostgreSQL timestamptz can come through as a string like "2023-06-04 10:15:30+00"
        const matches = String(dateString).match(/(\d{4})[/-](\d{1,2})[/-](\d{1,2})/);
        if (matches) {
            const year = matches[1];
            const month = String(parseInt(matches[2])).padStart(2, '0');
            const day = String(parseInt(matches[3])).padStart(2, '0');
            return `${day}-${month}-${year}`;
        }
        
        // If all attempts fail, return N/A
        return 'N/A';
    } catch (e) {
        console.error("Error formatting date:", e);
        return 'N/A';
    }
}

// Email filter regex-specific state
const emailFilterState = {
    settings: [],
    presets: []
};

/**
 * Load email filter regex settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadEmailFilterRegexSettings() {
    try {
        const emailFilterResult = await eel.get_email_filter_regex_settings()();
        const emailFilterPresetsResult = await eel.get_email_filter_regex_presets()();
        
        if (emailFilterResult.success && emailFilterPresetsResult.success) {
            emailFilterState.settings = emailFilterResult.settings;
            emailFilterState.presets = emailFilterPresetsResult.presets;
            renderEmailFilterRegexSettings();
            return true;
        } else {
            showNotification('error', 'Failed to load email filter regex settings');
            return false;
        }
    } catch (error) {
        console.error('Error loading email filter regex settings:', error);
        showNotification('error', 'An error occurred while loading email filter regex settings');
        return false;
    }
}

/**
 * Render email filter regex settings
 */
function renderEmailFilterRegexSettings() {
    const container = document.getElementById('email-filter-regex-content');
    if (!container) return;
    
    // First render the presets dropdown
    let html = `
        <div class="results-container">
            <h2>Email Filter Regex Presets</h2>
            <div style="display: flex; align-items: center; gap: 15px; margin: 15px 0; padding: 10px; 
                 background-color: var(--results-container-bg); border-radius: 5px;">
                <select id="email-filter-preset-select" 
                        style="flex: 1; padding: 8px; border: 1px solid var(--results-container-border); 
                        border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    <option value="">Select a preset...</option>
                    ${emailFilterState.presets.map(preset => 
                        `<option value="${preset.id}">${preset.name} - ${preset.description || ''}</option>`
                    ).join('')}
                </select>
                <button id="apply-email-filter-preset-btn" 
                        style="background-color: var(--button-bg); color: var(--button-text); 
                        border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer;">
                    Apply Preset
                </button>
            </div>
        </div>`;
    
    // Then render the current settings
    html += `<div class="results-container">
                <h2>Current Email Filter Settings</h2>
                <div style="display: grid; grid-template-columns: 1fr; gap: 20px;">`;
    
    emailFilterState.settings.forEach(setting => {
        html += `
            <div style="padding: 15px; background-color: var(--results-container-bg); border-radius: 5px;" 
                 data-id="${setting.id}" data-nr="${setting.nr}" data-type="email-filter">
                <h3 style="margin-top: 0;">${setting.name || 'Email Filter Configuration'}</h3>
                
                <div style="margin-bottom: 15px;">
                    <label for="email-filter-main-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                        Main Settings
                    </label>
                    <textarea id="email-filter-main-${setting.id}" rows="4"
                              style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                              border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.main_settings || ''}</textarea>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label for="email-filter-validation-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                        Validation Steps
                    </label>
                    <textarea id="email-filter-validation-${setting.id}" rows="4"
                              style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                              border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.validation_steps || ''}</textarea>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label for="email-filter-pattern-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                        Pattern Checks
                    </label>
                    <textarea id="email-filter-pattern-${setting.id}" rows="4"
                              style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                              border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.pattern_checks || ''}</textarea>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label for="email-filter-regex-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                        Regex Pattern
                    </label>
                    <textarea id="email-filter-regex-${setting.id}" rows="6"
                              style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                              border-radius: 4px; background-color: var(--bg-color); color: var,--text-color); font-family: monospace;">${setting.regex_pattern || ''}</textarea>
                </div>
                
                <details>
                    <summary style="cursor: pointer; padding: 8px; background-color: var(--bg-color); border-radius: 4px; margin-bottom: 15px;">
                        Advanced Options
                    </summary>
                    <div style="padding: 15px; background-color: var(--bg-color); border-radius: 4px; margin-top: 5px;">
                        <div style="margin-bottom: 15px;">
                            <label for="email-filter-format-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                                Format Options
                            </label>
                            <textarea id="email-filter-format-${setting.id}" rows="3"
                                      style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                                      border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.format_options || ''}</textarea>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label for="email-filter-local-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                                Local Part Options
                            </label>
                            <textarea id="email-filter-local-${setting.id}" rows="3"
                                      style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                                      border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.local_part_options || ''}</textarea>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label for="email-filter-domain-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                                Domain Options
                            </label>
                            <textarea id="email-filter-domain-${setting.id}" rows="3"
                                      style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                                      border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.domain_options || ''}</textarea>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label for="email-filter-idna-${setting.id}" style="font-weight: bold; display: block; margin-bottom: 5px;">
                                IDNA Options
                            </label>
                            <textarea id="email-filter-idna-${setting.id}" rows="3"
                                      style="width: 100%; padding: 8px; border: 1px solid var(--results-container-border); 
                                      border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">${setting.idna_options || ''}</textarea>
                        </div>
                    </div>
                </details>
                
                <div style="color: var(--text-muted); font-size: 0.8em; text-align: right;">
                    Last updated: ${formatDate(setting.updated_at)}
                </div>
            </div>
        `;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
    
    // Add event listener to apply preset button
    const applyPresetBtn = document.getElementById('apply-email-filter-preset-btn');
    if (applyPresetBtn) {
        applyPresetBtn.addEventListener('click', applyEmailFilterRegexPreset);
        // Add hover effect
        applyPresetBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        applyPresetBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
}

/**
 * Apply an email filter regex preset
 */
async function applyEmailFilterRegexPreset() {
    try {
        const selectEl = document.getElementById('email-filter-preset-select');
        const presetId = parseInt(selectEl.value);
        
        if (!presetId) {
            showNotification('warning', 'Please select a preset to apply');
            return;
        }
        
        // Show loading state
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        // Call the Python function to apply the preset
        const result = await eel.apply_email_filter_regex_preset(presetId)();
        
        if (result.success) {
            showNotification('success', 'Applied email filter regex preset successfully');
            
            // Reload settings to show updated values
            await loadEmailFilterRegexSettings();
        } else {
            showNotification('error', `Failed to apply preset: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error applying email filter regex preset:', error);
        showNotification('error', 'An error occurred while applying the preset');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

/**
 * Save email filter regex settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveEmailFilterRegexSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save email filter regex settings
        const emailFilterSettings = document.querySelectorAll('div[data-type="email-filter"]');
        for (const settingEl of emailFilterSettings) {
            const id = settingEl.dataset.id;
            
            // Collect all fields for this setting
            const mainSettingsEl = document.getElementById(`email-filter-main-${id}`);
            const validationStepsEl = document.getElementById(`email-filter-validation-${id}`);
            const patternChecksEl = document.getElementById(`email-filter-pattern-${id}`);
            const formatOptionsEl = document.getElementById(`email-filter-format-${id}`);
            const localPartOptionsEl = document.getElementById(`email-filter-local-${id}`);
            const domainOptionsEl = document.getElementById(`email-filter-domain-${id}`);
            const idnaOptionsEl = document.getElementById(`email-filter-idna-${id}`);
            const regexPatternEl = document.getElementById(`email-filter-regex-${id}`);
            
            if (!mainSettingsEl) continue;
            
            const settingsData = {
                main_settings: mainSettingsEl.value,
                validation_steps: validationStepsEl ? validationStepsEl.value : null,
                pattern_checks: patternChecksEl ? patternChecksEl.value : null,
                format_options: formatOptionsEl ? formatOptionsEl.value : null,
                local_part_options: localPartOptionsEl ? localPartOptionsEl.value : null,
                domain_options: domainOptionsEl ? domainOptionsEl.value : null,
                idna_options: idnaOptionsEl ? idnaOptionsEl.value : null,
                regex_pattern: regexPatternEl ? regexPatternEl.value : null
            };
            
            const result = await eel.update_email_filter_regex_setting(parseInt(id), settingsData)();
            result.success ? successCount++ : errorCount++;
        }
    } catch (error) {
        console.error('Error saving email filter regex settings:', error);
        showNotification('error', 'An error occurred while saving email filter regex settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    showNotification,
    formatDate,
    emailFilterState,
    loadEmailFilterRegexSettings,
    renderEmailFilterRegexSettings,
    applyEmailFilterRegexPreset,
    saveEmailFilterRegexSettings
};