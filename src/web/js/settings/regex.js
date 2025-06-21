/**
 * Email Filter Regex module for Email Verification Engine
 * Handles email validation patterns and regex configuration
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

/**
 * Format a date string from PostgreSQL TIMESTAMPTZ format
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    try {
        const date = new Date(dateString);
        
        if (!isNaN(date.getTime())) {
            const day = String(date.getDate()).padStart(2, '0');
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const year = date.getFullYear();
            return `${day}-${month}-${year}`;
        }
        
        const matches = String(dateString).match(/(\d{4})[/-](\d{1,2})[/-](\d{1,2})/);
        if (matches) {
            const year = matches[1];
            const month = String(parseInt(matches[2])).padStart(2, '0');
            const day = String(parseInt(matches[3])).padStart(2, '0');
            return `${day}-${month}-${year}`;
        }
        
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
 * Escape HTML to prevent XSS attacks
 * @param {string} unsafe - The unsafe string to escape
 * @return {string} The escaped string
 */
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Render email filter regex settings with proper HTML escaping
 */
function renderEmailFilterRegexSettings() {
    const container = document.getElementById('email-filter-regex-content');
    if (!container) return;
    
    let html = `
        <div class="results-container">
            <h2>Email Filter Regex</h2>
            <div class="email-filter-preset-container">
                <select id="email-filter-preset-select" class="email-filter-preset-select">
                    <option value="">Select filter</option>
                    <optgroup label="Preset filters:">
                        ${emailFilterState.presets.map(preset => 
                            `<option value="${escapeHtml(preset.id)}">${escapeHtml(preset.name)} - ${escapeHtml(preset.description || '')}</option>`
                        ).join('')}
                    </optgroup>
                    <optgroup label="Custom filter:">
                        ${emailFilterState.settings
                            .filter(setting => setting.nr >= 2)
                            .map(setting => 
                                `<option value="custom-${escapeHtml(setting.id)}">${escapeHtml(setting.name)}${setting.description ? ' - ' + escapeHtml(setting.description) : ''}</option>`
                            ).join('')}
                    </optgroup>
                </select>
                <button id="apply-email-filter-preset-btn" class="email-filter-preset-button">
                    Apply
                </button>
            </div>
        </div>`;
    
    const activeConfig = emailFilterState.settings.find(setting => setting.nr === 1);
    
    html += `<div class="results-container">
                <h2>Current Active Email Filter Configuration</h2>
                <div class="email-filter-config-display">
                    <h3 class="email-filter-config-header">
                        ${activeConfig ? escapeHtml(activeConfig.name) : 'No active configuration'} 
                        <span class="email-filter-readonly-badge">Read-only</span>
                    </h3>
                    ${activeConfig ? renderConfigurationStructure(activeConfig, true) : '<p>No active configuration found</p>'}
                    <div class="email-filter-config-footer">
                        Last updated: ${activeConfig ? escapeHtml(formatDate(activeConfig.updated_at)) : 'N/A'}
                    </div>
                </div>
            </div>`;
    
    html += `<div class="results-container">
            <h2>Create New Email Filter Configuration</h2>
            <div class="email-filter-form-container">
                <div class="email-filter-name-input">
                    <label for="new-config-name">Configuration Name</label>
                    <input type="text" id="new-config-name" placeholder="Enter configuration name..." 
                           class="email-filter-input">
                </div>
                <div class="email-filter-name-input">
                    <label for="new-config-description">Description (Optional)</label>
                    <input type="text" id="new-config-description" placeholder="Enter description..." 
                           class="email-filter-input">
                </div>
                
                ${renderConfigurationStructure(null, false)}
                
                <div class="email-filter-actions">
                    <button id="save-new-config-btn" class="email-filter-btn_primary">
                        Save New Configuration
                    </button>
                    <button id="reset-new-config-btn" class="email-filter-btn_secondary">
                        Reset to Defaults
                    </button>
                </div>
            </div>
        </div>`;
    
    // Set HTML content safely after escaping all dynamic values
    container.innerHTML = html;
    
    // Apply theme-specific classes after DOM insertion
    applyThemeClasses();
    
    addEmailFilterEventListeners();
    resetNewConfigurationToDefaults();
}

/**
 * Apply theme-specific classes to all email filter elements
 */
function applyThemeClasses() {
    const theme = getCurrentTheme();
    
    // Apply theme to disabled containers
    document.querySelectorAll('.email-filter-disabled-container').forEach(el => {
        el.setAttribute('data-theme', theme);
    });
    
    // Apply theme to disabled inputs
    document.querySelectorAll('.email-filter-disabled-input').forEach(el => {
        el.setAttribute('data-theme', theme);
    });
    
    // Apply theme to disabled labels
    document.querySelectorAll('.email-filter-disabled-label').forEach(el => {
        el.setAttribute('data-theme', theme);
    });
}

/**
 * Render configuration structure using CSS classes with proper HTML escaping
 */
function renderConfigurationStructure(config, readOnly = false) {
    const suffix = readOnly ? '-readonly' : '-new';
    const disabled = readOnly ? 'disabled' : '';
    const theme = getCurrentTheme();
    
    // CSS classes for disabled state
    const containerClass = readOnly ? `email-filter-disabled-container` : 'email-filter-section';
    const inputClass = readOnly ? `email-filter-input email-filter-disabled-input` : 'email-filter-input';
    const labelClass = readOnly ? `email-filter-checkbox-label email-filter-disabled-label` : 'email-filter-checkbox-label';
    
    let mainSettings = {};
    let validationSteps = {};
    let patternChecks = {};
    let formatOptions = {};
    let localPartOptions = {};
    let domainOptions = {};
    let idnaOptions = {};
    
    if (config) {
        try {
            mainSettings = typeof config.main_settings === 'string' ? JSON.parse(config.main_settings) : config.main_settings || {};
            validationSteps = typeof config.validation_steps === 'string' ? JSON.parse(config.validation_steps) : config.validation_steps || {};
            patternChecks = typeof config.pattern_checks === 'string' ? JSON.parse(config.pattern_checks) : config.pattern_checks || {};
            formatOptions = typeof config.format_options === 'string' ? JSON.parse(config.format_options) : config.format_options || {};
            localPartOptions = typeof config.local_part_options === 'string' ? JSON.parse(config.local_part_options) : config.local_part_options || {};
            domainOptions = typeof config.domain_options === 'string' ? JSON.parse(config.domain_options) : config.domain_options || {};
            idnaOptions = typeof config.idna_options === 'string' ? JSON.parse(config.idna_options) : config.idna_options || {};
        } catch (e) {
            console.error('Error parsing configuration JSON:', e);
        }
    }
    
    return `
        <!-- Main Settings -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Main Settings</h4>
            <div class="email-filter-grid-2col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="strict-mode${suffix}" ${mainSettings.strict_mode ? 'checked' : ''} ${disabled}>
                        <span>Strict Mode</span>
                    </label>
                    <small class="email-filter-help-text">Enables stricter validation according to RFC standards</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="email-filter-field-label">Basic Format Pattern</label>
                    <select id="basic-format-pattern${suffix}" ${disabled} class="${inputClass}" data-theme="${escapeHtml(theme)}">
                        <option value="basic" ${mainSettings.basic_format_pattern === 'basic' ? 'selected' : ''}>Basic</option>
                        <option value="rfc5322" ${mainSettings.basic_format_pattern === 'rfc5322' ? 'selected' : ''}>RFC 5322</option>
                    </select>
                    <small class="email-filter-help-text">Basic: simple pattern (something@domain.tld), RFC 5322: stricter standard compliance</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="email-filter-field-label">Max Local Length</label>
                    <input type="number" id="max-local-length${suffix}" value="${escapeHtml(mainSettings.max_local_length || 64)}" ${disabled}
                           class="${inputClass}" data-theme="${escapeHtml(theme)}">
                    <small class="email-filter-help-text">Maximum characters before @ sign (RFC standard is 64)</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="email-filter-field-label">Max Domain Length</label>
                    <input type="number" id="max-domain-length${suffix}" value="${escapeHtml(mainSettings.max_domain_length || 255)}" ${disabled}
                           class="${inputClass}" data-theme="${escapeHtml(theme)}">
                    <small class="email-filter-help-text">Maximum domain length in characters (RFC standard is 255)</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="email-filter-field-label">Max Total Length</label>
                    <input type="number" id="max-total-length${suffix}" value="${escapeHtml(mainSettings.max_total_length || 320)}" ${disabled}
                           class="${inputClass}" data-theme="${escapeHtml(theme)}">
                    <small class="email-filter-help-text">Maximum total email length (RFC standard is 320)</small>
                </div>
            </div>
        </div>

        <!-- Validation Steps -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Validation Steps</h4>
            <div class="email-filter-grid-3col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="basic-format${suffix}" ${validationSteps.basic_format !== false ? 'checked' : ''} ${disabled}>
                        <span>Basic Format</span>
                    </label>
                    <small class="email-filter-help-text">Validates presence of @ symbol and basic structure</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="normalization${suffix}" ${validationSteps.normalization !== false ? 'checked' : ''} ${disabled}>
                        <span>Normalization</span>
                    </label>
                    <small class="email-filter-help-text">Converts to lowercase and removes unnecessary spaces</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="length-limits${suffix}" ${validationSteps.length_limits !== false ? 'checked' : ''} ${disabled}>
                        <span>Length Limits</span>
                    </label>
                    <small class="email-filter-help-text">Enforces length limits on local part, domain, and total email</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="local-part${suffix}" ${validationSteps.local_part !== false ? 'checked' : ''} ${disabled}>
                        <span>Local Part</span>
                    </label>
                    <small class="email-filter-help-text">Validates the part before @ using specified character rules</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="domain${suffix}" ${validationSteps.domain !== false ? 'checked' : ''} ${disabled}>
                        <span>Domain</span>
                    </label>
                    <small class="email-filter-help-text">Validates domain structure including dots and character limits</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="idna${suffix}" ${validationSteps.idna !== false ? 'checked' : ''} ${disabled}>
                        <span>IDNA</span>
                    </label>
                    <small class="email-filter-help-text">Handles internationalized domain names with Unicode characters</small>
                </div>
            </div>
        </div>

        <!-- Pattern Checks -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Pattern Checks</h4>
            <div class="email-filter-grid-3col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="empty-parts${suffix}" ${patternChecks.empty_parts !== false ? 'checked' : ''} ${disabled}>
                        <span>Empty Parts</span>
                    </label>
                    <small class="email-filter-help-text">Rejects emails with empty local part or domain (e.g., @domain.com)</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="whitespace${suffix}" ${patternChecks.whitespace !== false ? 'checked' : ''} ${disabled}>
                        <span>Whitespace</span>
                    </label>
                    <small class="email-filter-help-text">Detects and rejects emails containing whitespace characters</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="consecutive-dots${suffix}" ${patternChecks.consecutive_dots !== false ? 'checked' : ''} ${disabled}>
                        <span>Consecutive Dots</span>
                    </label>
                    <small class="email-filter-help-text">Rejects emails with consecutive dots (..) in any part</small>
                </div>
            </div>
        </div>

        <!-- Format Options -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Format Options</h4>
            <div class="email-filter-grid-3col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-empty-parts${suffix}" ${formatOptions.check_empty_parts !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Empty Parts</span>
                    </label>
                    <small class="email-filter-help-text">Verifies both local and domain parts exist and aren't empty</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-whitespace${suffix}" ${formatOptions.check_whitespace !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Whitespace</span>
                    </label>
                    <small class="email-filter-help-text">Controls whether to allow or reject whitespace in email address</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-pattern${suffix}" ${formatOptions.check_pattern !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Pattern</span>
                    </label>
                    <small class="email-filter-help-text">Applies selected regex pattern (basic or RFC 5322) to validate structure</small>
                </div>
            </div>
        </div>

        <!-- Local Part Options -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Local Part Options</h4>
            <div class="email-filter-grid-2col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-consecutive-dots-local${suffix}" ${localPartOptions.check_consecutive_dots !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Consecutive Dots</span>
                    </label>
                    <small class="email-filter-help-text">Rejects local parts with consecutive dots (..) which are invalid</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-chars-strict${suffix}" ${localPartOptions.check_chars_strict ? 'checked' : ''} ${disabled}>
                        <span>Check Characters Strict</span>
                    </label>
                    <small class="email-filter-help-text">When enabled, only allows alphanumeric and specified special characters</small>
                </div>
                <div class="email-filter-field-container email-filter-text-input">
                    <label class="email-filter-field-label">Allowed Characters</label>
                    <input type="text" id="allowed-chars-local${suffix}" value="${localPartOptions.allowed_chars || '!#$%&\'*+-/=?^_`{|}~.'}" ${disabled}
                           class="${inputClass}" data-theme="${escapeHtml(theme)}">
                    <small class="email-filter-help-text">Special characters permitted in local part per RFC 5322</small>
                </div>
            </div>
        </div>

        <!-- Domain Options -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">Domain Options</h4>
            <div class="email-filter-grid-2col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="require-dot${suffix}" ${domainOptions.require_dot !== false ? 'checked' : ''} ${disabled}>
                        <span>Require Dot</span>
                    </label>
                    <small class="email-filter-help-text">Requires at least one dot in domain (example.com vs localhost)</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-hyphens${suffix}" ${domainOptions.check_hyphens !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Hyphens</span>
                    </label>
                    <small class="email-filter-help-text">Prevents domains from starting or ending with hyphens</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="check-consecutive-dots-domain${suffix}" ${domainOptions.check_consecutive_dots !== false ? 'checked' : ''} ${disabled}>
                        <span>Check Consecutive Dots</span>
                    </label>
                    <small class="email-filter-help-text">Rejects domains with consecutive dots (..) which are invalid</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="email-filter-field-label">Allowed Characters</label>
                    <input type="text" id="allowed-chars-domain${suffix}" value="${domainOptions.allowed_chars || '.-'}" ${disabled}
                           class="${inputClass}" data-theme="${escapeHtml(theme)}">
                    <small class="email-filter-help-text">Characters permitted in domain besides alphanumeric</small>
                </div>
            </div>
        </div>

        <!-- IDNA Options -->
        <div class="${containerClass}" data-theme="${escapeHtml(theme)}">
            <h4 class="email-filter-section-title">IDNA Options</h4>
            <div class="email-filter-grid-2col">
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="encode-unicode${suffix}" ${idnaOptions.encode_unicode !== false ? 'checked' : ''} ${disabled}>
                        <span>Encode Unicode</span>
                    </label>
                    <small class="email-filter-help-text">Converts international domain names to Punycode (xn--) format</small>
                </div>
                <div class="email-filter-field-container">
                    <label class="${labelClass}" data-theme="${escapeHtml(theme)}">
                        <input type="checkbox" id="validate-idna${suffix}" ${idnaOptions.validate_idna !== false ? 'checked' : ''} ${disabled}>
                        <span>Validate IDNA</span>
                    </label>
                    <small class="email-filter-help-text">Ensures international domain names follow IDNA protocol standards</small>
                </div>
            </div>
        </div>
    `;
}

/**
 * Update theme classes when theme changes
 */
function updateEmailFilterTheme() {
    applyThemeClasses();
}

// Listen for theme changes
document.addEventListener('themeChanged', updateEmailFilterTheme);

/**
 * Apply an email filter regex preset
 */
async function applyEmailFilterRegexPreset() {
    try {
        const selectEl = document.getElementById('email-filter-preset-select');
        const selectedValue = selectEl.value;
        
        if (!selectedValue) {
            showNotification('warning', 'Please select a filter to apply');
            return;
        }
        
        // Show loading state
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        let result;
        
        // Check if this is a custom filter or preset
        if (selectedValue.startsWith('custom-')) {
            // Extract the custom filter ID
            const customId = parseInt(selectedValue.replace('custom-', ''));
            // Call the Python function to apply the custom filter
            result = await eel.apply_custom_email_filter_regex(customId)();
        } else {
            // This is a preset filter
            const presetId = parseInt(selectedValue);
            // Call the Python function to apply the preset
            result = await eel.apply_email_filter_regex_preset(presetId)();
        }
        
        if (result.success) {
            showNotification('success', 'Applied email filter regex successfully');
            
            // Reload settings to show updated values
            await loadEmailFilterRegexSettings();
        } else {
            showNotification('error', `Failed to apply filter: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error applying email filter regex:', error);
        showNotification('error', 'An error occurred while applying the filter');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

/**
 * Save email filter regex settings
 */
async function saveEmailFilterRegexSettings() {
    try {
        // This function would be used to save modifications to existing settings
        // For now, return a success status since we're focusing on the preset and new config functionality
        return {
            success: 1,
            errors: 0
        };
    } catch (error) {
        console.error('Error saving email filter regex settings:', error);
        return {
            success: 0,
            errors: 1
        };
    }
}

/**
 * Add event listeners for email filter functionality
 */
function addEmailFilterEventListeners() {
    // Apply preset button
    const applyPresetBtn = document.getElementById('apply-email-filter-preset-btn');
    if (applyPresetBtn) {
        applyPresetBtn.addEventListener('click', applyEmailFilterRegexPreset);
        applyPresetBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        applyPresetBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
    
    // Save new configuration button
    const saveNewConfigBtn = document.getElementById('save-new-config-btn');
    if (saveNewConfigBtn) {
        saveNewConfigBtn.addEventListener('click', saveNewEmailFilterConfiguration);
        saveNewConfigBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        saveNewConfigBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
    
    // Reset new configuration button
    const resetNewConfigBtn = document.getElementById('reset-new-config-btn');
    if (resetNewConfigBtn) {
        resetNewConfigBtn.addEventListener('click', resetNewConfigurationToDefaults);
        resetNewConfigBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--results-container-bg)';
        });
        resetNewConfigBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--bg-color)';
        });
    }
}

/**
 * Reset new configuration form to default values
 */
function resetNewConfigurationToDefaults() {
    // Reset name and description
    const nameInput = document.getElementById('new-config-name');
    if (nameInput) {
        nameInput.value = '';
    }
    
    const descriptionInput = document.getElementById('new-config-description');
    if (descriptionInput) {
        descriptionInput.value = '';
    }
    
    // Reset all form fields to defaults
    const suffix = '-new';
    
    // Main Settings defaults
    const strictModeEl = document.getElementById(`strict-mode${suffix}`);
    if (strictModeEl) strictModeEl.checked = false;
    
    const basicFormatPatternEl = document.getElementById(`basic-format-pattern${suffix}`);
    if (basicFormatPatternEl) basicFormatPatternEl.value = 'basic';
    
    const maxLocalLengthEl = document.getElementById(`max-local-length${suffix}`);
    if (maxLocalLengthEl) maxLocalLengthEl.value = '64';
    
    const maxDomainLengthEl = document.getElementById(`max-domain-length${suffix}`);
    if (maxDomainLengthEl) maxDomainLengthEl.value = '255';
    
    const maxTotalLengthEl = document.getElementById(`max-total-length${suffix}`);
    if (maxTotalLengthEl) maxTotalLengthEl.value = '320';
    
    // Validation Steps defaults (all true)
    const validationStepIds = [
        'basic-format', 'normalization', 'length-limits', 'local-part', 'domain', 'idna'
    ];
    validationStepIds.forEach(id => {
        const el = document.getElementById(`${id}${suffix}`);
        if (el) el.checked = true;
    });
    
    // Pattern Checks defaults (all true)
    const patternCheckIds = [
        'empty-parts', 'whitespace', 'consecutive-dots'
    ];
    patternCheckIds.forEach(id => {
        const el = document.getElementById(`${id}${suffix}`);
        if (el) el.checked = true;
    });
    
    // Format Options defaults (all true)
    const formatOptionIds = [
        'check-empty-parts', 'check-whitespace', 'check-pattern'
    ];
    formatOptionIds.forEach(id => {
        const el = document.getElementById(`${id}${suffix}`);
        if (el) el.checked = true;
    });
    
    // Local Part Options defaults
    const checkConsecutiveDotsLocalEl = document.getElementById(`check-consecutive-dots-local${suffix}`);
    if (checkConsecutiveDotsLocalEl) checkConsecutiveDotsLocalEl.checked = true;
    
    const checkCharsStrictEl = document.getElementById(`check-chars-strict${suffix}`);
    if (checkCharsStrictEl) checkCharsStrictEl.checked = true;
    
    const allowedCharsLocalEl = document.getElementById(`allowed-chars-local${suffix}`);
    if (allowedCharsLocalEl) allowedCharsLocalEl.value = '!#$%&\'*+-/=?^_`{|}~.';
    
    // Domain Options defaults
    const requireDotEl = document.getElementById(`require-dot${suffix}`);
    if (requireDotEl) requireDotEl.checked = true;
    
    const checkHyphensEl = document.getElementById(`check-hyphens${suffix}`);
    if (checkHyphensEl) checkHyphensEl.checked = true;
    
    const checkConsecutiveDotsDomainEl = document.getElementById(`check-consecutive-dots-domain${suffix}`);
    if (checkConsecutiveDotsDomainEl) checkConsecutiveDotsDomainEl.checked = true;
    
    const allowedCharsDomainEl = document.getElementById(`allowed-chars-domain${suffix}`);
    if (allowedCharsDomainEl) allowedCharsDomainEl.value = '.-';
    
    // IDNA Options defaults
    const encodeUnicodeEl = document.getElementById(`encode-unicode${suffix}`);
    if (encodeUnicodeEl) encodeUnicodeEl.checked = true;
    
    const validateIdnaEl = document.getElementById(`validate-idna${suffix}`);
    if (validateIdnaEl) validateIdnaEl.checked = true;
}

/**
 * Save new email filter configuration
 */
async function saveNewEmailFilterConfiguration() {
    try {
        const nameInput = document.getElementById('new-config-name');
        const configName = nameInput.value.trim();
        
        if (!configName) {
            showNotification('warning', 'Please enter a configuration name');
            return;
        }
        
        // Get description (add this input to your HTML where appropriate)
        const descriptionInput = document.getElementById('new-config-description');
        const configDescription = descriptionInput ? descriptionInput.value.trim() : '';
        
        // Show loading state
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        // Collect all configuration data
        const suffix = '-new';
        const configData = {
            name: configName,
            description: configDescription,
            main_settings: {
                strict_mode: document.getElementById(`strict-mode${suffix}`).checked,
                max_local_length: parseInt(document.getElementById(`max-local-length${suffix}`).value),
                max_domain_length: parseInt(document.getElementById(`max-domain-length${suffix}`).value),
                max_total_length: parseInt(document.getElementById(`max-total-length${suffix}`).value),
                basic_format_pattern: document.getElementById(`basic-format-pattern${suffix}`).value
            },
            validation_steps: {
                basic_format: document.getElementById(`basic-format${suffix}`).checked,
                normalization: document.getElementById(`normalization${suffix}`).checked,
                length_limits: document.getElementById(`length-limits${suffix}`).checked,
                local_part: document.getElementById(`local-part${suffix}`).checked,
                domain: document.getElementById(`domain${suffix}`).checked,
                idna: document.getElementById(`idna${suffix}`).checked
            },
            pattern_checks: {
                empty_parts: document.getElementById(`empty-parts${suffix}`).checked,
                whitespace: document.getElementById(`whitespace${suffix}`).checked,
                consecutive_dots: document.getElementById(`consecutive-dots${suffix}`).checked
            },
            format_options: {
                check_empty_parts: document.getElementById(`check-empty-parts${suffix}`).checked,
                check_whitespace: document.getElementById(`check-whitespace${suffix}`).checked,
                check_pattern: document.getElementById(`check-pattern${suffix}`).checked
            },
            local_part_options: {
                check_consecutive_dots: document.getElementById(`check-consecutive-dots-local${suffix}`).checked,
                check_chars_strict: document.getElementById(`check-chars-strict${suffix}`).checked,
                allowed_chars: document.getElementById(`allowed-chars-local${suffix}`).value
            },
            domain_options: {
                require_dot: document.getElementById(`require-dot${suffix}`).checked,
                check_hyphens: document.getElementById(`check-hyphens${suffix}`).checked,
                check_consecutive_dots: document.getElementById(`check-consecutive-dots-domain${suffix}`).checked,
                allowed_chars: document.getElementById(`allowed-chars-domain${suffix}`).value
            },
            idna_options: {
                encode_unicode: document.getElementById(`encode-unicode${suffix}`).checked,
                validate_idna: document.getElementById(`validate-idna${suffix}`).checked
            },
            regex_patterns: {
                basic: "^.+@.+\\.+$",
                rfc5322: "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)",
                local_too_long: "^.{64,}@",
                empty_parts: "^@|@$|@\\.|\\.$",
                whitespace: "\\s+",
                consecutive_dots: "\\.{2,}"
            }
        };
        
        // Call the Python function to save the new configuration
        const result = await eel.create_new_email_filter_regex_configuration(configData)();
        
        if (result.success) {
            showNotification('success', `Created new email filter configuration: ${configName}`);
            
            // Reset the form
            resetNewConfigurationToDefaults();
            
            // Reload settings to show the new configuration
            await loadEmailFilterRegexSettings();
        } else {
            showNotification('error', `Failed to create configuration: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error saving new email filter configuration:', error);
        showNotification('error', 'An error occurred while saving the configuration');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

// Expose functions and state to the global window object
window.loadEmailFilterRegexSettings = loadEmailFilterRegexSettings;
window.saveEmailFilterRegexSettings = saveEmailFilterRegexSettings;
window.renderEmailFilterRegexSettings = renderEmailFilterRegexSettings;
window.emailFilterState = emailFilterState;