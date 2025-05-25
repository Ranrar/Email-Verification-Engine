/**
 * Settings Menu for Email Verification Engine
 * Allows users to view and modify application settings
 */

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
 * @param {string} type - The notification type: 'success', 'error', 'warning', 'info'
 * @param {string} message - The message to display
 * @param {boolean} persistent - Whether the notification should persist until clicked
 */
function showNotification(type, message, persistent = false) {
    if (typeof show_message === 'function') {
        // Use the global show_message function exposed by main.js
        show_message(type, message, persistent);
    } else {
        // Fallback if show_message isn't available
        console[type === 'error' ? 'error' : type === 'warning' ? 'warn' : 'log'](message);
        alert(`${type.toUpperCase()}: ${message}`);
    }
}

// State to store settings - expand to include new settings types
const settingsState = {
    appSettings: [],
    rateLimits: [],
    dnsSettings: [],
    executorSettings: {
        settings: [],
        presets: []
    },
    // New setting types
    validationScoring: [],
    confidenceLevels: [],
    portsConfiguration: [],
    emailFilterRegex: {
        settings: [],
        presets: []
    },
    blackWhiteList: [],
    loading: false,
    currentTab: 'general',
    initialized: false
};

/**
 * Initialize the settings menu
 */
async function initSettingsMenu() {
    // Only initialize once
    if (settingsState.initialized) {
        return;
    }

    // Add event listeners to tab buttons
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchSettingsTab(btn.dataset.tab));
    });

    // Load initial data
    await loadAllSettings();
    
    // Ensure the save button is properly attached
    const saveButton = document.getElementById('save-settings-btn');
    if (saveButton) {
        saveButton.addEventListener('click', saveAllSettings);
    }
    
    // Reset button functionality
    const resetButton = document.getElementById('reset-settings-btn');
    if (resetButton) {
        resetButton.addEventListener('click', () => loadAllSettings());
    }
    
    // Add event listener to Run Autotune button
    const autotuneBtn = document.getElementById('run-autotune-btn');
    if (autotuneBtn) {
        autotuneBtn.addEventListener('click', runExecutorAutotune);
        // Add hover effect
        autotuneBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        autotuneBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
    
    // Mark as initialized
    settingsState.initialized = true;
}

/**
 * Switch between settings tabs
 * @param {string} tabName - The name of the tab to show
 */
function switchSettingsTab(tabName) {
    // Update active tab button
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    // Update visible tab content - FIX: Add console logging to debug
    console.log(`Switching to tab: ${tabName}`);
    
    document.querySelectorAll('.settings-tab-content').forEach(tab => {
        const shouldShow = tab.id === `${tabName}-settings`;
        tab.style.display = shouldShow ? 'block' : 'none';
        console.log(`Tab ${tab.id}: ${shouldShow ? 'showing' : 'hiding'}`);
    });
    
    settingsState.currentTab = tabName;
}

/**
 * Load all settings from the database
 */
async function loadAllSettings() {
    settingsState.loading = true;
    updateLoadingState(true);
    
    try {
        // Load app settings
        const appSettingsResult = await eel.get_app_settings()();
        if (appSettingsResult.success) {
            settingsState.appSettings = appSettingsResult.settings;
            renderAppSettings();
        } else {
            showNotification('error', 'Failed to load application settings');
        }
        
        // Load rate limits
        const rateLimitsResult = await eel.get_rate_limits()();
        if (rateLimitsResult.success) {
            settingsState.rateLimits = rateLimitsResult.settings;
            renderRateLimits();
        } else {
            showNotification('error', 'Failed to load rate limits');
        }
        
        // Load DNS settings
        const dnsSettingsResult = await eel.get_dns_settings()();
        if (dnsSettingsResult.success) {
            settingsState.dnsSettings = dnsSettingsResult.settings;
            renderDNSSettings();
        } else {
            showNotification('error', 'Failed to load DNS settings');
        }
        
        // Load executor pool settings
        const executorSettingsResult = await eel.get_executor_pool_settings()();
        if (executorSettingsResult.success) {
            settingsState.executorSettings.settings = executorSettingsResult.settings;
            settingsState.executorSettings.presets = executorSettingsResult.presets;
            renderExecutorSettings();
        } else {
            showNotification('error', 'Failed to load executor settings');
        }
        
        // Load validation scoring
        try {
            console.log('Loading validation scoring...');
            const validationScoringResult = await eel.get_validation_scoring()();
            console.log('Result:', validationScoringResult);
            if (validationScoringResult.success) {
                settingsState.validationScoring = validationScoringResult.settings;
                renderValidationScoring();
            } else {
                console.error('Failed to load validation scoring:', validationScoringResult.error);
            }
        } catch (e) {
            console.error('Error loading validation scoring:', e);
        }
        
        // Load confidence levels
        try {
            const confidenceLevelsResult = await eel.get_confidence_levels()();
            if (confidenceLevelsResult.success) {
                settingsState.confidenceLevels = confidenceLevelsResult.settings;
                renderConfidenceLevels();
            }
        } catch (e) {
            console.warn('Confidence levels not loaded:', e);
        }
        
        // Load ports configuration
        try {
            const portsResult = await eel.get_ports_configuration()();
            if (portsResult.success) {
                settingsState.portsConfiguration = portsResult.settings;
                renderPortsConfiguration();
            }
        } catch (e) {
            console.warn('Ports configuration not loaded:', e);
        }
        
        // Load email filter regex settings
        try {
            const emailFilterResult = await eel.get_email_filter_regex_settings()();
            const emailFilterPresetsResult = await eel.get_email_filter_regex_presets()();
            
            if (emailFilterResult.success && emailFilterPresetsResult.success) {
                settingsState.emailFilterRegex.settings = emailFilterResult.settings;
                settingsState.emailFilterRegex.presets = emailFilterPresetsResult.presets;
                renderEmailFilterRegexSettings();
            }
        } catch (e) {
            console.warn('Email filter regex settings not loaded:', e);
        }
        
        // Load black/white list
        try {
            const blackWhiteResult = await eel.get_black_white_list()();
            if (blackWhiteResult.success) {
                settingsState.blackWhiteList = blackWhiteResult.domains;
                renderBlackWhiteList();
            }
        } catch (e) {
            console.warn('Black/white list not loaded:', e);
        }
    } catch (error) {
        console.error('Error loading settings:', error);
        showNotification('error', 'An error occurred while loading settings');
    } finally {
        settingsState.loading = false;
        updateLoadingState(false);
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
    settingsState.appSettings.forEach(setting => {
        if (!groupedSettings[setting.category]) {
            groupedSettings[setting.category] = {};
        }
        if (!groupedSettings[setting.category][setting.sub_category]) {
            groupedSettings[setting.category][setting.sub_category] = [];
        }
        groupedSettings[setting.category][setting.sub_category].push(setting);
    });
    
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
            });
            
            html += `</div></div>`;
        }
        
        html += `</div>`;
    }
    
    container.innerHTML = html;
}

/**
 * Render rate limit settings
 */
function renderRateLimits() {
    const container = document.getElementById('rate-limits-settings-content');
    if (!container) return;
    
    // Group settings by category
    const groupedSettings = {};
    settingsState.rateLimits.forEach(setting => {
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
                        <label for="rate-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
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
 * Render DNS settings
 */
function renderDNSSettings() {
    const container = document.getElementById('dns-settings-content');
    if (!container) return;
    
    let html = '<div class="results-container"><h2>DNS Configuration</h2><div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    settingsState.dnsSettings.forEach(setting => {
        if (setting.name === 'nameservers') {
            // Special handling for nameservers (textarea)
            html += `
                <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                     border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="dns">
                    <div style="flex: 1; padding-right: 15px;">
                        <label for="dns-setting-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                            DNS Nameservers
                        </label>
                        <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
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
 * Render executor pool settings
 */
function renderExecutorSettings() {
    const container = document.getElementById('executor-settings-content');
    if (!container) return;
    
    // First render the presets dropdown
    let html = `
        <div class="results-container">
            <h2>Executor Pool Presets</h2>
            <div style="display: flex; align-items: center; gap: 15px; margin: 15px 0; padding: 10px; 
                 background-color: var(--results-container-bg); border-radius: 5px;">
                <select id="executor-preset-select" 
                        style="flex: 1; padding: 8px; border: 1px solid var(--results-container-border); 
                        border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    <option value="">Select a preset...</option>
                    ${settingsState.executorSettings.presets.map(preset => 
                        `<option value="${preset.name}">${preset.name} - ${preset.description}</option>`
                    ).join('')}
                </select>
                <button id="apply-preset-btn" 
                        style="background-color: var(--button-bg); color: var(--button-text); 
                        border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer;">
                    Apply Preset
                </button>
            </div>
        </div>

        <div class="results-container">
            <h2>Current Settings</h2>
            <div style="display: grid; grid-template-columns: 1fr; gap: 10px;">
    `;
    
    // Then render individual settings
    settingsState.executorSettings.settings.forEach(setting => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-name="${setting.name}" data-type="executor">
                <div style="flex: 1; padding-right: 15px;">
                    <label for="exec-setting-${setting.name}" style="font-weight: bold; color: var(--text-color);">
                        ${formatSettingName(setting.name)}
                    </label>
                    <div style="font-size: 0.9em; color: var,--text-muted); margin-top: 5px;">
                        ${setting.description}
                    </div>
                    <div style="display: inline-block; font-size: 0.8em; background-color: var(--bg-color); 
                         color: var(--text-color); padding: 2px 6px; border-radius: 10px; margin-top: 5px;">
                        ${setting.is_time ? 'Time (seconds)' : 'Value'}
                    </div>
                </div>
                <div>
                    <input type="number" id="exec-setting-${setting.name}" value="${setting.value}"
                           min="1" ${setting.is_time ? 'step="1"' : 'step="1"'}
                           style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                           border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                </div>
            </div>
        `;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
    
    // Add event listener to apply preset button
    const applyBtn = document.getElementById('apply-preset-btn');
    if (applyBtn) {
        applyBtn.addEventListener('click', applyExecutorPreset);
        // Add hover effect
        applyBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        applyBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
}

/**
 * Update the UI loading state
 * @param {boolean} isLoading - Whether the UI is in a loading state
 */

/**
 * Apply an executor pool preset
 */
async function applyExecutorPreset() {
    try {
        const selectEl = document.getElementById('executor-preset-select');
        const presetName = selectEl.value;
        
        if (!presetName) {
            showNotification('warning', 'Please select a preset to apply');
            return;
        }
        
        // Show loading state
        updateLoadingState(true);
        
        // Call the Python function to apply the preset
        const result = await eel.apply_executor_pool_preset(presetName)();
        
        if (result.success) {
            showNotification('success', `Applied preset "${presetName}" successfully`);
            
            // Reload settings to show updated values
            await loadAllSettings();
        } else {
            showNotification('error', `Failed to apply preset: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error applying preset:', error);
        showNotification('error', 'An error occurred while applying the preset');
    } finally {
        updateLoadingState(false);
    }
}

function updateLoadingState(isLoading) {
    const loader = document.getElementById('settings-loader');
    if (loader) {
        loader.style.display = isLoading ? 'block' : 'none';
        loader.style.backgroundColor = 'var(--container-bg)';
        loader.style.color = 'var(--text-color)';
    }
    
    // Update save button styling
    const saveBtn = document.getElementById('save-settings-btn');
    if (saveBtn) {
        saveBtn.disabled = isLoading;
        saveBtn.style.backgroundColor = isLoading ? '#ccc' : 'var(--button-bg)';
        saveBtn.style.color = 'var(--button-text)';
        saveBtn.style.cursor = isLoading ? 'not-allowed' : 'pointer';
    }
    
    // Update reset button styling
    const resetBtn = document.getElementById('reset-settings-btn');
    if (resetBtn) {
        resetBtn.disabled = isLoading;
        resetBtn.style.backgroundColor = isLoading ? '#ccc' : 'var(--bg-color)';
        resetBtn.style.color = isLoading ? '#999' : 'var(--text-color)';
        resetBtn.style.cursor = isLoading ? 'not-allowed' : 'pointer';
    }
    
    // Disable/enable form controls during loading
    document.querySelectorAll('.settings-form input, .settings-form select, .settings-form button, textarea')
        .forEach(el => {
            el.disabled = isLoading;
        });
}

/**
 * Save all modified settings
 */
async function saveAllSettings() {
    updateLoadingState(true);
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
        
        // Save executor settings
        const execSettings = document.querySelectorAll('div[data-type="executor"]');
        for (const settingEl of execSettings) {
            const name = settingEl.dataset.name;
            const inputEl = document.getElementById(`exec-setting-${name}`);
            
            if (!inputEl) continue;
            
            const value = parseInt(inputEl.value);
            
            const result = await eel.update_executor_pool_setting(name, value)();
            result.success ? successCount++ : errorCount++;
        }
        
        // Save validation scoring settings
        const scoringSettings = document.querySelectorAll('div[data-type="scoring"]');
        for (const settingEl of scoringSettings) {
            const id = settingEl.dataset.id;
            const valueEl = document.getElementById(`scoring-value-${id}`);
            const penaltyEl = document.getElementById(`scoring-penalty-${id}`);
            
            if (!valueEl || !penaltyEl) continue;
            
            const value = parseInt(valueEl.value);
            const isPenalty = penaltyEl.checked;
            
            const result = await eel.update_validation_scoring(parseInt(id), value, isPenalty)();
            result.success ? successCount++ : errorCount++;
        }
        
        // Save confidence level settings
        const confidenceSettings = document.querySelectorAll('div[data-type="confidence"]');
        for (const settingEl of confidenceSettings) {
            const id = settingEl.dataset.id;
            const minEl = document.getElementById(`confidence-min-${id}`);
            const maxEl = document.getElementById(`confidence-max-${id}`);
            
            if (!minEl || !maxEl) continue;
            
            const min = parseInt(minEl.value);
            const max = parseInt(maxEl.value);
            
            const result = await eel.update_confidence_level(parseInt(id), min, max)();
            result.success ? successCount++ : errorCount++;
        }
        
        // Save port settings
        const portSettings = document.querySelectorAll('div[data-type="port"]');
        for (const settingEl of portSettings) {
            const id = settingEl.dataset.id;
            const priorityEl = document.getElementById(`port-priority-${id}`);
            const enabledEl = document.getElementById(`port-enabled-${id}`);
            
            if (!priorityEl || !enabledEl) continue;
            
            const priority = parseInt(priorityEl.value);
            const enabled = enabledEl.checked;
            
            const result = await eel.update_port(parseInt(id), priority, enabled)();
            result.success ? successCount++ : errorCount++;
        }
        
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
        
        // We don't save the black/white list here as it has dedicated add/remove/update functions
        
        if (errorCount === 0) {
            showNotification('success', `Successfully saved ${successCount} settings`);
        } else {
            showNotification('warning', `Saved ${successCount} settings, but ${errorCount} failed`);
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        showNotification('error', 'An error occurred while saving settings');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Render validation scoring settings
 */
function renderValidationScoring() {
    const container = document.getElementById('validation-scoring-content');
    if (!container) return;
    
    let html = '<div class="results-container"><h2>Validation Scoring</h2><div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    settingsState.validationScoring.forEach(setting => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="scoring">
                <div style="flex: 1; padding-right: 15px;">
                    <label for="scoring-value-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                        ${setting.check_name}
                    </label>
                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                        ${setting.description}
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <input type="number" id="scoring-value-${setting.id}" value="${setting.score_value}"
                           min="0" step="1"
                           style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                           border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    <label style="display: flex; align-items: center; gap: 5px;">
                        <span>Is Penalty</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="scoring-penalty-${setting.id}" 
                                   ${setting.is_penalty ? "checked" : ""}>
                            <span class="toggle-slider round"></span>
                        </label>
                    </label>
                </div>
            </div>
        `;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
}

/**
 * Render confidence level settings
 */
function renderConfidenceLevels() {
    const container = document.getElementById('confidence-levels-content');
    if (!container) return;
    
    let html = '<div class="results-container"><h2>Confidence Levels</h2><div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    settingsState.confidenceLevels.forEach(level => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${level.id}" data-type="confidence">
                <div style="flex: 1; padding-right: 15px;">
                    <label style="font-weight: bold; color: var(--text-color);">
                        ${level.level_name}
                    </label>
                    <div style="font-size: 0.9em; color: var,--text-muted); margin-top: 5px;">
                        ${level.description}
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <div>
                        <label for="confidence-min-${level.id}">Min</label>
                        <input type="number" id="confidence-min-${level.id}" value="${level.min_threshold}"
                               min="0" max="100" step="1"
                               style="width: 60px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    </div>
                    <div>
                        <label for="confidence-max-${level.id}">Max</label>
                        <input type="number" id="confidence-max-${level.id}" value="${level.max_threshold}"
                               min="0" max="100" step="1"
                               style="width: 60px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
                    </div>
                </div>
            </div>
        `;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
}

/**
 * Render ports configuration
 */
function renderPortsConfiguration() {
    const container = document.getElementById('ports-configuration-content');
    if (!container) return;
    
    // Group by category
    const groupedPorts = {};
    settingsState.portsConfiguration.forEach(port => {
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
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div>
                            <label for="port-priority-${port.id}">Priority</label>
                            <input type="number" id="port-priority-${port.id}" value="${port.priority}"
                                   min="1" step="1"
                                   style="width: 60px; padding: 8px; border: 1px solid var(--results-container-border); 
                                   border-radius: 4px; background-color: var(--bg-color); color: var,--text-color);">
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
                </div>
            `;
        });
        
        html += `</div></div>`;
    }
    
    container.innerHTML = html;
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
                    ${settingsState.emailFilterRegex.presets.map(preset => 
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
    
    settingsState.emailFilterRegex.settings.forEach(setting => {
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
        updateLoadingState(true);
        
        // Call the Python function to apply the preset
        const result = await eel.apply_email_filter_regex_preset(presetId)();
        
        if (result.success) {
            showNotification('success', 'Applied email filter regex preset successfully');
            
            // Reload settings to show updated values
            await loadAllSettings();
        } else {
            showNotification('error', `Failed to apply preset: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error applying email filter regex preset:', error);
        showNotification('error', 'An error occurred while applying the preset');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Render black/white list
 */
function renderBlackWhiteList() {
    const container = document.getElementById('black-white-list-content');
    if (!container) return;
    
    let html = `
        <div class="results-container">
            <h2>Domain Black/White List</h2>
            
            <!-- Add new domain form -->
            <div style="display: flex; gap: 10px; margin: 15px 0; padding: 15px; background-color: var(--results-container-bg); border-radius: 5px;">
                <input type="text" id="new-domain-input" placeholder="Enter domain (e.g., example.com)"
                       style="flex: 1; padding: 8px; border: 1px solid var(--results-container-border); border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                <select id="new-domain-category"
                        style="padding: 8px; border: 1px solid var(--results-container-border); border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                    <option value="blacklisted">Blacklist</option>
                    <option value="whitelisted">Whitelist</option>
                </select>
                <button id="add-domain-btn"
                        style="background-color: var(--button-bg); color: var(--button-text); border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer;">
                    Add
                </button>
            </div>
            
            <!-- Domain list -->
            <div style="margin-top: 20px;">
                <table style="width: 100%; border-collapse: collapse; background-color: var(--results-container-bg); border-radius: 5px;">
                    <thead>
                        <tr>
                            <th style="text-align: left; padding: 12px; border-bottom: 1px solid var(--results-container-border);">Domain</th>
                            <th style="text-align: left; padding: 12px; border-bottom: 1px solid var(--results-container-border);">Status</th>
                            <th style="text-align: left; padding: 12px; border-bottom: 1px solid var(--results-container-border);">Added By</th>
                            <th style="text-align: left; padding: 12px; border-bottom: 1px solid var(--results-container-border);">Date Added</th>
                            <th style="text-align: center; padding: 12px; border-bottom: 1px solid var(--results-container-border);">Actions</th>
                        </tr>
                    </thead>
                    <tbody>`;
    
    if (settingsState.blackWhiteList.length === 0) {
        html += `
            <tr>
                <td colspan="5" style="text-align: center; padding: 20px;">
                    No domains in the black/white list
                </td>
            </tr>`;
    } else {
        settingsState.blackWhiteList.forEach(domain => {
            const isBlacklisted = domain.category === 'blacklisted';
            
            html += `
                <tr data-id="${domain.id}" data-type="black-white">
                    <td style="padding: 12px; border-bottom: 1px solid var(--results-container-border);">
                        ${domain.domain}
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid var(--results-container-border);">
                        <span style="display: inline-block; padding: 4px 8px; border-radius: 4px; 
                              background-color: ${isBlacklisted ? 'rgba(255,0,0,0.1)' : 'rgba(0,255,0,0.1)'}; 
                              color: ${isBlacklisted ? '#ff6666' : '#66cc66'};">
                            ${isBlacklisted ? 'Blacklisted' : 'Whitelisted'}
                        </span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid var(--results-container-border);">
                        ${domain.added_by}
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid var(--results-container-border);">
                        ${formatDate(domain.timestamp)}
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid var(--results-container-border); text-align: center;">
                        <button class="toggle-domain-btn" data-id="${domain.id}" data-current="${domain.category}"
                                style="margin-right: 10px; padding: 4px 8px; background-color: var(--bg-color); 
                                border: 1px solid var(--results-container-border); border-radius: 4px; cursor: pointer;">
                            ${isBlacklisted ? 'Move to Whitelist' : 'Move to Blacklist'}
                        </button>
                        <button class="remove-domain-btn" data-id="${domain.id}"
                                style="padding: 4px 8px; background-color: rgba(255,0,0,0.1); color: #ff6666; 
                                border: 1px solid #ff6666; border-radius: 4px; cursor: pointer;">
                            Remove
                        </button>
                    </td>
                </tr>`;
        });
    }
    
    html += `
                    </tbody>
                </table>
            </div>
        </div>`;
    
    container.innerHTML = html;
    
    // Add domain button listener
    const addDomainBtn = document.getElementById('add-domain-btn');
    if (addDomainBtn) {
        addDomainBtn.addEventListener('click', addDomainToList);
        // Add hover effect
        addDomainBtn.addEventListener('mouseover', function() {
            this.style.backgroundColor = 'var(--button-hover)';
        });
        addDomainBtn.addEventListener('mouseout', function() {
            this.style.backgroundColor = 'var(--button-bg)';
        });
    }
    
    // Toggle domain category buttons
    document.querySelectorAll('.toggle-domain-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = parseInt(this.dataset.id);
            const currentCategory = this.dataset.current;
            const newCategory = currentCategory === 'blacklisted' ? 'whitelisted' : 'blacklisted';
            
            updateDomainCategory(id, newCategory);
        });
    });
    
    // Remove domain buttons
    document.querySelectorAll('.remove-domain-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = parseInt(this.dataset.id);
            removeDomainFromList(id);
        });
    });
}

/**
 * Add a domain to the black/white list
 */
async function addDomainToList() {
    try {
        const domainInput = document.getElementById('new-domain-input');
        const categorySelect = document.getElementById('new-domain-category');
        
        const domain = domainInput.value.trim();
        const category = categorySelect.value;
        
        if (!domain) {
            showNotification('warning', 'Please enter a domain');
            return;
        }
        
        // Simple domain validation
        if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i.test(domain)) {
            showNotification('error', 'Please enter a valid domain name');
            return;
        }
        
        // Show loading state
        updateLoadingState(true);
        
        // Call the Python function to add the domain
        const result = await eel.add_domain_to_list(domain, category, 'UI')();
        
        if (result.success) {
            showNotification('success', `Added ${domain} to the ${category === 'blacklisted' ? 'blacklist' : 'whitelist'}`);
            domainInput.value = '';
            
            // Reload the black/white list
            const blackWhiteResult = await eel.get_black_white_list()();
            if (blackWhiteResult.success) {
                settingsState.blackWhiteList = blackWhiteResult.domains;
                renderBlackWhiteList();
            }
        } else {
            showNotification('error', `Failed to add domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error adding domain:', error);
        showNotification('error', 'An error occurred while adding the domain');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Update a domain's category in the black/white list
 */
async function updateDomainCategory(id, newCategory) {
    try {
        // Show loading state
        updateLoadingState(true);
        
        // Call the Python function to update the domain
        const result = await eel.update_domain_category(id, newCategory)();
        
        if (result.success) {
            showNotification('success', `Updated domain to ${newCategory === 'blacklisted' ? 'blacklist' : 'whitelist'}`);
            
            // Reload the black/white list
            const blackWhiteResult = await eel.get_black_white_list()();
            if (blackWhiteResult.success) {
                settingsState.blackWhiteList = blackWhiteResult.domains;
                renderBlackWhiteList();
            }
        } else {
            showNotification('error', `Failed to update domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error updating domain:', error);
        showNotification('error', 'An error occurred while updating the domain');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Remove a domain from the black/white list
 */
async function removeDomainFromList(id) {
    try {
        // Show loading state
        updateLoadingState(true);
        
        // Call the Python function to remove the domain
        const result = await eel.remove_domain_from_list(id)();
        
        if (result.success) {
            showNotification('success', 'Removed domain from the list');
            
            // Reload the black/white list
            const blackWhiteResult = await eel.get_black_white_list()();
            if (blackWhiteResult.success) {
                settingsState.blackWhiteList = blackWhiteResult.domains;
                renderBlackWhiteList();
            }
        } else {
            showNotification('error', `Failed to remove domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error removing domain:', error);
        showNotification('error', 'An error occurred while removing the domain');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Run executor autotune
 */
async function runExecutorAutotune() {
    try {
        // Show loading state
        updateLoadingState(true);
        
        // Display a message that this might take some time
        showNotification('info', 'Running executor pool autotune. This may take a few moments...', true);
        
        // Call the Python function to run autotune
        const result = await eel.run_executor_autotune(true)();
        
        if (result.success) {
            showNotification('success', 'Executor pool autotune completed successfully');
            
            // Display the results in a more readable format
            let detailedResults = 'Autotune results:\n';
            if (result.results && typeof result.results === 'object') {
                detailedResults += Object.entries(result.results)
                    .map(([key, value]) => `${key}: ${value}`)
                    .join('\n');
            }
            
            // Show detailed results in console
            console.log(detailedResults);
            
            // Reload settings to show updated values
            await loadAllSettings();
        } else {
            showNotification('error', `Failed to run autotune: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error running executor autotune:', error);
        showNotification('error', 'An error occurred while running autotune');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Format a date string
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Execute when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Test tab button event listeners
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            console.log('Tab clicked:', this.dataset.tab);
            switchSettingsTab(this.dataset.tab);
        });
    });
});