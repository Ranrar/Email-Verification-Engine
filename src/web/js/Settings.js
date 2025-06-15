/**
 * Settings Menu for Email Verification Engine
 * Coordinates the modular settings components
 */

// Coordinator state
const settingsState = {
    loading: false,
    currentTab: 'general',
    initialized: false,
    originalData: {},           // Store original values by section
    changedSections: new Set(), // Track which sections have changes
    changedFields: new Map()    // Track individual field changes: Map<fieldId, {original, current, section}>
};

/**
 * Initialize the settings menu and handle panel management
 */
async function initSettingsMenu() {
    // Only initialize once
    if (settingsState.initialized) {
        return;
    }

    // Initialize tab buttons with proper CSS classes
    const tabButtons = document.querySelectorAll('.settings-tab-btn');
    tabButtons.forEach(btn => {
        // Use CSS utility classes instead of inline styles
        btn.classList.add('text-center');
        
        // Remove inline styles and rely on CSS classes
        btn.style.whiteSpace = 'nowrap';
        btn.style.flexShrink = '0';
    });
    
    // Initialize tabs container with CSS classes
    const tabsContainer = document.querySelector('.settings-tabs');
    if (tabsContainer) {
        tabsContainer.classList.add('flex');
        // The CSS already handles overflow-x: auto and scrollbar hiding
    }

    // Add event listeners to tab buttons
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchSettingsTab(btn.dataset.tab));  
    });

    // Load initial data
    await loadAllSettings();
    
    // Initialize save button with proper CSS classes
    const saveButton = document.getElementById('save-settings-btn');
    if (saveButton) {
        saveButton.classList.add('btn');
        saveButton.addEventListener('click', saveChangedSettings);
        saveButton.disabled = true; // Start disabled
    }
    
    // Initialize reset button with proper CSS classes
    const resetButton = document.getElementById('reset-settings-btn');
    if (resetButton) {
        resetButton.classList.add('btn', 'btn-cancel');
        resetButton.addEventListener('click', () => loadAllSettings());
    }
    
    // Initialize autotune button with proper CSS classes and hover effects
    const autotuneBtn = document.getElementById('run-autotune-btn');
    if (autotuneBtn) {
        autotuneBtn.classList.add('btn');
        autotuneBtn.addEventListener('click', runExecutorAutotune);
        
        // Remove inline style event listeners - CSS handles hover states
    }
    
    // Mark as initialized
    settingsState.initialized = true;
}

/**
 * Switch between settings tabs using CSS classes
 * @param {string} tabName - The name of the tab to show
 */
function switchSettingsTab(tabName) {
    // Update active tab button using CSS classes
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    
    // Update visible tab content
    document.querySelectorAll('.settings-tab-content').forEach(tab => {
        const shouldShow = tab.id === `${tabName}-settings`;
        tab.style.display = shouldShow ? 'block' : 'none';
        
        // Debug - log what's happening
        console.log(`Tab ${tab.id}: ${shouldShow ? 'showing' : 'hiding'}`);
    });
    
    settingsState.currentTab = tabName;
    console.log(`Current tab: ${tabName}`);
}

/**
 * Store original data for change detection
 */
function storeOriginalData(sectionName, data) {
    settingsState.originalData[sectionName] = JSON.parse(JSON.stringify(data));
    console.log(`Stored original data for ${sectionName}:`, settingsState.originalData[sectionName]);
}

/**
 * Store original field values for all form elements
 */
function storeOriginalFieldValues() {
    const allInputs = document.querySelectorAll('.settings-form input, .settings-form select, .settings-form textarea');
    
    allInputs.forEach(element => {
        const currentValue = getElementValue(element);
        element.dataset.originalValue = currentValue;
        
        // Find which section this element belongs to
        const section = findElementSection(element);
        if (section) {
            const fieldKey = `${section}-${element.id || element.name}`;
            settingsState.changedFields.set(fieldKey, {
                original: currentValue,
                current: currentValue,
                section: section,
                element: element
            });
        }
    });
    
    console.log('Stored original field values for', settingsState.changedFields.size, 'fields');
}

/**
 * Get the value of a form element regardless of type
 */
function getElementValue(element) {
    if (element.type === 'checkbox') {
        return element.checked;
    } else if (element.type === 'radio') {
        return element.checked ? element.value : null;
    } else {
        return element.value || '';
    }
}

/**
 * Find which section a form element belongs to
 */
function findElementSection(element) {
    const tabContent = element.closest('.settings-tab-content');
    if (tabContent) {
        return tabContent.id.replace('-settings', '');
    }
    return null;
}

/**
 * Check if a field has changed
 */
function hasFieldChanged(fieldKey) {
    const fieldData = settingsState.changedFields.get(fieldKey);
    if (!fieldData) return false;
    
    const currentValue = getElementValue(fieldData.element);
    return currentValue !== fieldData.original;
}

/**
 * Mark a section as changed and update UI
 */
function markSectionChanged(sectionName) {
    settingsState.changedSections.add(sectionName);
    updateSaveButtonState();
    
    // Add visual indicator to the tab
    const tabButton = document.querySelector(`[data-tab="${sectionName}"]`);
    if (tabButton && !tabButton.classList.contains('has-changes')) {
        tabButton.classList.add('has-changes');
        // Add a visual indicator (dot or asterisk)
        if (!tabButton.querySelector('.change-indicator')) {
            const indicator = document.createElement('span');
            indicator.className = 'change-indicator';
            indicator.textContent = ' •';
            indicator.style.color = 'var(--accent-color, #007bff)';
            tabButton.appendChild(indicator);
        }
    }
}

/**
 * Clear changes for a section
 */
function clearSectionChanges(sectionName) {
    settingsState.changedSections.delete(sectionName);
    updateSaveButtonState();
    
    // Remove visual indicator from the tab
    const tabButton = document.querySelector(`[data-tab="${sectionName}"]`);
    if (tabButton) {
        tabButton.classList.remove('has-changes');
        const indicator = tabButton.querySelector('.change-indicator');
        if (indicator) {
            indicator.remove();
        }
    }
    
    // Update stored original values for this section
    const sectionFields = Array.from(settingsState.changedFields.entries())
        .filter(([key, data]) => data.section === sectionName);
    
    sectionFields.forEach(([key, data]) => {
        const currentValue = getElementValue(data.element);
        data.original = currentValue;
        data.current = currentValue;
        data.element.dataset.originalValue = currentValue;
        settingsState.changedFields.set(key, data);
    });
}

/**
 * Update save button to show change status
 */
function updateSaveButtonState() {
    const saveBtn = document.getElementById('save-settings-btn');
    if (!saveBtn) return;
    
    const changeCount = settingsState.changedSections.size;
    
    if (changeCount > 0) {
        saveBtn.classList.add('btn-has-changes');
        saveBtn.textContent = `Save Changes (${changeCount})`;
        saveBtn.disabled = false;
        saveBtn.style.backgroundColor = 'var(--accent-color, #007bff)';
    } else {
        saveBtn.classList.remove('btn-has-changes');
        saveBtn.textContent = 'Save Settings';
        saveBtn.disabled = true;
        saveBtn.style.backgroundColor = '';
    }
}

/**
 * Add comprehensive change detection to form elements
 */
function addChangeDetection() {
    console.log('Setting up change detection...');
    
    // Store original values first
    storeOriginalFieldValues();
    
    // Add change listeners to all form inputs
    const allInputs = document.querySelectorAll('.settings-form input, .settings-form select, .settings-form textarea');
    
    allInputs.forEach(element => {
        // Multiple event types for comprehensive detection
        const events = ['change', 'input', 'blur'];
        
        events.forEach(eventType => {
            element.addEventListener(eventType, function(event) {
                handleFieldChange(this, event.type);
            });
        });
    });
    
    console.log(`Added change detection to ${allInputs.length} form elements`);
}

/**
 * Handle individual field changes
 */
function handleFieldChange(element, eventType) {
    const section = findElementSection(element);
    if (!section) return;
    
    const fieldKey = `${section}-${element.id || element.name}`;
    const fieldData = settingsState.changedFields.get(fieldKey);
    
    if (!fieldData) {
        console.warn(`No field data found for ${fieldKey}`);
        return;
    }
    
    const currentValue = getElementValue(element);
    const originalValue = fieldData.original;
    const hasChanged = currentValue !== originalValue;
    
    // Update current value
    fieldData.current = currentValue;
    settingsState.changedFields.set(fieldKey, fieldData);
    
    // Check if any field in this section has changes
    const sectionHasChanges = Array.from(settingsState.changedFields.entries())
        .filter(([key, data]) => data.section === section)
        .some(([key, data]) => data.current !== data.original);
    
    if (sectionHasChanges) {
        markSectionChanged(section);
    } else {
        clearSectionChanges(section);
    }
    
    // Debug logging
    if (hasChanged) {
        console.log(`Field changed: ${fieldKey}`, {
            original: originalValue,
            current: currentValue,
            section: section
        });
    }
}

/**
 * Get only changed values for a section
 */
function getChangedValuesForSection(sectionName) {
    const changes = {};
    
    Array.from(settingsState.changedFields.entries())
        .filter(([key, data]) => data.section === sectionName && data.current !== data.original)
        .forEach(([key, data]) => {
            const element = data.element;
            const fieldId = element.id || element.name;
            const settingId = element.dataset.id || fieldId;
            
            changes[settingId] = {
                original: data.original,
                current: data.current,
                element: element,
                fieldId: fieldId
            };
        });
    
    return changes;
}

/**
 * Load all settings from the database
 */
async function loadAllSettings() {
    settingsState.loading = true;
    updateLoadingState(true);
    
    try {
        // Load all settings modules
        const loadResults = await Promise.all([
            loadGeneralSettings(),
            loadRateLimitSettings(),
            loadDNSSettings(),
            loadExecutorSettings(),
            loadValidationSettings(),
            loadPortsConfiguration(),
            loadEmailFilterRegexSettings(),
            loadBlackWhiteList()
        ]);
        
        // Store original data for each section
        const sectionNames = ['general', 'rate-limits', 'dns', 'executor', 'validation-scoring', 'ports', 'email-filter', 'black-white-list'];
        loadResults.forEach((result, index) => {
            if (result && result.success) {
                storeOriginalData(sectionNames[index], result);
            }
        });
        
        // Clear all change markers after loading
        settingsState.changedSections.clear();
        settingsState.changedFields.clear();
        
        // Wait for DOM to update, then setup change detection
        setTimeout(() => {
            addChangeDetection();
            updateSaveButtonState();
        }, 100);
        
        // Use global show_message function directly
        if (typeof window.show_message === 'function') {
            window.show_message('success', 'Settings loaded successfully', false, null);
        }
        
    } catch (error) {
        console.error('Error loading settings:', error);
        // Use global show_message function directly
        if (typeof window.show_message === 'function') {
            window.show_message('error', 'An error occurred while loading settings', true, error.message);
        }
    } finally {
        settingsState.loading = false;
        updateLoadingState(false);
    }
}

/**
 * Update the UI loading state
 * @param {boolean} isLoading - Whether the UI is in a loading state
 */
function updateLoadingState(isLoading) {
    const loader = document.getElementById('settings-loader');
    if (loader) {
        loader.style.display = isLoading ? 'block' : 'none';
        loader.classList.add('loader', 'text-center');
        // Remove inline styles - CSS variables handle theming
    }
    
    // Update buttons using CSS classes and proper disabled states
    const saveBtn = document.getElementById('save-settings-btn');
    if (saveBtn) {
        saveBtn.disabled = isLoading;
        saveBtn.classList.toggle('btn-disabled', isLoading);
        // CSS handles the visual state changes
    }
    
    const resetBtn = document.getElementById('reset-settings-btn');
    if (resetBtn) {
        resetBtn.disabled = isLoading;
        resetBtn.classList.toggle('btn-disabled', isLoading);
        // CSS handles the visual state changes
    }
    
    // Disable/enable form controls during loading
    document.querySelectorAll('.settings-form input, .settings-form select, .settings-form button, .settings-form textarea')
        .forEach(el => {
            el.disabled = isLoading;
            el.classList.toggle('disabled', isLoading);
        });
}

/**
 * Save only changed settings sections
 */
async function saveChangedSettings() {
    if (settingsState.changedSections.size === 0) {
        if (typeof window.show_message === 'function') {
            window.show_message('info', 'No changes to save', false, null);
        }
        return;
    }
    
    updateLoadingState(true);
    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    const changedSectionsArray = Array.from(settingsState.changedSections);
    
    try {
        console.log(`Saving ${changedSectionsArray.length} changed sections:`, changedSectionsArray);
        
        for (const sectionName of changedSectionsArray) {
            try {
                console.log(`Processing section: ${sectionName}`);
                const changedValues = getChangedValuesForSection(sectionName);
                const changeCount = Object.keys(changedValues).length;
                
                if (changeCount === 0) {
                    console.log(`No actual changes found in section ${sectionName}, skipping`);
                    clearSectionChanges(sectionName);
                    continue;
                }
                
                console.log(`Found ${changeCount} changed fields in ${sectionName}:`, changedValues);
                
                // Call the appropriate save function for this section
                let result;
                switch (sectionName) {
                    case 'general':
                        result = await saveOnlyChangedFields(changedValues, 'general');
                        break;
                    case 'rate-limits':
                        result = await saveOnlyChangedFields(changedValues, 'rate-limits');
                        break;
                    case 'dns':
                        result = await saveOnlyChangedFields(changedValues, 'dns');
                        break;
                    case 'executor':
                        result = await saveOnlyChangedFields(changedValues, 'executor');
                        break;
                    case 'validation-scoring':
                        result = await saveOnlyChangedFields(changedValues, 'validation');
                        break;
                    case 'ports':
                        result = await saveOnlyChangedFields(changedValues, 'ports');
                        break;
                    default:
                        console.warn(`No save handler for section: ${sectionName}`);
                        result = { success: 0, errors: 1 };
                }
                
                if (result && result.success > 0) {
                    successCount += result.success;
                    clearSectionChanges(sectionName);
                    console.log(`Successfully saved ${result.success} changes in ${sectionName}`);
                }
                
                if (result && result.errors > 0) {
                    errorCount += result.errors;
                    errors.push(`${sectionName}: ${result.errors} errors`);
                }
                
            } catch (error) {
                console.error(`Error saving section ${sectionName}:`, error);
                errors.push(`${sectionName}: ${error.message || 'Save failed'}`);
                errorCount++;
            }
        }
        
        // Show result notification
        if (errorCount === 0) {
            if (typeof window.show_message === 'function') {
                window.show_message('success', `Successfully saved ${successCount} changed settings`, false, null);
            }
        } else {
            if (typeof window.show_message === 'function') {
                const message = `Saved ${successCount} settings, ${errorCount} failed`;
                window.show_message('warning', message, true, errors.join(', '));
            }
            console.warn('Save errors:', errors);
        }
        
    } catch (error) {
        console.error('Error in saveChangedSettings:', error);
        if (typeof window.show_message === 'function') {
            window.show_message('error', 'An error occurred while saving settings', true, error.message);
        }
    } finally {
        updateLoadingState(false);
        updateSaveButtonState();
    }
}

/**
 * Save only the changed fields for a specific section
 */
async function saveOnlyChangedFields(changedValues, sectionType) {
    let successCount = 0;
    let errorCount = 0;
    
    console.log(`Saving changed fields for ${sectionType}:`, changedValues);
    
    for (const [settingId, change] of Object.entries(changedValues)) {
        try {
            let result;
            const element = change.element;
            const value = change.current;
            
            console.log(`Saving ${sectionType} setting ${settingId}: ${change.original} → ${value}`);
            
            switch (sectionType) {
                case 'general':
                    result = await eel.update_app_setting(parseInt(settingId), String(value))();
                    break;
                case 'rate-limits':
                    const enabled = element.type === 'checkbox' ? value : element.closest('div').querySelector('input[type="checkbox"]')?.checked || false;
                    result = await eel.update_rate_limit(parseInt(settingId), String(value), enabled)();
                    break;
                case 'dns':
                    result = await eel.update_dns_setting(parseInt(settingId), String(value))();
                    break;
                case 'executor':
                    const settingName = element.dataset.setting || element.name;
                    result = await eel.update_executor_setting(settingName, String(value))();
                    break;
                case 'validation':
                    const isPenalty = element.dataset.penalty === 'true';
                    result = await eel.update_validation_scoring(parseInt(settingId), parseInt(value), isPenalty)();
                    break;
                case 'ports':
                    const priority = 0; // Keep existing priority
                    result = await eel.update_port(parseInt(settingId), priority, Boolean(value))();
                    break;
                default:
                    console.warn(`Unknown section type: ${sectionType}`);
                    result = { success: false };
            }
            
            if (result && result.success !== false) {
                successCount++;
                console.log(`✓ Successfully saved ${sectionType} setting ${settingId}`);
            } else {
                errorCount++;
                console.error(`✗ Failed to save ${sectionType} setting ${settingId}:`, result);
            }
            
        } catch (error) {
            errorCount++;
            console.error(`Error saving ${sectionType} setting ${settingId}:`, error);
        }
    }
    
    return { success: successCount, errors: errorCount };
}

// Enhanced coordinator state with comprehensive change tracking
const enhancedSettingsState = {
    loading: false,
    currentTab: 'general',
    initialized: false,
    originalData: {},      // Store original values
    changedSections: new Set()  // Track which sections have changes
};

/**
 * Open settings panel with improved CSS handling
 */
function openSettingsPanel(tabName = 'general') {
    console.log(`Opening settings panel: ${tabName}`);
    
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) {
        console.error('Settings panel element not found');
        return;
    }
    
    // Use CSS classes for display control
    settingsPanel.classList.add('settings-overlay-active');
    settingsPanel.style.display = 'flex';
    
    // Setup close button with proper styles and event listener
    const closeBtn = document.getElementById('closeSettingsBtn');
    if (closeBtn) {
        closeBtn.classList.add('settings-close-btn');
        closeBtn.addEventListener('click', closeSettingsPanel);
    }
    
    // Initialize settings if needed
    initSettingsMenu().then(() => {
        if (tabName) {
            switchSettingsTab(tabName);
        }
    }).catch(error => {
        console.error('Error initializing settings menu:', error);
    });
    
    document.body.classList.add('modal-open');
}

/**
 * Close settings panel with CSS classes
 */
function closeSettingsPanel() {
    console.log('Closing settings panel');
    
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) return;
    
    settingsPanel.classList.remove('settings-overlay-active');
    settingsPanel.style.display = 'none';
    document.body.classList.remove('modal-open');
}

// ===== EXPOSE FUNCTIONS GLOBALLY =====
// Make functions available to other modules and main.js
window.openSettingsPanel = openSettingsPanel;
window.closeSettingsPanel = closeSettingsPanel;
window.initSettingsMenu = initSettingsMenu;
window.switchSettingsTab = switchSettingsTab;
window.saveChangedSettings = saveChangedSettings;
window.loadAllSettings = loadAllSettings;
window.updateLoadingState = updateLoadingState;

console.log('Settings.js functions exposed globally:', {
    openSettingsPanel: typeof openSettingsPanel,
    closeSettingsPanel: typeof closeSettingsPanel,
    initSettingsMenu: typeof initSettingsMenu,
    switchSettingsTab: typeof switchSettingsTab
});