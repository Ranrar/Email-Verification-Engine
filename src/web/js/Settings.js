/**
 * Settings Menu for Email Verification Engine
 * Coordinates the modular settings components
 */

// Import settings modules
import {
    capitalizeFirstLetter,
    formatSettingName,
    showNotification,
    generalState,
    loadGeneralSettings,
    renderAppSettings,
    saveGeneralSettings
} from './settings/general.js';

import {
    rateLimitState,
    loadRateLimitSettings,
    renderRateLimits,
    saveRateLimitSettings
} from './settings/rate_limit.js';

import {
    dnsState,
    loadDNSSettings,
    renderDNSSettings,
    saveDNSSettings
} from './settings/dns.js';

import {
    executorState,
    loadExecutorSettings,
    renderExecutorSettings,
    saveExecutorSettings,
    applyExecutorPreset,
    runExecutorAutotune
} from './settings/exe.js';

import {
    validationState,
    loadValidationSettings,
    renderValidationScoring,
    saveValidationSettings
} from './settings/validation.js';

import {
    portState,
    loadPortsConfiguration,
    renderPortsConfiguration,
    savePortsConfiguration
} from './settings/port.js';

import {
    emailFilterState,
    loadEmailFilterRegexSettings,
    renderEmailFilterRegexSettings,
    applyEmailFilterRegexPreset,
    saveEmailFilterRegexSettings,
    formatDate
} from './settings/regex.js';

import {
    bwState,
    loadBlackWhiteList,
    renderBlackWhiteList,
    addDomainToList,
    updateDomainCategory,
    removeDomainFromList
} from './settings/bw.js';

// Coordinator state
const settingsState = {
    loading: false,
    currentTab: 'general',
    initialized: false
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
        saveButton.addEventListener('click', saveAllSettings);
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
 * Load all settings from the database
 */
async function loadAllSettings() {
    settingsState.loading = true;
    updateLoadingState(true);
    
    try {
        // Load all settings modules
        await Promise.all([
            loadGeneralSettings(),
            loadRateLimitSettings(),
            loadDNSSettings(),
            loadExecutorSettings(),
            loadValidationSettings(),
            loadPortsConfiguration(),
            loadEmailFilterRegexSettings(),
            loadBlackWhiteList()
        ]);
        
        // Show success toast using new CSS classes
        showToast('Settings loaded successfully', 'success');
        
    } catch (error) {
        console.error('Error loading settings:', error);
        showToast('An error occurred while loading settings', 'error');
    } finally {
        settingsState.loading = false;
        updateLoadingState(false);
    }
}

/**
 * Update the UI loading state using CSS classes
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
 * Save all modified settings with improved error handling
 */
async function saveAllSettings() {
    updateLoadingState(true);
    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    
    try {
        // Create array of save operations for better error handling
        const saveOperations = [
            { name: 'General Settings', fn: saveGeneralSettings },
            { name: 'Rate Limits', fn: saveRateLimitSettings },
            { name: 'DNS Settings', fn: saveDNSSettings },
            { name: 'Executor Settings', fn: saveExecutorSettings },
            { name: 'Validation Settings', fn: saveValidationSettings },
            { name: 'Port Settings', fn: savePortsConfiguration },
            { name: 'Email Filter Settings', fn: saveEmailFilterRegexSettings }
        ];
        
        // Execute save operations
        for (const operation of saveOperations) {
            try {
                const result = await operation.fn();
                successCount += result.success || 0;
                errorCount += result.errors || 0;
                
                if (result.errors > 0) {
                    errors.push(`${operation.name}: ${result.errors} errors`);
                }
            } catch (error) {
                console.error(`Error saving ${operation.name}:`, error);
                errors.push(`${operation.name}: Failed to save`);
                errorCount++;
            }
        }
        
        // Show appropriate notification using new CSS classes
        if (errorCount === 0) {
            showToast(`Successfully saved ${successCount} settings`, 'success');
        } else {
            showToast(`Saved ${successCount} settings, but ${errorCount} failed`, 'warning');
            console.warn('Save errors:', errors);
        }
        
    } catch (error) {
        console.error('Error saving settings:', error);
        showToast('An error occurred while saving settings', 'error');
    } finally {
        updateLoadingState(false);
    }
}

/**
 * Open settings panel with improved CSS handling
 */
function openSettingsPanel(tabName = 'general') {
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) return;
    
    // Use CSS classes for display control
    settingsPanel.classList.add('settings-overlay-active');
    settingsPanel.style.display = 'flex';
    
    // Setup close button with proper styles and event listener
    const closeBtn = document.getElementById('closeSettingsBtn');
    if (closeBtn) {
        // Apply the CSS class
        closeBtn.classList.add('settings-close-btn');
        // Add event listener to close settings when clicked
        closeBtn.addEventListener('click', closeSettingsPanel);
    }
    
    // Apply layout improvements using CSS classes
    const tabsContainer = document.querySelector('.settings-tabs');
    const contentContainer = document.querySelector('.settings-content');
    
    if (tabsContainer && contentContainer) {
        // Add CSS classes for sticky behavior
        tabsContainer.classList.add('settings-tabs-sticky');
        contentContainer.classList.add('settings-content-scrollable');
    }
    
    // Initialize settings if needed
    initSettingsMenu().then(() => {
        // Switch to the specified tab
        if (tabName) {
            switchSettingsTab(tabName);
        }
    });
    
    // Disable body scrolling
    document.body.classList.add('modal-open');
}

/**
 * Close settings panel with CSS classes
 */
function closeSettingsPanel() {
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) return;
    
    // Use CSS classes for hiding
    settingsPanel.classList.remove('settings-overlay-active');
    settingsPanel.style.display = 'none';
    
    // Re-enable body scrolling
    document.body.classList.remove('modal-open');
}

/**
 * Show toast notification using the global system
 * @param {string} message - The message to display
 * @param {string} type - The type of toast (success, error, warning, info)
 */
function showToast(message, type = 'info') {
    // Use the global showToast function
    if (typeof window.showToast === 'function') {
        window.showToast(message, type);
    } else {
        console.log(`${type.toUpperCase()}: ${message}`);
    }
}

// Export functions for use in main.js
window.openSettingsPanel = openSettingsPanel;
window.closeSettingsPanel = closeSettingsPanel;
window.initSettingsMenu = initSettingsMenu;
window.switchSettingsTab = switchSettingsTab;
window.showToast = showToast;

// Debugging function to list available tabs and content areas
window.debugTabs = function() {
    console.log("Available tabs:");
    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
        console.log(`Tab: ${btn.dataset.tab} (Text: ${btn.textContent.trim()})`);
    });
    console.log("Available content areas:");
    document.querySelectorAll('.settings-tab-content').forEach(content => {
        console.log(`Content ID: ${content.id}, Display: ${content.style.display}`);
    });
};

// Re-export utility functions for use by other modules
export {
    capitalizeFirstLetter,
    formatSettingName,
    showNotification,
    formatDate,
    showToast
};