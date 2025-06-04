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

    // Fix tab text wrapping issues
    const tabButtons = document.querySelectorAll('.settings-tab-btn');
    tabButtons.forEach(btn => {
        // Prevent text wrapping
        btn.style.whiteSpace = 'nowrap';
        // Add some horizontal padding for better appearance
        btn.style.padding = '10px 15px';
        // Set consistent width behavior
        btn.style.flexShrink = '0';
    });
    
    // Make the tabs container scrollable horizontally if needed
    const tabsContainer = document.querySelector('.settings-tabs');
    if (tabsContainer) {
        tabsContainer.style.display = 'flex';
        tabsContainer.style.overflowX = 'auto';
        tabsContainer.style.width = '100%';
        tabsContainer.style.padding = '10px 0 5px 0';
        tabsContainer.style.msOverflowStyle = 'none'; // Hide scrollbar in IE
        tabsContainer.style.scrollbarWidth = 'none'; // Hide scrollbar in Firefox
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
    
    // Update visible tab content - Fix the mapping between tab names and IDs
    document.querySelectorAll('.settings-tab-content').forEach(tab => {
        // Map the various tab names to their correct content IDs
        let shouldShow = false;
        
        if (tab.id === `${tabName}-settings`) {
            shouldShow = true;
        }
        
        tab.style.display = shouldShow ? 'block' : 'none';
        
        // Debug - log what's happening
        console.log(`Tab ${tab.id}: ${shouldShow ? 'showing' : 'hiding'}`);
    });
    
    settingsState.currentTab = tabName;
    
    // Debug - log the current tab
    console.log(`Current tab: ${tabName}`);
}

/**
 * Load all settings from the database
 */
async function loadAllSettings() {
    settingsState.loading = true;
    updateLoadingState(true);
    
    try {
        // Load app settings
        await loadGeneralSettings();
        
        // Load rate limits
        await loadRateLimitSettings();
        
        // Load DNS settings
        await loadDNSSettings();
        
        // Load executor pool settings
        await loadExecutorSettings();
        
        // Load validation scoring and confidence levels
        await loadValidationSettings();
        
        // Load ports configuration
        await loadPortsConfiguration();
        
        // Load email filter regex settings
        await loadEmailFilterRegexSettings();
        
        // Load black/white list
        await loadBlackWhiteList();
    } catch (error) {
        console.error('Error loading settings:', error);
        showNotification('error', 'An error occurred while loading settings');
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
        const generalResult = await saveGeneralSettings();
        successCount += generalResult.success;
        errorCount += generalResult.errors;
        
        // Save rate limit settings
        const rateLimitResult = await saveRateLimitSettings();
        successCount += rateLimitResult.success;
        errorCount += rateLimitResult.errors;
        
        // Save DNS settings
        const dnsResult = await saveDNSSettings();
        successCount += dnsResult.success;
        errorCount += dnsResult.errors;
        
        // Save executor settings
        const executorResult = await saveExecutorSettings();
        successCount += executorResult.success;
        errorCount += executorResult.errors;
        
        // Save validation scoring settings
        const validationResult = await saveValidationSettings();
        successCount += validationResult.success;
        errorCount += validationResult.errors;
        
        // Save port settings
        const portResult = await savePortsConfiguration();
        successCount += portResult.success;
        errorCount += portResult.errors;
        
        // Save email filter regex settings
        const emailFilterResult = await saveEmailFilterRegexSettings();
        successCount += emailFilterResult.success;
        errorCount += emailFilterResult.errors;
        
        // Note: Black/white list has dedicated add/remove/update functions
        
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
 * Open settings panel with specified tab
 */
function openSettingsPanel(tabName = 'general') {
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) return;
    
    settingsPanel.style.display = 'flex';
    
    // Apply styles to make tabs fixed and content scrollable
    const tabsContainer = document.querySelector('.settings-tabs');
    const contentContainer = document.querySelector('.settings-content');
    
    if (tabsContainer && contentContainer) {
        // Make tabs fixed at the top and touch the red title
        tabsContainer.style.position = 'sticky';
        tabsContainer.style.top = '0';
        tabsContainer.style.zIndex = '10';
        tabsContainer.style.backgroundColor = 'var(--container-bg)';
        tabsContainer.style.borderBottom = '1px solid var(--border-color)';
        tabsContainer.style.width = '100%';
        tabsContainer.style.marginTop = '0';
        tabsContainer.style.paddingTop = '0';
        
        // Remove any padding/margin from parent elements that might create a gap
        if (tabsContainer.parentElement) {
            tabsContainer.parentElement.style.paddingTop = '0';
            tabsContainer.parentElement.style.marginTop = '0';
        }
        
        // Make content area scrollable
        contentContainer.style.overflowY = 'auto';
        contentContainer.style.maxHeight = 'calc(100vh - 120px)'; // Adjust based on your header height
        contentContainer.style.paddingBottom = '20px';
    }
    
    // Initialize settings if needed
    initSettingsMenu().then(() => {
        // Switch to the specified tab
        if (tabName) {
            switchSettingsTab(tabName);
        }
    });
    
    // Disable scrolling on the background
    document.body.style.overflow = 'hidden';
}

/**
 * Close settings panel
 */
function closeSettingsPanel() {
    const settingsPanel = document.getElementById('settingsPanel');
    if (!settingsPanel) return;
    
    settingsPanel.style.display = 'none';
    
    // Re-enable scrolling
    document.body.style.overflow = 'auto';
}

// Export functions for use in main.js
window.openSettingsPanel = openSettingsPanel;
window.closeSettingsPanel = closeSettingsPanel;
window.initSettingsMenu = initSettingsMenu;
window.switchSettingsTab = switchSettingsTab;

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
    formatDate
};