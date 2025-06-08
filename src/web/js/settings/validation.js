/**
 * Validation Settings module for Email Verification Engine
 * Handles validation scoring and confidence levels
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
        // Use the global show_message function exposed by main.js
        // Parameters match notifier.py: type_name, message, persistent, details
        show_message(type_name, message, persistent, details);
    } else {
        // Fallback if show_message isn't available
        console[type_name === 'error' ? 'error' : type_name === 'warning' ? 'warn' : 'log'](message);
        alert(`${type_name.toUpperCase()}: ${message}${details ? '\n' + details : ''}`);
    }
}

// Validation-specific state
const validationState = {
    validationScoring: [],
    confidenceLevels: []
};

/**
 * Load validation scoring and confidence level settings from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadValidationSettings() {
    try {
        // Load validation scoring
        console.log('Loading validation scoring...');
        const validationScoringResult = await eel.get_validation_scoring()();
        console.log('Result:', validationScoringResult);
        if (!validationScoringResult.success) {
            showNotification('error', 'Failed to load validation scoring');
            return false;
        }
        
        validationState.validationScoring = validationScoringResult.settings;
        
        // Also load confidence levels
        try {
            const confidenceLevelsResult = await eel.get_confidence_levels()();
            if (!confidenceLevelsResult.success) {
                showNotification('error', 'Failed to load confidence levels');
                return false;
            }
            validationState.confidenceLevels = confidenceLevelsResult.settings;
        } catch (e) {
            console.warn('Confidence levels not loaded:', e);
            showNotification('warning', 'Failed to load confidence levels');
            return false;
        }
        
        renderValidationScoring();
        return true;
    } catch (error) {
        console.error('Error loading validation settings:', error);
        showNotification('error', 'An error occurred while loading validation settings');
        return false;
    }
}

/**
 * Render validation scoring and confidence levels
 */
function renderValidationScoring() {
    const container = document.getElementById('validation-scoring-content');
    if (!container) return;
    
    // Split scoring settings into positive and negative groups
    const positiveScores = validationState.validationScoring.filter(setting => !setting.is_penalty);
    const negativeScores = validationState.validationScoring.filter(setting => setting.is_penalty);
    
    // Generate HTML for both sections
    let html = '<div class="results-container"><h2>Validation Scoring</h2>';
    
    // Positive scores section
    html += '<div class="scoring-section positive-section">';
    html += '<h3>Positive Scores</h3>';
    html += '<div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    positiveScores.forEach(setting => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="scoring" data-penalty="false">
                <div style="flex: 1; padding-right: 15px;">
                    <label for="scoring-value-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                        ${setting.check_name}
                    </label>
                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                        ${setting.description}
                    </div>
                </div>
                <div style="display: flex; align-items: center;">
                    <input type="number" id="scoring-value-${setting.id}" value="${Math.abs(setting.score_value)}"
                           min="0" step="1"
                           style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                           border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                </div>
            </div>
        `;
    });
    
    html += '</div></div>';
    
    // Negative scores section (penalties)
    html += '<div class="scoring-section negative-section" style="margin-top: 20px;">';
    html += '<h3>Penalty Scores</h3>';
    html += '<div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    negativeScores.forEach(setting => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${setting.id}" data-type="scoring" data-penalty="true">
                <div style="flex: 1; padding-right: 15px;">
                    <label for="scoring-value-${setting.id}" style="font-weight: bold; color: var(--text-color);">
                        ${setting.check_name}
                    </label>
                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                        ${setting.description}
                    </div>
                </div>
                <div style="display: flex; align-items: center;">
                    <input type="number" id="scoring-value-${setting.id}" value="${Math.abs(setting.score_value)}"
                           min="0" step="1"
                           style="width: 80px; padding: 8px; border: 1px solid var(--results-container-border); 
                           border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                </div>
            </div>
        `;
    });
    
    html += '</div></div>';
    html += '</div>';
    
    // Then add the confidence levels to the same container
    html += '<div class="results-container"><h2>Confidence Levels</h2><div style="display: grid; grid-template-columns: 1fr; gap: 10px;">';
    
    validationState.confidenceLevels.forEach(level => {
        html += `
            <div style="display: flex; padding: 10px; background-color: var(--results-container-bg); 
                 border-radius: 5px; margin-bottom: 5px;" data-id="${level.id}" data-type="confidence">
                <div style="flex: 1; padding-right: 15px;">
                    <label style="font-weight: bold; color: var(--text-color);">
                        ${level.level_name}
                    </label>
                    <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                        ${level.description}
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <div>
                        <label for="confidence-min-${level.id}">Min</label>
                        <input type="number" id="confidence-min-${level.id}" value="${level.min_threshold}"
                               min="0" max="100" step="1"
                               style="width: 60px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                    </div>
                    <div>
                        <label for="confidence-max-${level.id}">Max</label>
                        <input type="number" id="confidence-max-${level.id}" value="${level.max_threshold}"
                               min="0" max="100" step="1"
                               style="width: 60px; padding: 8px; border: 1px solid var(--results-container-border); 
                               border-radius: 4px; background-color: var(--bg-color); color: var(--text-color);">
                    </div>
                </div>
            </div>
        `;
    });
    
    html += `</div></div>`;
    container.innerHTML = html;
}

/**
 * Save validation scoring and confidence level settings
 * @returns {Promise<{success: number, errors: number}>} Counts of successful and failed saves
 */
async function saveValidationSettings() {
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Save validation scoring settings
        const scoringSettings = document.querySelectorAll('div[data-type="scoring"]');
        for (const settingEl of scoringSettings) {
            const id = settingEl.dataset.id;
            const valueEl = document.getElementById(`scoring-value-${id}`);
            const isPenalty = settingEl.dataset.penalty === 'true';
            
            if (!valueEl) continue;
            
            const value = parseInt(valueEl.value);
            
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
    } catch (error) {
        console.error('Error saving validation settings:', error);
        showNotification('error', 'An error occurred while saving validation settings');
        errorCount++;
    }
    
    return { success: successCount, errors: errorCount };
}

/**
 * Update theme classes when theme changes
 */
function updateValidationTheme() {
    // Re-apply any theme-specific styling
    const theme = getCurrentTheme();
    // Update any module-specific theme classes here if needed
}

// Listen for theme changes
document.addEventListener('themeChanged', updateValidationTheme);

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    showNotification,
    validationState,
    loadValidationSettings,
    renderValidationScoring,
    saveValidationSettings
};