/**
 * Black and White List module for Email Verification Engine
 * Handles domain blacklist and whitelist management
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

// Black/White list specific state
const bwState = {
    blackWhiteList: []
};

/**
 * Load black and white list domains from the database
 * @returns {Promise<boolean>} Success or failure
 */
async function loadBlackWhiteList() {
    try {
        const blackWhiteResult = await eel.get_black_white_list()();
        if (blackWhiteResult.success) {
            bwState.blackWhiteList = blackWhiteResult.domains;
            renderBlackWhiteList();
            return true;
        } else {
            showNotification('error', 'Failed to load black/white list');
            return false;
        }
    } catch (error) {
        console.error('Error loading black/white list:', error);
        showNotification('error', 'An error occurred while loading black/white list');
        return false;
    }
}

/**
 * Render black/white list
 */
function renderBlackWhiteList() {
    const container = document.getElementById('black-white-list-content');
    if (!container) return;
    
    // Split domains into blacklisted and whitelisted
    const blacklistDomains = bwState.blackWhiteList.filter(domain => domain.category === 'blacklisted');
    const whitelistDomains = bwState.blackWhiteList.filter(domain => domain.category === 'whitelisted');
    
    let html = `
        <div class="results-container">
            <h2>Domain Management</h2>
            
            <!-- Add new domain form -->
            <div class="domain-input-container">
                <input type="text" id="new-domain-input" placeholder="Enter domain (e.g., example.com)" class="domain-input">
                <select id="new-domain-category" class="domain-category-select">
                    <option value="blacklisted">Blacklist</option>
                    <option value="whitelisted">Whitelist</option>
                </select>
                <button id="add-domain-btn" class="btn btn-primary">Add</button>
            </div>
        </div>

        <!-- Blacklist section -->
        <div class="results-container">
            <h3>Blacklisted Domains</h3>
            <div class="domain-table-container">
                <table class="domain-table">
                    <thead>
                        <tr>
                            <th width="25%">Domain</th>
                            <th width="25%">Added By</th>
                            <th width="25%">Date Added</th>
                            <th width="25%">Actions</th>
                        </tr>
                    </thead>
                    <tbody>`;
    
    if (blacklistDomains.length === 0) {
        html += `
            <tr>
                <td colspan="4" class="empty-list-message">
                    No domains in the blacklist
                </td>
            </tr>`;
    } else {
        blacklistDomains.forEach(domain => {
            html += `
                <tr data-id="${domain.id}" data-type="black-white">
                    <td>${domain.domain}</td>
                    <td>${domain.added_by}</td>
                    <td>${formatDate(domain.timestamp)}</td>
                    <td class="text-center">
                        <button class="toggle-domain-btn btn-secondary" data-id="${domain.id}" data-current="${domain.category}">
                            Move to Whitelist
                        </button>
                        <button class="remove-domain-btn btn-danger" data-id="${domain.id}">
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
        </div>

        <!-- Whitelist section -->
        <div class="results-container">
            <h3>Whitelisted Domains</h3>
            <div class="domain-table-container">
                <table class="domain-table">
                    <thead>
                        <tr>
                            <th width="25%">Domain</th>
                            <th width="25%">Added By</th>
                            <th width="25%">Date Added</th>
                            <th width="25%">Actions</th>
                        </tr>
                    </thead>
                    <tbody>`;
    
    if (whitelistDomains.length === 0) {
        html += `
            <tr>
                <td colspan="4" class="empty-list-message">
                    No domains in the whitelist
                </td>
            </tr>`;
    } else {
        whitelistDomains.forEach(domain => {
            html += `
                <tr data-id="${domain.id}" data-type="black-white">
                    <td>${domain.domain}</td>
                    <td>${domain.added_by}</td>
                    <td>${formatDate(domain.timestamp)}</td>
                    <td class="text-center">
                        <button class="toggle-domain-btn btn-secondary" data-id="${domain.id}" data-current="${domain.category}">
                            Move to Blacklist
                        </button>
                        <button class="remove-domain-btn btn-danger" data-id="${domain.id}">
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
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        // Call the Python function to add the domain
        const result = await eel.add_domain_to_list(domain, category, 'UI')();
        
        if (result.success) {
            showNotification('success', `Added ${domain} to the ${category === 'blacklisted' ? 'blacklist' : 'whitelist'}`);
            domainInput.value = '';
            
            // Reload the black/white list
            await loadBlackWhiteList();
        } else {
            showNotification('error', `Failed to add domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error adding domain:', error);
        showNotification('error', 'An error occurred while adding the domain');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

/**
 * Update a domain's category in the black/white list
 */
async function updateDomainCategory(id, newCategory) {
    try {
        // Show loading state
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        // Call the Python function to update the domain
        const result = await eel.update_domain_category(id, newCategory)();
        
        if (result.success) {
            showNotification('success', `Updated domain to ${newCategory === 'blacklisted' ? 'blacklist' : 'whitelist'}`);
            
            // Reload the black/white list
            await loadBlackWhiteList();
        } else {
            showNotification('error', `Failed to update domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error updating domain:', error);
        showNotification('error', 'An error occurred while updating the domain');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

/**
 * Remove a domain from the black/white list
 */
async function removeDomainFromList(id) {
    try {
        // Show loading state
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(true);
        }
        
        // Call the Python function to remove the domain
        const result = await eel.remove_domain_from_list(id)();
        
        if (result.success) {
            showNotification('success', 'Removed domain from the list');
            
            // Reload the black/white list
            await loadBlackWhiteList();
        } else {
            showNotification('error', `Failed to remove domain: ${result.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('Error removing domain:', error);
        showNotification('error', 'An error occurred while removing the domain');
    } finally {
        if (typeof updateLoadingState === 'function') {
            updateLoadingState(false);
        }
    }
}

// Export functions and state for use by the main settings module
export {
    capitalizeFirstLetter,
    showNotification,
    formatDate,
    bwState,
    loadBlackWhiteList,
    renderBlackWhiteList,
    addDomainToList,
    updateDomainCategory,
    removeDomainFromList
};