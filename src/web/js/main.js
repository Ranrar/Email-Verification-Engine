// This file contains the JavaScript code that handles theme management, menu system, and module coordination.

document.addEventListener('DOMContentLoaded', function() {
    // Create message container for notifications if it doesn't exist
    if (!document.getElementById('message-container')) {
        const messageContainer = document.createElement('div');
        messageContainer.id = 'message-container';
        messageContainer.style.position = 'fixed';
        messageContainer.style.bottom = '20px';
        messageContainer.style.left = '20px';
        messageContainer.style.zIndex = '9999';
        messageContainer.style.display = 'flex';
        messageContainer.style.flexDirection = 'column-reverse';
        document.body.appendChild(messageContainer);
    }
    
    // Initialize modules
    initializeModules();
    
    // Initialize theme management
    initializeTheme();
    
    // Initialize menu system
    initializeMenuSystem();
});

/**
 * Initialize all application modules
 */
function initializeModules() {
    // Initialize ValidationEngine
    if (window.ValidationEngine) {
        const validationEngine = new ValidationEngine();
        if (validationEngine.init()) {
            console.log('ValidationEngine initialized successfully');
            window.validationEngine = validationEngine;
        } else {
            console.error('Failed to initialize ValidationEngine');
        }
    }
    
    // Initialize ResultsDisplay
    if (window.ResultsDisplay) {
        const resultsDisplay = new ResultsDisplay();
        if (resultsDisplay.init()) {
            console.log('ResultsDisplay initialized successfully');
            // Store the instance (lowercase r)
            window.resultsDisplay = resultsDisplay;
        } else {
            console.error('Failed to initialize ResultsDisplay');
        }
    }
    
    // Settings module is initialized when needed
}

/**
 * Initialize theme management
 */
function initializeTheme() {
    const themeToggle = document.getElementById('theme-toggle');
    
    function detectOSTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    }
    
    // Apply the saved theme or OS preference on page load
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        applyTheme(savedTheme);
    } else {
        applyTheme(detectOSTheme());
    }

    // Theme toggle functionality
    if (themeToggle) {
        themeToggle.checked = document.documentElement.getAttribute('data-theme') === 'dark';
        
        themeToggle.addEventListener('change', function() {
            const theme = this.checked ? 'dark' : 'light';
            applyTheme(theme);
        });
    }
}

/**
 * Initialize menu system
 */
function initializeMenuSystem() {
    document.querySelectorAll('.menu-bar a[data-action]').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const action = this.getAttribute('data-action');
            handleMenuAction(action);
        });
    });
    
    // Add settings close button event listener
    const closeSettingsBtn = document.getElementById('closeSettingsBtn');
    if (closeSettingsBtn) {
        closeSettingsBtn.addEventListener('click', closeSettingsPanel);
    }
    
    // Add settings button event listener
    const settingsButton = document.getElementById('settingsButton');
    if (settingsButton) {
        settingsButton.addEventListener('click', function() {
            openSettingsPanel('general');
        });
    }
}

/**
 * Handle all menu actions
 */
function handleMenuAction(action) {
    console.log(`Menu action: ${action}`);
    
    switch(action) {
        // File menu
        case 'exit':
            handleExitApplication();
            break;
            
        // Validation menu
        case 'command-line':
            showDialog('Command Line Validation', 'Enter email addresses to validate:');
            break;
            
        case 'new-batch':
            showDialog('New Batch Validation', 'Upload a CSV file with email addresses:');
            break;
            
        case 'batch-history':
            showDialog('Batch Validation History', 'View previous batch validation jobs:');
            break;
            
        // Validation Records menu
        case 'show-records':
            showDialog('All Records', 'Displaying all validation records:');
            break;
            
        case 'custom-filter':
            showDialog('Custom Filter', 'Define filter criteria:');
            break;
            
        // Export menu
        case 'export-all':
            showDialog('Export All Records', 'Export all validation records:');
            break;
            
        case 'export-date':
            showDialog('Export by Date Range', 'Select date range:');
            break;
            
        case 'export-batch':
            showDialog('Export by Batch', 'Select batch:');
            break;
            
        case 'export-domain':
            showDialog('Export by Domain', 'Enter domain:');
            break;
            
        case 'export-confidence':
            showDialog('Export by Confidence Level', 'Select confidence range:');
            break;
            
        case 'export-field':
            showDialog('Export by Field Categories', 'Select fields:');
            break;
            
        // Settings menu
        case 'settings-general':
            openSettingsPanel('general');
            break;
        case 'settings-rate-limits':
            openSettingsPanel('rate-limits');
            break;
        case 'settings-dns':
            openSettingsPanel('dns');
            break;
        case 'settings-thread-pool':
            openSettingsPanel('executor');
            break;
        case 'settings-user':
        case 'settings-port':
        case 'settings-validation':
        case 'settings-cache':
        case 'settings-security':
        case 'settings-logging':
        case 'settings-database':
            openSettingsPanel('general');
            break;
            
        // More menu
        case 'more-statistics':
            showDialog('Statistics', 'Email validation statistics:\n• Total validations: 1,245\n• Success rate: 87%');
            break;
            
        case 'more-performance':
            showDialog('Performance Metrics', 'System performance metrics:\n• Average validation time: 2.3s');
            break;
            
        case 'more-resources':
            showDialog('System Resources', 'Current system resource usage:\n• CPU: 24%\n• Memory: 156MB');
            break;
            
        // Help menu
        case 'help-docs':
            showDialog('Documentation', 'Full documentation available at:\nhttps://github.com/Ranrar/EVS/wiki');
            break;
            
        case 'help-shortcuts':
            showDialog('Keyboard Shortcuts', 'Available shortcuts:\n• Enter - Validate email\n• Ctrl+C - Exit application');
            break;
            
        case 'help-about':
            showAboutDialog();
            break;
            
        default:
            showDialog('Notice', 'This feature is not yet implemented.');
    }
}

/**
 * Handle exit application
 */
function handleExitApplication() {
    const asciiLogo = `
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░`;
                
    showDialog(
        'Exit Application', 
        'Are you sure you want to exit the application?',
        [
            {
                text: 'Yes',
                handler: function() {
                    closeDialog();
                    
                    eel.exit_application();
                    
                    const overlay = document.createElement('div');
                    overlay.style.position = 'fixed';
                    overlay.style.top = 0;
                    overlay.style.left = 0;
                    overlay.style.width = '100%';
                    overlay.style.height = '100%';
                    overlay.style.backgroundColor = 'rgba(0,0,0,0.8)';
                    overlay.style.zIndex = 1000;
                    overlay.style.display = 'flex';
                    overlay.style.justifyContent = 'center';
                    overlay.style.alignItems = 'center';
                    overlay.style.color = '#fff';
                    overlay.style.fontSize = '24px';
                    overlay.textContent = 'Exiting application...';
                    document.body.appendChild(overlay);
                    
                    setTimeout(function() {
                        window.close();
                        overlay.textContent = 'Application backend has been closed. You can now safely close this tab.';
                    }, 500);
                }
            },
            {
                text: 'No',
                handler: closeDialog
            }
        ]
    );
}

/**
 * Show about dialog
 */
function showAboutDialog() {
    const asciiLogo = `
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░`;
    
    showAboutDialogWithLogo('About', asciiLogo, 'Email Verification Engine\nCopyright © 2025 Kim Skov Rasmussen');
}

/**
 * Create and show dialogs
 */
function showDialog(title, content, buttons = [{text: 'OK', handler: closeDialog}]) {
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    const titleElement = document.createElement('div');
    titleElement.className = 'dialog-title';
    titleElement.textContent = title;
    dialog.appendChild(titleElement);
    
    const body = document.createElement('div');
    body.className = 'dialog-body';
    body.innerText = content;
    dialog.appendChild(body);
    
    const buttonsContainer = document.createElement('div');
    buttonsContainer.className = 'dialog-buttons';
    
    buttons.forEach(buttonConfig => {
        const button = document.createElement('button');
        button.textContent = buttonConfig.text;
        button.addEventListener('click', buttonConfig.handler);
        buttonsContainer.appendChild(button);
    });
    
    dialog.appendChild(buttonsContainer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    overlay.style.display = 'block';
}

function closeDialog() {
    const overlay = document.querySelector('.dialog-overlay');
    if (overlay) {
        document.body.removeChild(overlay);
    }
}

function showAboutDialogWithLogo(title, logo, content) {
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    
    const dialog = document.createElement('div');
    dialog.className = 'dialog';
    
    const titleElement = document.createElement('div');
    titleElement.className = 'dialog-title';
    titleElement.textContent = title;
    dialog.appendChild(titleElement);
    
    const logoContainer = document.createElement('pre');
    logoContainer.className = 'ascii-art';
    logoContainer.textContent = logo;
    
    const body = document.createElement('div');
    body.className = 'dialog-body';
    body.appendChild(logoContainer);
    
    const contentText = document.createElement('p');
    contentText.style.textAlign = 'center';
    contentText.style.marginTop = '20px';
    contentText.innerText = content;
    body.appendChild(contentText);
    
    dialog.appendChild(body);
    
    const buttonsContainer = document.createElement('div');
    buttonsContainer.className = 'dialog-buttons';
    
    const okButton = document.createElement('button');
    okButton.textContent = 'OK';
    okButton.addEventListener('click', closeDialog);
    buttonsContainer.appendChild(okButton);
    
    dialog.appendChild(buttonsContainer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    overlay.style.display = 'block';
}

// Update the show_message function to match the Python Notifier's call signature
eel.expose(show_message);
function show_message(type_name, message, persistent = false, details = null) {
    const div = document.createElement("div");

    let category, status;
    if (type_name.includes(":")) {
        [category, status] = type_name.split(":");
    } else {
        status = type_name;
        category = "generic";
    }

    div.className = `toast ${category}-${status}`;
    
    const messageContainer = document.createElement("div");
    messageContainer.className = "toast-message";
    messageContainer.textContent = message;
    div.appendChild(messageContainer);
    
    if (details) {
        const detailsContainer = document.createElement("div");
        detailsContainer.className = "toast-details";
        detailsContainer.textContent = details;
        detailsContainer.style.display = "none";
        detailsContainer.style.maxHeight = "0";
        detailsContainer.style.overflow = "hidden";
        detailsContainer.style.transition = "max-height 0.3s ease, padding 0.3s ease";
        div.appendChild(detailsContainer);
    }
    
    if (persistent) {
        div.setAttribute('data-persistent', 'true');
        div.style.cursor = 'pointer';
        div.style.position = 'relative';
        
        let hoverTimeout;
        
        if (details) {
            div.addEventListener('mouseenter', function() {
                hoverTimeout = setTimeout(() => {
                    const detailsContainer = this.querySelector('.toast-details');
                    if (detailsContainer) {
                        detailsContainer.style.display = "block";
                        setTimeout(() => {
                            detailsContainer.style.maxHeight = detailsContainer.scrollHeight + "px";
                            detailsContainer.style.padding = "8px 0 0 0";
                        }, 10);
                    }
                }, 500);
            });
            
            div.addEventListener('mouseleave', function() {
                clearTimeout(hoverTimeout);
                const detailsContainer = this.querySelector('.toast-details');
                if (detailsContainer) {
                    detailsContainer.style.maxHeight = "0";
                    detailsContainer.style.padding = "0";
                    setTimeout(() => {
                        if (detailsContainer.style.maxHeight === "0px") {
                            detailsContainer.style.display = "none";
                        }
                    }, 300);
                }
            });
        }
        
        const closeIcon = document.createElement('span');
        closeIcon.textContent = '✕';
        closeIcon.className = 'close-icon';
        div.appendChild(closeIcon);
        
        div.addEventListener('click', function(e) {
            if (e.target === closeIcon || e.target === messageContainer || e.target === div) {
                div.style.opacity = '0';
                div.style.transform = 'translateX(-100%)';
                setTimeout(() => div.remove(), 300);
            }
        });
    } else {
        div.textContent = message;
    }
    
    div.style.opacity = '0';
    div.style.transform = 'translateX(-100%)';
    div.style.transition = 'all 0.3s ease';
    
    const container = document.getElementById("message-container");
    if (container) {
        container.prepend(div);
    } else {
        console.log(`[${type_name.toUpperCase()}] ${message}${details ? ' - ' + details : ''}`);
        return;
    }
    
    setTimeout(() => {
        div.style.opacity = '1';
        div.style.transform = 'translateX(0)';
    }, 10);
    
    if (!persistent) {
        setTimeout(() => {
            div.style.opacity = '0';
            div.style.transform = 'translateX(-100%)';
            setTimeout(() => div.remove(), 300);
        }, 5000);
    }
}

// Settings panel handling
function openSettingsPanel(tabName = 'general') {
    const settingsPanel = document.getElementById('settingsPanel');
    settingsPanel.style.display = 'flex';
    
    if (typeof initSettingsMenu === 'function') {
        initSettingsMenu().then(() => {
            if (tabName) {
                switchSettingsTab(tabName);
            }
        });
    }
    
    document.body.style.overflow = 'hidden';
}

function closeSettingsPanel() {
    const settingsPanel = document.getElementById('settingsPanel');
    settingsPanel.style.display = 'none';
    document.body.style.overflow = 'auto';
}