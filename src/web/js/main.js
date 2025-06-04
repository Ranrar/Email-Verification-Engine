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
            showDocumentationList();
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
    buttonsContainer.style.display = 'flex';
    buttonsContainer.style.justifyContent = 'space-between';
    buttonsContainer.style.width = '100%';
    
    // Add License button
    const licenseButton = document.createElement('button');
    licenseButton.textContent = 'License';
    licenseButton.style.width = '32%';
    licenseButton.addEventListener('click', function() {
        showMarkdownFile('LICENSE.md');
    });
    buttonsContainer.appendChild(licenseButton);
    
    // Add EULA button
    const eulaButton = document.createElement('button');
    eulaButton.textContent = 'EULA';
    eulaButton.style.width = '32%';
    eulaButton.addEventListener('click', function() {
        showMarkdownFile('EULA.md');
    });
    buttonsContainer.appendChild(eulaButton);
    
    // Add OK button
    const okButton = document.createElement('button');
    okButton.textContent = 'OK';
    okButton.style.width = '32%';
    okButton.addEventListener('click', closeDialog);
    buttonsContainer.appendChild(okButton);
    
    dialog.appendChild(buttonsContainer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    overlay.style.display = 'block';
}

/**
 * Documentation viewer state
 */
const docViewerState = {
    isActive: false,
    currentFile: null,
    dialogElement: null,
    bodyElement: null,
    breadcrumbElement: null
};

/**
 * Show documentation file selection dialog
 */
async function showDocumentationList() {
    try {
        // Call Python function to get a list of documentation files
        const result = await eel.list_documentation_files()();
        
        if (!result.success) {
            show_message('error', 'Failed to load documentation files', true, result.error);
            return;
        }
        
        if (result.files.length === 0) {
            show_message('warning', 'No documentation files found', true, 'Check the other/doc directory');
            return;
        }
        
        // If we already have a doc viewer open, just go back to file list
        if (docViewerState.isActive && docViewerState.dialogElement) {
            showDocumentFileList(result.files);
            return;
        }
        
        // Create the dialog
        const overlay = document.createElement('div');
        overlay.className = 'dialog-overlay';
        
        const dialog = document.createElement('div');
        dialog.className = 'dialog';
        dialog.style.width = '800px';
        dialog.style.maxWidth = '90%';
        dialog.style.height = '600px';
        dialog.style.maxHeight = '90vh';
        dialog.style.display = 'flex';
        dialog.style.flexDirection = 'column';
        
        const titleElement = document.createElement('div');
        titleElement.className = 'dialog-title';
        titleElement.textContent = 'Documentation';
        dialog.appendChild(titleElement);
        
        // Create breadcrumb navigation
        const breadcrumb = document.createElement('div');
        breadcrumb.className = 'doc-breadcrumb';
        breadcrumb.style.padding = '5px 15px';
        breadcrumb.style.backgroundColor = 'var(--results-container-bg)';
        breadcrumb.style.borderRadius = '4px';
        breadcrumb.style.margin = '0 20px 10px 20px';
        breadcrumb.style.fontSize = '0.9em';
        breadcrumb.innerHTML = '<span class="breadcrumb-home">Documentation Home</span>';
        dialog.appendChild(breadcrumb);
        
        // Create the body container that will hold either file list or content
        const body = document.createElement('div');
        body.className = 'dialog-body';
        body.style.flex = '1';
        body.style.overflow = 'auto';
        body.style.padding = '0 20px 20px 20px';
        dialog.appendChild(body);
        
        const buttonsContainer = document.createElement('div');
        buttonsContainer.className = 'dialog-buttons';
        
        const closeButton = document.createElement('button');
        closeButton.textContent = 'Close';
        closeButton.addEventListener('click', function() {
            docViewerState.isActive = false;
            docViewerState.currentFile = null;
            docViewerState.dialogElement = null;
            docViewerState.bodyElement = null;
            docViewerState.breadcrumbElement = null;
            closeDialog();
        });
        buttonsContainer.appendChild(closeButton);
        
        dialog.appendChild(buttonsContainer);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        overlay.style.display = 'block';
        
        // Save references to elements
        docViewerState.isActive = true;
        docViewerState.dialogElement = dialog;
        docViewerState.bodyElement = body;
        docViewerState.breadcrumbElement = breadcrumb;
        
        // Show the file list
        showDocumentFileList(result.files);
        
    } catch (error) {
        console.error('Error loading documentation files:', error);
        show_message('error', 'An error occurred while loading documentation files', true, error.toString());
    }
}

/**
 * Display the list of documentation files in the body
 * @param {Array} files - Array of documentation file objects
 */
function showDocumentFileList(files) {
    if (!docViewerState.isActive || !docViewerState.bodyElement) {
        return;
    }
    
    // Reset state
    docViewerState.currentFile = null;
    
    // Update breadcrumb
    if (docViewerState.breadcrumbElement) {
        docViewerState.breadcrumbElement.innerHTML = '<span class="breadcrumb-home">Documentation Home</span>';
    }
    
    // Create file list
    const body = docViewerState.bodyElement;
    body.innerHTML = '';
    
    const fileList = document.createElement('ul');
    fileList.style.listStyle = 'none';
    fileList.style.padding = '0';
    fileList.style.margin = '0';
    
    // Add README first if available
    const readmeOption = document.createElement('li');
    readmeOption.style.padding = '12px';
    readmeOption.style.margin = '5px 0';
    readmeOption.style.backgroundColor = 'var(--results-container-bg)';
    readmeOption.style.borderRadius = '5px';
    readmeOption.style.cursor = 'pointer';
    readmeOption.style.fontWeight = 'bold';
    readmeOption.style.borderLeft = '4px solid var(--primary-color)';
    readmeOption.textContent = 'README - Getting Started';
    readmeOption.addEventListener('click', function() {
        showMarkdownFile('README.md');
    });
    fileList.appendChild(readmeOption);
    
    // Group files by directory
    const fileGroups = {};
    files.forEach(file => {
        const path = file.path;
        const parts = path.split('/');
        const directory = parts.length > 2 ? parts[1] : 'root';
        
        if (!fileGroups[directory]) {
            fileGroups[directory] = [];
        }
        fileGroups[directory].push(file);
    });
    
    // Sort directories
    const sortedDirs = Object.keys(fileGroups).sort();
    
    sortedDirs.forEach(dir => {
        if (dir !== 'root') {
            // Add directory header
            const dirHeader = document.createElement('div');
            dirHeader.style.padding = '8px';
            dirHeader.style.margin = '15px 0 5px 0';
            dirHeader.style.backgroundColor = 'var(--border-color)';
            dirHeader.style.borderRadius = '5px';
            dirHeader.style.fontWeight = 'bold';
            dirHeader.textContent = dir;
            fileList.appendChild(dirHeader);
        }
        
        // Add files for this directory
        fileGroups[dir].forEach(file => {
            const listItem = document.createElement('li');
            listItem.style.padding = '12px';
            listItem.style.margin = '5px 0';
            listItem.style.backgroundColor = 'var(--results-container-bg)';
            listItem.style.borderRadius = '5px';
            listItem.style.cursor = 'pointer';
            listItem.style.display = 'flex';
            listItem.style.justifyContent = 'space-between';
            listItem.style.alignItems = 'center';
            
            const fileName = document.createElement('div');
            fileName.textContent = file.title || file.name.replace('.md', '');
            listItem.appendChild(fileName);
            
            // Add icon to indicate it's clickable
            const icon = document.createElement('span');
            icon.textContent = '›';
            icon.style.fontWeight = 'bold';
            icon.style.fontSize = '20px';
            listItem.appendChild(icon);
            
            listItem.addEventListener('click', function() {
                showMarkdownFile(file.path);
            });
            
            // Add hover effect
            listItem.addEventListener('mouseover', function() {
                this.style.backgroundColor = 'var(--primary-color-light)';
            });
            listItem.addEventListener('mouseout', function() {
                this.style.backgroundColor = 'var(--results-container-bg)';
            });
            
            fileList.appendChild(listItem);
        });
    });
    
    body.appendChild(fileList);
}

/**
 * Show a markdown file in the documentation viewer
 * @param {string} filename - The markdown file to display
 */
async function showMarkdownFile(filename) {
    try {
        // Call Python function to read the file content
        const result = await eel.read_markdown_file(filename)();
        
        if (!result.success) {
            show_message('error', `Failed to load ${filename}`, true, result.error);
            return;
        }

        // If we're showing a document from the documentation browser
        if (docViewerState.isActive && docViewerState.bodyElement) {
            // Update current file
            docViewerState.currentFile = filename;
            
            // Update breadcrumb
            if (docViewerState.breadcrumbElement) {
                const homeLink = document.createElement('span');
                homeLink.className = 'breadcrumb-home';
                homeLink.textContent = 'Documentation Home';
                homeLink.style.cursor = 'pointer';
                homeLink.style.color = 'var(--primary-color)';
                homeLink.addEventListener('click', function() {
                    showDocumentationList();
                });
                
                // Create breadcrumb
                docViewerState.breadcrumbElement.innerHTML = '';
                docViewerState.breadcrumbElement.appendChild(homeLink);
                docViewerState.breadcrumbElement.appendChild(document.createTextNode(' › '));
                
                // Extract directory if present
                let displayName = filename;
                if (filename.includes('/')) {
                    const parts = filename.split('/');
                    const dir = parts.length > 2 ? parts[1] : null;
                    displayName = parts[parts.length - 1];
                    
                    if (dir) {
                        const dirSpan = document.createElement('span');
                        dirSpan.textContent = dir;
                        docViewerState.breadcrumbElement.appendChild(dirSpan);
                        docViewerState.breadcrumbElement.appendChild(document.createTextNode(' › '));
                    }
                }
                
                const fileSpan = document.createElement('span');
                fileSpan.textContent = displayName;
                fileSpan.style.fontWeight = 'bold';
                docViewerState.breadcrumbElement.appendChild(fileSpan);
            }
            
            // Clear the content area
            docViewerState.bodyElement.innerHTML = '';
            
            // Create markdown content container
            const mdContent = document.createElement('div');
            mdContent.className = 'markdown-content markdown-body';
            mdContent.style.padding = '20px';
            
            // Parse and display the markdown content
            mdContent.innerHTML = marked.parse(result.content);
            
            // Add the content to the body
            docViewerState.bodyElement.appendChild(mdContent);
            
            return;
        }
        
        // Otherwise, create a standalone markdown viewer (for LICENSE.md, EULA.md)
        const mdOverlay = document.createElement('div');
        mdOverlay.className = 'markdown-overlay';
        
        const contentContainer = document.createElement('div');
        contentContainer.className = 'markdown-container';
        
        const mdTitle = document.createElement('h2');
        mdTitle.textContent = filename;
        mdTitle.className = 'markdown-title';
        contentContainer.appendChild(mdTitle);
        
        const mdContent = document.createElement('div');
        mdContent.className = 'markdown-content markdown-body';
        mdContent.innerHTML = marked.parse(result.content);
        contentContainer.appendChild(mdContent);
        
        const closeButton = document.createElement('button');
        closeButton.textContent = 'Close';
        closeButton.className = 'btn btn-primary';
        closeButton.style.alignSelf = 'center';
        closeButton.addEventListener('click', function() {
            document.body.removeChild(mdOverlay);
        });
        contentContainer.appendChild(closeButton);
        
        mdOverlay.appendChild(contentContainer);
        document.body.appendChild(mdOverlay);
        
    } catch (error) {
        console.error(`Error displaying ${filename}:`, error);
        show_message('error', `Error displaying ${filename}`, true, error.toString());
    }
}