// This file contains the JavaScript code that handles user interactions, communicates with the backend, and manages the email verification process.

document.addEventListener('DOMContentLoaded', function() {
    const verifyButton = document.getElementById('verifyButton');
    const emailInput = document.getElementById('emailInput');
    const resultDiv = document.getElementById('result');
    const detailedResults = document.getElementById('detailedResults');
    const themeToggle = document.getElementById('theme-toggle');
    
    // Create message container for notifications if it doesn't exist
    if (!document.getElementById('message-container')) {
        const messageContainer = document.createElement('div');
        messageContainer.id = 'message-container';
        messageContainer.style.position = 'fixed';
        messageContainer.style.bottom = '20px'; // Changed from top to bottom
        messageContainer.style.left = '20px';
        messageContainer.style.zIndex = '9999';
        messageContainer.style.display = 'flex';
        messageContainer.style.flexDirection = 'column-reverse'; // Stack items bottom-to-top
        document.body.appendChild(messageContainer);
    }
    
    // Add these new variables
    const showMoreButton = document.getElementById('showMoreButton');
    const expandedDetails = document.getElementById('expandedDetails');
    const collapseAllButton = document.getElementById('collapseAllButton');
    const expandAllButton = document.getElementById('expandAllButton');

    // Hide the "Show More" button initially
    if (showMoreButton) {
        showMoreButton.style.display = 'none';
    }
    
    // Initialize the accordion - THIS IS THE CRITICAL LINE THAT WAS MISSING
    initAccordion();
    
    // Apply theme from localStorage first thing when page loads
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

    // Theme toggle functionality - now updated to work with the theme we just applied
    if (themeToggle) {
        // Set initial state based on current theme
        themeToggle.checked = document.documentElement.getAttribute('data-theme') === 'dark';
        
        // Add event listener for theme toggle
        themeToggle.addEventListener('change', function() {
            const theme = this.checked ? 'dark' : 'light';
            applyTheme(theme);
        });
    }

    // Menu system handling
    document.querySelectorAll('.menu-bar a[data-action]').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const action = this.getAttribute('data-action');
            handleMenuAction(action);
        });
    });

    // Handle all menu actions
    function handleMenuAction(action) {
        console.log(`Menu action: ${action}`);
        
        switch(action) {
            // File menu
            case 'exit':
                // Create a custom exit confirmation dialog
                showDialog(
                    'Exit Application', 
                    'Are you sure you want to exit the application?',
                    [
                        {
                            text: 'Yes',
                            handler: function() {
                                // Close dialog first
                                closeDialog();
                                
                                // Notify Python backend to shut down
                                eel.exit_application();
                                
                                // Show exit overlay
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
                                
                                // Try to close the window/tab after a short delay
                                setTimeout(function() {
                                    window.close();
                                    
                                    // If window.close() fails due to browser security
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
            // For other settings, we'll default to the general tab
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
                // Get the ASCII logo
                const asciiLogo = `
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░`;
                
                // Create a special about dialog with logo
                showAboutDialog('About', asciiLogo, 'Email Verification Engine\nCopyright © 2025 Kim Skov Rasmussen');
                break;
                
            default:
                showDialog('Notice', 'This feature is not yet implemented.');
        }
    }

    // Function to create and show dialogs
    function showDialog(title, content, buttons = [{text: 'OK', handler: closeDialog}]) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'dialog-overlay';
        
        // Create dialog
        const dialog = document.createElement('div');
        dialog.className = 'dialog';
        
        // Dialog title
        const titleElement = document.createElement('div');
        titleElement.className = 'dialog-title';
        titleElement.textContent = title;
        dialog.appendChild(titleElement);
        
        // Dialog body
        const body = document.createElement('div');
        body.className = 'dialog-body';
        body.innerText = content;
        dialog.appendChild(body);
        
        // Dialog buttons
        const buttonsContainer = document.createElement('div');
        buttonsContainer.className = 'dialog-buttons';
        
        buttons.forEach(buttonConfig => {
            const button = document.createElement('button');
            button.textContent = buttonConfig.text;
            button.addEventListener('click', buttonConfig.handler);
            buttonsContainer.appendChild(button);
        });
        
        dialog.appendChild(buttonsContainer);
        
        // Append to document
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        
        // Show dialog
        overlay.style.display = 'block';
    }
    
    function closeDialog() {
        const overlay = document.querySelector('.dialog-overlay');
        if (overlay) {
            document.body.removeChild(overlay);
        }
    }
    
    function showSettingsDialog(settingType) {
        eel.get_settings(settingType)(function(settings) {
            showDialog(`${settingType.charAt(0).toUpperCase() + settingType.slice(1)} Settings`, 
                       `Configure ${settingType} settings: ${JSON.stringify(settings, null, 2)}`);
        });
    }

    // Function to show a special about dialog with ASCII art logo
    function showAboutDialog(title, logo, content) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'dialog-overlay';
        
        // Create dialog
        const dialog = document.createElement('div');
        dialog.className = 'dialog';
        
        // Dialog title
        const titleElement = document.createElement('div');
        titleElement.className = 'dialog-title';
        titleElement.textContent = title;
        dialog.appendChild(titleElement);
        
        // Logo container
        const logoContainer = document.createElement('pre');
        logoContainer.className = 'ascii-art';
        logoContainer.textContent = logo;
        
        // Dialog body
        const body = document.createElement('div');
        body.className = 'dialog-body';
        
        // Add logo to body
        body.appendChild(logoContainer);
        
        // Add content text
        const contentText = document.createElement('p');
        contentText.style.textAlign = 'center';
        contentText.style.marginTop = '20px';
        contentText.innerText = content;
        body.appendChild(contentText);
        
        dialog.appendChild(body);
        
        // Dialog buttons
        const buttonsContainer = document.createElement('div');
        buttonsContainer.className = 'dialog-buttons';
        
        const okButton = document.createElement('button');
        okButton.textContent = 'OK';
        okButton.addEventListener('click', closeDialog);
        buttonsContainer.appendChild(okButton);
        
        dialog.appendChild(buttonsContainer);
        
        // Append to document
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        
        // Show dialog
        overlay.style.display = 'block';
    }

    // Enhanced email validation handling
    verifyButton.addEventListener('click', function() {
        const email = emailInput.value;
        
        if (verifyButton.textContent === "New Validation") {
            // Reset the form for a new validation
            resetValidationForm();
            return;
        }
        
        if (validateEmail(email)) {
            // Disable input and show loading
            emailInput.disabled = true;
            verifyButton.disabled = true;
            
            // Show loading bar
            const progressBar = document.getElementById('validationProgress');
            const progressFill = document.getElementById('validation-progress-fill');
            const percentText = document.getElementById('validation-percent');
            
            progressBar.style.display = 'block';
            resultDiv.innerText = "";
            resultDiv.className = '';
            detailedResults.style.display = 'none';
            
            // Simulate progress steps (in real app, these would come from the backend)
            let progress = 0;
            const validationSteps = [
                "Checking email format...",
                "Validating domain...",
                "Checking MX records...",
                "Looking for disposable patterns...",
                "Performing SMTP validation...",
                "Calculating confidence score..."
            ];
            
            const stepDuration = 400; // milliseconds per step
            const intervalTime = 50;
            let currentStep = 0;
            
            document.getElementById('validation-step').textContent = validationSteps[0];
            
            // Update progress bar
            const progressInterval = setInterval(function() {
                // Calculate which step we should be on
                const expectedProgress = Math.min(100, Math.floor((progress / (validationSteps.length * stepDuration)) * 100));
                
                // Update visual elements
                progressFill.style.width = `${expectedProgress}%`;
                percentText.textContent = `${expectedProgress}%`;
                
                // Move to next step if needed
                if (progress > 0 && progress % stepDuration === 0 && currentStep < validationSteps.length - 1) {
                    currentStep++;
                    document.getElementById('validation-step').textContent = validationSteps[currentStep];
                }
                
                progress += intervalTime;
                
                // If we reach 100%, call the validation API
                if (expectedProgress >= 100) {
                    clearInterval(progressInterval);
                    
                    // Call the Python validation function
                    eel.verify_email(email)(function(response) {
                        // Hide progress bar
                        progressBar.style.display = 'none';
                        
                        // Set the basic result message
                        resultDiv.innerText = response.message;
                        
                        // Set validation status class
                        resultDiv.className = response.valid ? 'message success' : 'message error';
                        
                        // Populate detailed results
                        document.getElementById('confidenceScore').innerText = response.details.confidence_score + '%';
                        document.getElementById('confidenceLevel').innerText = response.details.confidence_level;
                        document.getElementById('smtpVerified').innerText = response.details.smtp_verified ? '✓ Yes' : '✗ No';
                        document.getElementById('isDisposable').innerText = response.details.is_disposable ? '✗ Yes' : '✓ No';
                        
                        // Format MX records if available
                        if (response.details.mx_records && response.details.mx_records.length > 0) {
                            document.getElementById('mxRecords').innerText = response.details.mx_records.join(', ');
                        } else {
                            document.getElementById('mxRecords').innerText = 'None found';
                        }
                        
                        document.getElementById('traceId').innerText = response.details.trace_id;
                        
                        // Show detailed results
                        detailedResults.style.display = 'block';
                        
                        // Show the "Show More" button ONLY after validation is complete and if we have a trace ID
                        const showMoreButton = document.getElementById('showMoreButton');
                        if (showMoreButton && response.details.trace_id) {
                            showMoreButton.style.display = 'block';
                        }
                        
                        // Reset expanded details if they were shown
                        const expandedDetails = document.getElementById('expandedDetails');
                        if (expandedDetails && expandedDetails.style.display === 'block') {
                            expandedDetails.style.display = 'none';
                            showMoreButton.textContent = 'Show More Details';
                        }
                        
                        // Change button to "New Validation"
                        verifyButton.textContent = "New Validation";
                        verifyButton.disabled = false;
                    });
                }
            }, intervalTime);
            
        } else {
            resultDiv.innerText = 'Please enter a valid email address.';
            resultDiv.className = 'message error';
            detailedResults.style.display = 'none';
        }
    });

    // Function to reset the validation form
    function resetValidationForm() {
        // Clear the input
        emailInput.value = '';
        emailInput.disabled = false;
        
        // Clear the results
        resultDiv.innerText = '';
        resultDiv.className = '';
        detailedResults.style.display = 'none';
        
        // Hide the "Show More" button when resetting
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
        }
        
        // Reset the button
        verifyButton.textContent = "Verify Email";
        
        // Set focus to the input field
        emailInput.focus();
        
        // Also hide expanded details if visible
        const expandedDetails = document.getElementById('expandedDetails');
        if (expandedDetails) {
            expandedDetails.style.display = 'none';
        }
    }

    // Add Enter key support for form submission (with protection against multiple submissions)
    emailInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            
            // Only trigger if button is not disabled and not in "New Validation" state
            if (!verifyButton.disabled && verifyButton.textContent !== "New Validation") {
                verifyButton.click();
            } else if (verifyButton.textContent === "New Validation") {
                // If in "New Validation" state, reset the form
                resetValidationForm();
            }
        }
    });

    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(String(email).toLowerCase());
    }

    // Add Show More button handler
    showMoreButton.addEventListener('click', function() {
        // Get the current trace ID from the traceId field
        const traceId = document.getElementById('traceId').innerText;
        
        if (traceId && traceId !== '-') {
            // If expandedDetails is already visible, toggle it
            if (expandedDetails.style.display === 'block') {
                expandedDetails.style.display = 'none';
                showMoreButton.textContent = 'Show More Details';
            } else {
                // Show loading state
                showMoreButton.textContent = 'Loading...';
                showMoreButton.disabled = true;
                
                // Call Python function to get detailed data
                eel.get_detailed_validation_data(traceId)(function(data) {
                    // Populate the detailed sections with the returned data
                    populateDetailedSections(data);
                    
                    // Show the expanded details section
                    expandedDetails.style.display = 'block';
                    
                    // Change button text and re-enable
                    showMoreButton.textContent = 'Hide Details';
                    showMoreButton.disabled = false;
                });
            }
        }
    });
    
    // Collapse All button
    if (collapseAllButton) {
        collapseAllButton.addEventListener('click', function() {
            document.querySelectorAll('.accordion-item').forEach(item => {
                item.classList.remove('active');
            });
        });
    }
    
    // Expand All button
    if (expandAllButton) {
        expandAllButton.addEventListener('click', function() {
            document.querySelectorAll('.accordion-item').forEach(item => {
                item.classList.add('active');
            });
        });
    }
    
    // Initialize accordion functionality
    function initAccordion() {
        document.querySelectorAll('.accordion-header').forEach(header => {
            header.addEventListener('click', function() {
                const item = this.parentElement;
                const content = item.querySelector('.accordion-content');
                
                if (item.classList.contains('active')) {
                    // Closing the accordion
                    content.style.maxHeight = '0px';
                    // Wait for animation to complete before removing active class
                    setTimeout(() => {
                        item.classList.remove('active');
                    }, 500); // Match this to your CSS transition time
                } else {
                    // Opening the accordion - first set active to get full height
                    item.classList.add('active');
                    // Temporarily remove the transition for accurate height calculation
                    content.style.transition = 'none';
                    content.style.maxHeight = 'none';
                    const actualHeight = content.scrollHeight;
                    content.style.maxHeight = '0px';
                    
                    // Force reflow to ensure the maxHeight: 0px is applied
                    void content.offsetHeight;
                    
                    // Restore the transition and set the actual height
                    content.style.transition = 'max-height 0.5s ease';
                    content.style.maxHeight = actualHeight + 'px';
                }
            });
        });
        
        // Make the initial state work correctly
        document.querySelectorAll('.accordion-item.active').forEach(item => {
            const content = item.querySelector('.accordion-content');
            content.style.maxHeight = content.scrollHeight + 'px';
        });
    }
    
    // Function to populate detailed sections with data
    function populateDetailedSections(data) {
        // DNS Information
        const dnsTable = document.getElementById('dnsDetailsTable');
        dnsTable.innerHTML = '';
        
        if (data.email_validation_record) {
            addTableRow(dnsTable, 'Domain', data.email_validation_record.domain || 'N/A');
            addTableRow(dnsTable, 'MX Records', data.email_validation_record.mx_records || 'N/A');
            addTableRow(dnsTable, 'MX Preferences', data.email_validation_record.mx_preferences || 'N/A');
            addTableRow(dnsTable, 'Reverse DNS', data.email_validation_record.reverse_dns || 'N/A');
            addTableRow(dnsTable, 'WHOIS Info', data.email_validation_record.whois_info || 'N/A');
        }
        
        // SMTP Details
        const smtpTable = document.getElementById('smtpDetailsTable');
        smtpTable.innerHTML = '';
        
        if (data.email_validation_record) {
            addTableRow(smtpTable, 'SMTP Result', data.email_validation_record.smtp_result || 'N/A');
            addTableRow(smtpTable, 'SMTP Banner', data.email_validation_record.smtp_banner || 'N/A');
            addTableRow(smtpTable, 'SMTP VRFY', data.email_validation_record.smtp_vrfy || 'N/A');
            addTableRow(smtpTable, 'Port Used', data.email_validation_record.port || 'N/A');
            addTableRow(smtpTable, 'Catch-All', data.email_validation_record.catch_all || 'N/A');
        }
        
        // MX Infrastructure
        const mxTable = document.getElementById('mxDetailsTable');
        mxTable.innerHTML = '';
        
        if (data.mx_infrastructure && data.mx_infrastructure.length > 0) {
            data.mx_infrastructure.forEach((mx, index) => {
                addTableRow(mxTable, `MX Record ${index + 1}`, mx.mx_record || 'N/A');
                addTableRow(mxTable, `Preference`, mx.preference || 'N/A');
                addTableRow(mxTable, `Primary`, mx.is_primary ? 'Yes' : 'No');
                addTableRow(mxTable, `Has Failover`, mx.has_failover ? 'Yes' : 'No');
                addTableRow(mxTable, `Load Balanced`, mx.load_balanced ? 'Yes' : 'No');
                addTableRow(mxTable, `Provider`, mx.provider_name || 'N/A');
                addTableRow(mxTable, `Self-Hosted`, mx.is_self_hosted ? 'Yes' : 'No');
                
                // Add separator between multiple MX records
                if (index < data.mx_infrastructure.length - 1) {
                    const tr = document.createElement('tr');
                    const td = document.createElement('td');
                    td.colSpan = 2;
                    td.style.borderBottom = '1px solid var(--results-container-border)';
                    td.style.height = '10px';
                    tr.appendChild(td);
                    mxTable.appendChild(tr);
                }
            });
        } else {
            addTableRow(mxTable, 'MX Records', 'No MX infrastructure data available');
        }
        
        // IP Information
        const ipTable = document.getElementById('ipDetailsTable');
        ipTable.innerHTML = '';

        if (data.mx_ip_addresses && data.mx_ip_addresses.length > 0) {
            // Group IP addresses by mx_infrastructure_id first
            const serverGroups = {};
            
            // First pass - initialize groups and establish server names
            data.mx_ip_addresses.forEach(ip => {
                const infraId = ip.mx_infrastructure_id;
                if (!serverGroups[infraId]) {
                    serverGroups[infraId] = {
                        name: null,
                        ipv4: [],
                        ipv6: []
                    };
                }
                
                // Try to find a proper name for this infrastructure
                if (ip.ptr_record && !serverGroups[infraId].name) {
                    serverGroups[infraId].name = ip.ptr_record;
                }
            });
            
            // Second pass - add IPs to their groups
            data.mx_ip_addresses.forEach(ip => {
                const infraId = ip.mx_infrastructure_id;
                const group = serverGroups[infraId];
                
                // Use a proper name if found, or a generic one if not
                if (!group.name) {
                    group.name = `Mail Server ${infraId}`;
                }
                
                // Add IP with its individual metadata
                if (ip.ip_version === 4) {
                    group.ipv4.push({
                        address: ip.ip_address,
                        country: ip.country_code || 'N/A',
                        region: ip.region || 'N/A',
                        provider: ip.provider || 'N/A'
                    });
                } else if (ip.ip_version === 6) {
                    group.ipv6.push({
                        address: ip.ip_address,
                        country: ip.country_code || 'N/A',
                        region: ip.region || 'N/A',
                        provider: ip.provider || 'N/A'
                    });
                }
            });
            
            // Now display the grouped data
            let serverIndex = 1;
            for (const [infraId, info] of Object.entries(serverGroups)) {
                // Add server header
                addTableRow(ipTable, `Server ${serverIndex}`, info.name || `Mail Server ${infraId}`);
                
                // Add IPv4 addresses with their info
                if (info.ipv4.length > 0) {
                    addTableRow(ipTable, 'IPv4 Addresses', '');
                    info.ipv4.forEach((ip, idx) => {
                        addTableRow(ipTable, `  Address ${idx+1}`, ip.address);
                        addTableRow(ipTable, `  Location`, `${ip.country}, ${ip.region}`);
                        addTableRow(ipTable, `  Provider`, ip.provider);
                        
                        // Add mini-separator if not the last IPv4
                        if (idx < info.ipv4.length - 1) {
                            const tr = document.createElement('tr');
                            const td = document.createElement('td');
                            td.colSpan = 2;
                            td.style.borderBottom = '1px dashed var(--results-container-border)';
                            td.style.height = '5px';
                            tr.appendChild(td);
                            ipTable.appendChild(tr);
                        }
                    });
                } else {
                    addTableRow(ipTable, 'IPv4 Addresses', 'None');
                }
                
                // Add a separator between IPv4 and IPv6 sections
                const ipTypeSeparator = document.createElement('tr');
                const ipTypeSeparatorCell = document.createElement('td');
                ipTypeSeparatorCell.colSpan = 2;
                ipTypeSeparatorCell.style.borderBottom = '1px solid var(--results-container-border)';
                ipTypeSeparatorCell.style.height = '10px';
                ipTypeSeparator.appendChild(ipTypeSeparatorCell);
                ipTable.appendChild(ipTypeSeparator);
                
                // Add IPv6 addresses with their individual info
                if (info.ipv6.length > 0) {
                    addTableRow(ipTable, 'IPv6 Addresses', '');
                    info.ipv6.forEach((ip, idx) => {
                        addTableRow(ipTable, `  Address ${idx+1}`, ip.address);
                        addTableRow(ipTable, `  Location`, `${ip.country}, ${ip.region}`);
                        addTableRow(ipTable, `  Provider`, ip.provider);
                        
                        // Add mini-separator if not the last IPv6
                        if (idx < info.ipv6.length - 1) {
                            const tr = document.createElement('tr');
                            const td = document.createElement('td');
                            td.colSpan = 2;
                            td.style.borderBottom = '1px dashed var(--results-container-border)';
                            td.style.height = '5px';
                            tr.appendChild(td);
                            ipTable.appendChild(tr);
                        }
                    });
                } else {
                    addTableRow(ipTable, 'IPv6 Addresses', 'None');
                }
                
                // Add separator between servers
                if (serverIndex < Object.keys(serverGroups).length) {
                    const tr = document.createElement('tr');
                    const td = document.createElement('td');
                    td.colSpan = 2;
                    td.style.borderBottom = '2px solid var(--results-container-border)';
                    td.style.height = '15px';
                    tr.appendChild(td);
                    ipTable.appendChild(tr);
                }
                
                serverIndex++;
            }
        } else {
            addTableRow(ipTable, 'IP Addresses', 'No IP address data available');
        }
        
        // Security & Authentication 
        const securityTable = document.getElementById('securityDetailsTable');
        securityTable.innerHTML = '';
        
        if (data.email_validation_record) {
            addTableRow(securityTable, 'SPF Status', data.email_validation_record.spf_status || 'N/A');
            addTableRow(securityTable, 'DKIM Status', data.email_validation_record.dkim_status || 'N/A');
            addTableRow(securityTable, 'DMARC Status', data.email_validation_record.dmarc_status || 'N/A');
            addTableRow(securityTable, 'Server Policies', data.email_validation_record.server_policies || 'N/A');
            addTableRow(securityTable, 'Disposable', data.email_validation_record.disposable || 'N/A');
            addTableRow(securityTable, 'Blacklist Info', data.email_validation_record.blacklist_info || 'N/A');
            
            // IMAP and POP3 info
            addTableRow(securityTable, 'IMAP Status', data.email_validation_record.imap_status || 'N/A');
            addTableRow(securityTable, 'IMAP Info', data.email_validation_record.imap_info || 'N/A');
            addTableRow(securityTable, 'IMAP Security', data.email_validation_record.imap_security || 'N/A');
            addTableRow(securityTable, 'POP3 Status', data.email_validation_record.pop3_status || 'N/A');
            addTableRow(securityTable, 'POP3 Info', data.email_validation_record.pop3_info || 'N/A');
            addTableRow(securityTable, 'POP3 Security', data.email_validation_record.pop3_security || 'N/A');
        }
        
        // Timing & Performance
        const timingTable = document.getElementById('timingDetailsTable');
        timingTable.innerHTML = '';
        
        if (data.email_validation_record) {
            // Use the formatted execution time from the backend if available
            const executionTimeDisplay = data.email_validation_record.execution_time_formatted || 
                                      (data.email_validation_record.execution_time ? 
                                       formatExecutionTime(data.email_validation_record.execution_time) : 'N/A');
                                       
            addTableRow(timingTable, 'Execution Time', executionTimeDisplay);
            
            addTableRow(timingTable, 'Timestamp', formatDate(data.email_validation_record.timestamp) || 'N/A');
            addTableRow(timingTable, 'Check Count', data.email_validation_record.check_count || 'N/A');
            addTableRow(timingTable, 'Validation Complete', data.email_validation_record.validation_complete ? 'Yes' : 'No');
            addTableRow(timingTable, 'Timing Details', data.email_validation_record.timing_details || 'N/A');
        }
    }
    
    // Helper function to add a row to a table
    function addTableRow(table, label, value) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        valueCell.textContent = value;
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }
    
    // Helper function to format date
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString();
    }
    
    // Add this helper function for time formatting
    function formatExecutionTime(milliseconds) {
        const seconds = milliseconds / 1000;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = (seconds % 60).toFixed(2);
        
        if (minutes > 0) {
            return `${minutes} minute${minutes > 1 ? 's' : ''}, ${remainingSeconds} seconds`;
        } else {
            return `${remainingSeconds} seconds`;
        }
    }
});

// Modify the show_message function to use prepend instead of append
eel.expose(show_message);
function show_message(label, message, persistent = false, details = null) {
    const div = document.createElement("div");

    let [category, status] = label.split(":");
    if (!status) {
        status = category;
        category = "generic";
    }

    div.className = `toast ${category}-${status}`;
    
    // Create a container for the message
    const messageContainer = document.createElement("div");
    messageContainer.className = "toast-message";
    messageContainer.textContent = message;
    div.appendChild(messageContainer);
    
    // Create a container for the expanded details (hidden by default)
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
        // Add the data-persistent attribute to enable proper CSS targeting
        div.setAttribute('data-persistent', 'true');
        div.style.cursor = 'pointer';
        div.style.position = 'relative';
        
        // Add hover expansion behavior for persistent notifications
        let hoverTimeout;
        
        if (details) {
            div.addEventListener('mouseenter', function() {
                hoverTimeout = setTimeout(() => {
                    const detailsContainer = this.querySelector('.toast-details');
                    if (detailsContainer) {
                        detailsContainer.style.display = "block";
                        // Use a timeout to allow the browser to process the display change first
                        setTimeout(() => {
                            detailsContainer.style.maxHeight = detailsContainer.scrollHeight + "px";
                            detailsContainer.style.padding = "8px 0 0 0";
                        }, 10);
                    }
                }, 500); // 0.5 second delay
            });
            
            div.addEventListener('mouseleave', function() {
                clearTimeout(hoverTimeout);
                const detailsContainer = this.querySelector('.toast-details');
                if (detailsContainer) {
                    detailsContainer.style.maxHeight = "0";
                    detailsContainer.style.padding = "0";
                    // Hide after transition
                    setTimeout(() => {
                        if (detailsContainer.style.maxHeight === "0px") {
                            detailsContainer.style.display = "none";
                        }
                    }, 300);
                }
            });
        }
        
        // Add close indicator
        const closeIcon = document.createElement('span');
        closeIcon.textContent = '✕';
        closeIcon.className = 'close-icon';
        div.appendChild(closeIcon);
        
        // Add click handler to dismiss
        div.addEventListener('click', function(e) {
            // Only dismiss if clicking the close icon or the main div (not the details)
            if (e.target === closeIcon || e.target === messageContainer || e.target === div) {
                div.style.opacity = '0';
                div.style.transform = 'translateX(-100%)';
                setTimeout(() => div.remove(), 300);
            }
        });
    } else {
        // For non-persistent notifications, just set the text directly
        div.textContent = message;
    }
    
    // Add animation and positioning for entry
    div.style.opacity = '0';
    div.style.transform = 'translateX(-100%)';
    div.style.transition = 'all 0.3s ease';
    
    // Add to container - prepend to place new notifications at the top (FIFO style)
    const container = document.getElementById("message-container");
    container.prepend(div);
    
    // Trigger animation to show toast
    setTimeout(() => {
        div.style.opacity = '1';
        div.style.transform = 'translateX(0)';
    }, 10);
    
    // If not persistent, remove after 5 seconds
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
    
    // Initialize settings if needed
    if (typeof initSettingsMenu === 'function') {
        initSettingsMenu().then(() => {
            // Switch to the specified tab
            if (tabName) {
                switchSettingsTab(tabName);
            }
        });
    }
    
    // Disable scrolling on the background
    document.body.style.overflow = 'hidden';
}

function closeSettingsPanel() {
    const settingsPanel = document.getElementById('settingsPanel');
    settingsPanel.style.display = 'none';
    
    // Re-enable scrolling
    document.body.style.overflow = 'auto';
}

// Add event listeners when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Your existing code...
    
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
});