/**
 * Results Display Module
 * Handles display of validation results, detailed data, and accordion functionality
 */

class ResultsDisplay {
    constructor() {
        this.showMoreButton = null;
        this.expandedDetails = null;
        this.collapseAllButton = null;
        this.expandAllButton = null;
    }

    /**
     * Initialize the results display
     */
    init() {
        this.showMoreButton = document.getElementById('showMoreButton');
        this.expandedDetails = document.getElementById('expandedDetails');
        this.collapseAllButton = document.getElementById('collapseAllButton');
        this.expandAllButton = document.getElementById('expandAllButton');

        this.attachEventListeners();
        this.initAccordion();
        
        return true;
    }

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        // Show More button handler
        if (this.showMoreButton) {
            this.showMoreButton.addEventListener('click', () => this.handleShowMoreClick());
        }
        
        // Collapse All button
        if (this.collapseAllButton) {
            this.collapseAllButton.addEventListener('click', () => this.collapseAllAccordions());
        }
        
        // Expand All button
        if (this.expandAllButton) {
            this.expandAllButton.addEventListener('click', () => this.expandAllAccordions());
        }
    }

    /**
     * Display basic validation results
     */
    displayResults(details) {
        if (!details) return;

        // Populate basic detailed results
        this.setElementText('confidenceScore', details.confidence_score + '%');
        this.setElementText('confidenceLevel', details.confidence_level);
        
        // Enhanced SMTP details display
        const smtpVerified = details.smtp_result || details.smtp_verified;
        this.setElementText('smtpVerified', smtpVerified ? '✓ Yes' : '✗ No');
        
        // Add SMTP details if available
        const smtpDetails = details.smtp_details || {};
        if (smtpDetails && Object.keys(smtpDetails).length > 0) {
            // Check if elements exist before updating
            if (document.getElementById('smtpConnection')) {
                this.setElementText('smtpConnection', 
                    smtpDetails.connection_success ? '✓ Connected' : '✗ Failed');
            }
            if (document.getElementById('smtpResponse')) {
                this.setElementText('smtpResponse', 
                    smtpDetails.smtp_flow_success ? '✓ Accepted' : '✗ Rejected');
            }
            if (document.getElementById('smtpErrorCode')) {
                this.setElementText('smtpErrorCode', 
                    smtpDetails.smtp_error_code || 'None');
            }
        }
        
        this.setElementText('isDisposable', details.is_disposable ? '✗ Yes' : '✓ No');
        
        // Format MX records
        if (details.mx_records && details.mx_records.length > 0) {
            this.setElementText('mxRecords', details.mx_records.join(', '));
        } else {
            this.setElementText('mxRecords', 'None found');
        }
        
        this.setElementText('traceId', details.trace_id);
        
        // Reset expanded details if they were shown
        if (this.expandedDetails && this.expandedDetails.style.display === 'block') {
            this.expandedDetails.style.display = 'none';
            if (this.showMoreButton) {
                this.showMoreButton.textContent = 'Show More Details';
            }
        }
    }

    /**
     * Handle Show More button click
     */
    async handleShowMoreClick() {
        const traceId = document.getElementById('traceId')?.innerText;
        
        if (!traceId || traceId === '-') return;
        
        // If expandedDetails is already visible, toggle it
        if (this.expandedDetails.style.display === 'block') {
            this.expandedDetails.style.display = 'none';
            this.showMoreButton.textContent = 'Show More Details';
        } else {
            // Show loading state
            this.showMoreButton.textContent = 'Loading...';
            this.showMoreButton.disabled = true;
            
            try {
                // Call Python function to get detailed data
                const data = await eel.get_detailed_validation_data(traceId)();
                
                // Populate the detailed sections with the returned data
                this.populateDetailedSections(data);
                
                // Show the expanded details section
                this.expandedDetails.style.display = 'block';
                
                // Change button text and re-enable
                this.showMoreButton.textContent = 'Hide Details';
                this.showMoreButton.disabled = false;
                
            } catch (error) {
                console.error('Error loading detailed data:', error);
                this.showMoreButton.textContent = 'Show More Details';
                this.showMoreButton.disabled = false;
            }
        }
    }

    /**
     * Populate detailed sections with data
     */
    populateDetailedSections(data) {
        // DNS Information
        this.populateDNSDetails(data);
        
        // SMTP Details
        this.populateSMTPDetails(data);
        
        // MX Infrastructure
        this.populateMXDetails(data);
        
        // IP Information
        this.populateIPDetails(data);
        
        // Security & Authentication
        this.populateSecurityDetails(data);
        
        // Timing & Performance
        this.populateTimingDetails(data);
    }

    /**
     * Populate DNS details table
     */
    populateDNSDetails(data) {
        const dnsTable = document.getElementById('dnsDetailsTable');
        if (!dnsTable) return;
        
        dnsTable.innerHTML = '';
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            this.addTableRow(dnsTable, 'Domain', record.domain || 'N/A');
            this.addTableRow(dnsTable, 'MX Records', record.mx_records || 'N/A');
            this.addTableRow(dnsTable, 'MX Preferences', record.mx_preferences || 'N/A');
            this.addTableRow(dnsTable, 'Reverse DNS', record.reverse_dns || 'N/A');
            this.addTableRow(dnsTable, 'WHOIS Info', record.whois_info || 'N/A');
        }
    }

    /**
     * Populate SMTP details table
     */
    populateSMTPDetails(data) {
        const smtpTable = document.getElementById('smtpDetailsTable');
        if (!smtpTable) return;
        
        smtpTable.innerHTML = '';
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            this.addTableRow(smtpTable, 'SMTP Result', record.smtp_result || 'N/A');
            this.addTableRow(smtpTable, 'SMTP Banner', record.smtp_banner || 'N/A');
            this.addTableRow(smtpTable, 'SMTP VRFY', record.smtp_vrfy || 'N/A');
            this.addTableRow(smtpTable, 'Port Used', record.port || 'N/A');
            this.addTableRow(smtpTable, 'Catch-All', record.catch_all || 'N/A');
        }
    }

    /**
     * Populate MX details table
     */
    populateMXDetails(data) {
        const mxTable = document.getElementById('mxDetailsTable');
        if (!mxTable) return;
        
        mxTable.innerHTML = '';
        
        if (data.mx_infrastructure && data.mx_infrastructure.length > 0) {
            data.mx_infrastructure.forEach((mx, index) => {
                this.addTableRow(mxTable, `MX Record ${index + 1}`, mx.mx_record || 'N/A');
                this.addTableRow(mxTable, `Preference`, mx.preference || 'N/A');
                this.addTableRow(mxTable, `Primary`, mx.is_primary ? 'Yes' : 'No');
                this.addTableRow(mxTable, `Has Failover`, mx.has_failover ? 'Yes' : 'No');
                this.addTableRow(mxTable, `Load Balanced`, mx.load_balanced ? 'Yes' : 'No');
                this.addTableRow(mxTable, `Provider`, mx.provider_name || 'N/A');
                this.addTableRow(mxTable, `Self-Hosted`, mx.is_self_hosted ? 'Yes' : 'No');
                
                if (index < data.mx_infrastructure.length - 1) {
                    this.addTableSeparator(mxTable);
                }
            });
        } else {
            this.addTableRow(mxTable, 'MX Records', 'No MX infrastructure data available');
        }
    }

    /**
     * Populate IP details table
     */
    populateIPDetails(data) {
        const ipTable = document.getElementById('ipDetailsTable');
        if (!ipTable) return;
        
        ipTable.innerHTML = '';

        if (data.mx_ip_addresses && data.mx_ip_addresses.length > 0) {
            // Group IP addresses by mx_infrastructure_id
            const serverGroups = this.groupIPAddresses(data.mx_ip_addresses);
            
            // Display the grouped data
            let serverIndex = 1;
            for (const [infraId, info] of Object.entries(serverGroups)) {
                this.addTableRow(ipTable, `Server ${serverIndex}`, info.name || `Mail Server ${infraId}`);
                
                // Add IPv4 addresses
                this.addIPAddressGroup(ipTable, 'IPv4 Addresses', info.ipv4);
                this.addTableSeparator(ipTable);
                
                // Add IPv6 addresses
                this.addIPAddressGroup(ipTable, 'IPv6 Addresses', info.ipv6);
                
                if (serverIndex < Object.keys(serverGroups).length) {
                    this.addTableSeparator(ipTable, true);
                }
                
                serverIndex++;
            }
        } else {
            this.addTableRow(ipTable, 'IP Addresses', 'No IP address data available');
        }
    }

    /**
     * Populate security details table
     */
    populateSecurityDetails(data) {
        const securityTable = document.getElementById('securityDetailsTable');
        if (!securityTable) return;
        
        securityTable.innerHTML = '';
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            this.addTableRow(securityTable, 'SPF Status', record.spf_status || 'N/A');
            this.addTableRow(securityTable, 'DKIM Status', record.dkim_status || 'N/A');
            this.addTableRow(securityTable, 'DMARC Status', record.dmarc_status || 'N/A');
            this.addTableRow(securityTable, 'Server Policies', record.server_policies || 'N/A');
            this.addTableRow(securityTable, 'Disposable', record.disposable || 'N/A');
            this.addTableRow(securityTable, 'Blacklist Info', record.blacklist_info || 'N/A');
            this.addTableRow(securityTable, 'IMAP Status', record.imap_status || 'N/A');
            this.addTableRow(securityTable, 'IMAP Info', record.imap_info || 'N/A');
            this.addTableRow(securityTable, 'IMAP Security', record.imap_security || 'N/A');
            this.addTableRow(securityTable, 'POP3 Status', record.pop3_status || 'N/A');
            this.addTableRow(securityTable, 'POP3 Info', record.pop3_info || 'N/A');
            this.addTableRow(securityTable, 'POP3 Security', record.pop3_security || 'N/A');
        }
    }

    /**
     * Populate timing details table
     */
    populateTimingDetails(data) {
        const timingTable = document.getElementById('timingDetailsTable');
        if (!timingTable) return;
        
        timingTable.innerHTML = '';
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            const executionTimeDisplay = record.execution_time_formatted || 
                                      (record.execution_time ? 
                                       this.formatExecutionTime(record.execution_time) : 'N/A');
                                       
            this.addTableRow(timingTable, 'Execution Time', executionTimeDisplay);
            this.addTableRow(timingTable, 'Timestamp', this.formatDate(record.timestamp) || 'N/A');
            this.addTableRow(timingTable, 'Check Count', record.check_count || 'N/A');
            this.addTableRow(timingTable, 'Validation Complete', record.validation_complete ? 'Yes' : 'No');
            this.addTableRow(timingTable, 'Timing Details', record.timing_details || 'N/A');
        }
    }

    /**
     * Group IP addresses by infrastructure ID
     */
    groupIPAddresses(ipAddresses) {
        const serverGroups = {};
        
        // Initialize groups
        ipAddresses.forEach(ip => {
            const infraId = ip.mx_infrastructure_id;
            if (!serverGroups[infraId]) {
                serverGroups[infraId] = {
                    name: null,
                    ipv4: [],
                    ipv6: []
                };
            }
            
            if (ip.ptr_record && !serverGroups[infraId].name) {
                serverGroups[infraId].name = ip.ptr_record;
            }
        });
        
        // Add IPs to groups
        ipAddresses.forEach(ip => {
            const infraId = ip.mx_infrastructure_id;
            const group = serverGroups[infraId];
            
            if (!group.name) {
                group.name = `Mail Server ${infraId}`;
            }
            
            const ipData = {
                address: ip.ip_address,
                country: ip.country_code || 'N/A',
                region: ip.region || 'N/A',
                provider: ip.provider || 'N/A'
            };
            
            if (ip.ip_version === 4) {
                group.ipv4.push(ipData);
            } else if (ip.ip_version === 6) {
                group.ipv6.push(ipData);
            }
        });
        
        return serverGroups;
    }

    /**
     * Add IP address group to table
     */
    addIPAddressGroup(table, label, addresses) {
        if (addresses.length > 0) {
            this.addTableRow(table, label, '');
            addresses.forEach((ip, idx) => {
                this.addTableRow(table, `  Address ${idx+1}`, ip.address);
                this.addTableRow(table, `  Location`, `${ip.country}, ${ip.region}`);
                this.addTableRow(table, `  Provider`, ip.provider);
                
                if (idx < addresses.length - 1) {
                    this.addTableSeparator(table, false, true);
                }
            });
        } else {
            this.addTableRow(table, label, 'None');
        }
    }

    /**
     * Add a row to a table
     */
    addTableRow(table, label, value) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        valueCell.textContent = value;
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add table separator
     */
    addTableSeparator(table, thick = false, mini = false) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.style.borderBottom = mini ? 
            '1px dashed var(--results-container-border)' : 
            (thick ? '2px solid var(--results-container-border)' : '1px solid var(--results-container-border)');
        td.style.height = mini ? '5px' : (thick ? '15px' : '10px');
        tr.appendChild(td);
        table.appendChild(tr);
    }

    /**
     * Initialize accordion functionality
     */
    initAccordion() {
        document.querySelectorAll('.accordion-header').forEach(header => {
            header.addEventListener('click', () => {
                const item = header.parentElement;
                const content = item.querySelector('.accordion-content');
                
                if (item.classList.contains('active')) {
                    content.style.maxHeight = '0px';
                    setTimeout(() => {
                        item.classList.remove('active');
                    }, 500);
                } else {
                    item.classList.add('active');
                    content.style.transition = 'none';
                    content.style.maxHeight = 'none';
                    const actualHeight = content.scrollHeight;
                    content.style.maxHeight = '0px';
                    
                    void content.offsetHeight;
                    
                    content.style.transition = 'max-height 0.5s ease';
                    content.style.maxHeight = actualHeight + 'px';
                }
            });
        });
        
        // Set initial state for active accordions
        document.querySelectorAll('.accordion-item.active').forEach(item => {
            const content = item.querySelector('.accordion-content');
            content.style.maxHeight = content.scrollHeight + 'px';
        });
    }

    /**
     * Collapse all accordions
     */
    collapseAllAccordions() {
        document.querySelectorAll('.accordion-item').forEach(item => {
            item.classList.remove('active');
        });
    }

    /**
     * Expand all accordions
     */
    expandAllAccordions() {
        document.querySelectorAll('.accordion-item').forEach(item => {
            item.classList.add('active');
        });
    }

    /**
     * Set element text content safely
     */
    setElementText(elementId, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerText = text;
        }
    }

    /**
     * Format date string
     */
    formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString();
    }

    /**
     * Format execution time
     */
    formatExecutionTime(milliseconds) {
        const seconds = milliseconds / 1000;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = (seconds % 60).toFixed(2);
        
        if (minutes > 0) {
            return `${minutes} minute${minutes > 1 ? 's' : ''}, ${remainingSeconds} seconds`;
        } else {
            return `${remainingSeconds} seconds`;
        }
    }
}

// Export for use in other modules
window.ResultsDisplay = ResultsDisplay;