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
     * Display basic validation results with improved CSS integration
     */
    displayResults(details) {
        if (!details) return;

        // Populate basic detailed results using CSS utility classes
        this.setElementText('confidenceScore', details.confidence_score + '%');
        this.setElementText('confidenceLevel', details.confidence_level);
        
        // Enhanced SMTP details display with CSS styling
        const smtpVerified = details.smtp_result || details.smtp_verified;
        this.setElementWithIcon('smtpVerified', smtpVerified, 'Yes', 'No');
        
        // Add SMTP details if available
        const smtpDetails = details.smtp_details || {};
        if (smtpDetails && Object.keys(smtpDetails).length > 0) {
            // Use improved CSS-based styling for SMTP status display
            if (document.getElementById('smtpConnection')) {
                this.setElementWithIcon('smtpConnection', 
                    smtpDetails.connection_success, 'Connected', 'Failed');
            }
            if (document.getElementById('smtpResponse')) {
                this.setElementWithIcon('smtpResponse', 
                    smtpDetails.smtp_flow_success, 'Accepted', 'Rejected');
            }
            if (document.getElementById('smtpErrorCode')) {
                this.setElementText('smtpErrorCode', 
                    smtpDetails.smtp_error_code || 'None');
            }
        }
        
        this.setElementWithIcon('isDisposable', !details.is_disposable, 'No', 'Yes');
        
        // Format MX records with better styling
        if (details.mx_records && details.mx_records.length > 0) {
            this.setElementText('mxRecords', details.mx_records.join(', '));
        } else {
            this.setElementText('mxRecords', 'None found');
        }
        
        this.setElementText('traceId', details.trace_id);
        
        // Reset expanded details if they were shown using CSS classes
        if (this.expandedDetails && this.expandedDetails.style.display === 'block') {
            this.expandedDetails.style.display = 'none';
            if (this.showMoreButton) {
                this.showMoreButton.textContent = 'Show More Details';
                this.showMoreButton.className = 'btn btn-secondary';
            }
        }
    }

    /**
     * Handle Show More button click with improved loading states
     */
    async handleShowMoreClick() {
        const traceId = document.getElementById('traceId')?.innerText;
        
        if (!traceId || traceId === '-') return;
        
        // If expandedDetails is already visible, toggle it
        if (this.expandedDetails.style.display === 'block') {
            this.expandedDetails.style.display = 'none';
            this.showMoreButton.textContent = 'Show More Details';
            this.showMoreButton.className = 'btn btn-secondary';
        } else {
            // Show loading state with proper CSS classes
            this.showMoreButton.textContent = 'Loading...';
            this.showMoreButton.className = 'btn btn-secondary disabled';
            this.showMoreButton.disabled = true;
            
            try {
                // Call Python function to get detailed data
                const data = await eel.get_detailed_validation_data(traceId)();
                
                // Populate the detailed sections with the returned data
                this.populateDetailedSections(data);
                
                // Show the expanded details section
                this.expandedDetails.style.display = 'block';
                
                // Change button text and re-enable with proper CSS classes
                this.showMoreButton.textContent = 'Hide Details';
                this.showMoreButton.className = 'btn btn-secondary';
                this.showMoreButton.disabled = false;
                
                // Show success toast using new CSS classes
                this.showToast('Detailed data loaded successfully', 'success');
                
            } catch (error) {
                console.error('Error loading detailed data:', error);
                this.showMoreButton.textContent = 'Show More Details';
                this.showMoreButton.className = 'btn btn-secondary';
                this.showMoreButton.disabled = false;
                
                // Show error toast using new CSS classes
                this.showToast('Failed to load detailed data', 'error');
            }
        }
    }

    /**
     * Populate detailed sections with data using improved CSS styling
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
        
        // DMARC Analysis
        this.populateDMARCAnalysis(data);
        
        // Timing & Performance
        this.populateTimingDetails(data);
    }

    /**
     * Populate DNS details table with improved styling
     */
    populateDNSDetails(data) {
        const dnsTable = document.getElementById('dnsDetailsTable');
        if (!dnsTable) return;
        
        dnsTable.innerHTML = '';
        dnsTable.className = 'details-table'; // Use CSS class from components.css
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            this.addTableRow(dnsTable, 'Domain', record.domain || 'N/A');
            this.addTableRow(dnsTable, 'MX Records', record.mx_records || 'N/A');
            this.addTableRow(dnsTable, 'MX Preferences', record.mx_preferences || 'N/A');
            this.addTableRow(dnsTable, 'Reverse DNS', record.reverse_dns || 'N/A');
            this.addTableRow(dnsTable, 'WHOIS Info', record.whois_info || 'N/A');
        } else {
            this.addTableRow(dnsTable, 'DNS Information', 'No DNS data available');
        }
    }

    /**
     * Populate SMTP details table with enhanced status indicators
     */
    populateSMTPDetails(data) {
        const smtpTable = document.getElementById('smtpDetailsTable');
        if (!smtpTable) return;
        
        smtpTable.innerHTML = '';
        smtpTable.className = 'details-table'; // Use CSS class from components.css
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            
            // Add SMTP status with proper CSS styling for success/error
            this.addStatusRow(smtpTable, 'SMTP Result', record.smtp_result, 'Valid', 'Invalid');
                
            // Add SMTP banner with code styling
            if (record.smtp_banner) {
                this.addCodeRow(smtpTable, 'SMTP Banner', record.smtp_banner);
            }
            
            // Add SMTP support details with status indicators
            this.addStatusRow(smtpTable, 'SMTP VRFY Support', record.smtp_vrfy, 'Supported', 'Not Supported');
            this.addStatusRow(smtpTable, 'TLS Support', record.smtp_supports_tls, 'Supported', 'Not Supported');
            this.addStatusRow(smtpTable, 'AUTH Support', record.smtp_supports_auth, 'Supported', 'Not Supported');
            this.addStatusRow(smtpTable, 'SMTP Flow Completed', record.smtp_flow_success, 'Yes', 'No');
                
            // Add error code if available with warning styling
            if (record.smtp_error_code) {
                this.addWarningRow(smtpTable, 'SMTP Error Code', record.smtp_error_code);
            }
            
            // Add server message if available
            if (record.smtp_server_message) {
                this.addCodeRow(smtpTable, 'Server Message', record.smtp_server_message);
            }
            
            // Add port information if available
            if (record.port) {
                this.addTableRow(smtpTable, 'Port Used', record.port);
            }
            
            // Add catch-all status with proper styling
            this.addInfoRow(smtpTable, 'Catch-All Domain', 
                record.catch_all ? 'Yes (accepts all emails)' : 'No');
        } else {
            this.addTableRow(smtpTable, 'SMTP Details', 'No SMTP data available');
        }
    }

    /**
     * Populate MX details table with improved organization
     */
    populateMXDetails(data) {
        const mxTable = document.getElementById('mxDetailsTable');
        if (!mxTable) return;
        
        mxTable.innerHTML = '';
        mxTable.className = 'details-table'; // Use CSS class from components.css
        
        if (data.mx_infrastructure && data.mx_infrastructure.length > 0) {
            data.mx_infrastructure.forEach((mx, index) => {
                // Create header for each MX record with CSS styling
                this.addHeaderRow(mxTable, `MX Record ${index + 1}`);
                
                this.addTableRow(mxTable, 'Record', mx.mx_record || 'N/A');
                this.addTableRow(mxTable, 'Preference', mx.preference || 'N/A');
                this.addStatusRow(mxTable, 'Primary', mx.is_primary, 'Yes', 'No');
                this.addStatusRow(mxTable, 'Has Failover', mx.has_failover, 'Yes', 'No');
                this.addStatusRow(mxTable, 'Load Balanced', mx.load_balanced, 'Yes', 'No');
                this.addTableRow(mxTable, 'Provider', mx.provider_name || 'N/A');
                this.addStatusRow(mxTable, 'Self-Hosted', mx.is_self_hosted, 'Yes', 'No');
                
                if (index < data.mx_infrastructure.length - 1) {
                    this.addTableSeparator(mxTable);
                }
            });
        } else {
            this.addTableRow(mxTable, 'MX Records', 'No MX infrastructure data available');
        }
    }

    /**
     * Populate IP details table with enhanced grouping
     */
    populateIPDetails(data) {
        const ipTable = document.getElementById('ipDetailsTable');
        if (!ipTable) return;
        
        ipTable.innerHTML = '';
        ipTable.className = 'details-table'; // Use CSS class from components.css

        if (data.mx_ip_addresses && data.mx_ip_addresses.length > 0) {
            // Group IP addresses by mx_infrastructure_id
            const serverGroups = this.groupIPAddresses(data.mx_ip_addresses);
            
            // Display the grouped data with improved styling
            let serverIndex = 1;
            for (const [infraId, info] of Object.entries(serverGroups)) {
                this.addHeaderRow(ipTable, `Server ${serverIndex}: ${info.name || `Mail Server ${infraId}`}`);
                
                // Add IPv4 addresses with improved styling
                this.addIPAddressGroup(ipTable, 'IPv4 Addresses', info.ipv4);
                this.addTableSeparator(ipTable);
                
                // Add IPv6 addresses with improved styling
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
     * Populate security details table with status indicators
     */
    populateSecurityDetails(data) {
        const securityTable = document.getElementById('securityDetailsTable');
        if (!securityTable) return;
        
        securityTable.innerHTML = '';
        securityTable.className = 'details-table'; // Use CSS class from components.css
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            
            // Email security protocols with status styling
            this.addHeaderRow(securityTable, 'Email Security Protocols');
            
            // Enhanced SPF display with more details
            this.addSecurityRow(securityTable, 'SPF Status', record.spf_status);
            
            // Add SPF details if available
            if (record.spf_details) {
                let spfDetails;
                try {
                    spfDetails = typeof record.spf_details === 'string' ? 
                        JSON.parse(record.spf_details) : record.spf_details;
                        
                    if (spfDetails) {
                        this.addTableSeparator(securityTable, false, true);
                        this.addSubheaderRow(securityTable, 'SPF Details');
                        
                        if (spfDetails.spf_record) {
                            this.addCodeRow(securityTable, 'SPF Record', spfDetails.spf_record);
                        }
                        
                        if (spfDetails.spf_result) {
                            let resultClass = 'text-muted';
                            if (spfDetails.spf_result === 'pass') {
                                resultClass = 'valid-result';
                            } else if (['fail', 'permerror', 'temperror'].includes(spfDetails.spf_result)) {
                                resultClass = 'invalid-result';
                            } else if (spfDetails.spf_result === 'softfail') {
                                resultClass = 'warning-color';
                            }
                            
                            const resultCell = document.createElement('td');
                            resultCell.innerHTML = `<span class="${resultClass}">${spfDetails.spf_result}</span>`;
                            this.addTableRow(securityTable, 'Result', '', resultCell);
                        }
                        
                        if (spfDetails.spf_mechanism_matched) {
                            this.addTableRow(securityTable, 'Mechanism Matched', spfDetails.spf_mechanism_matched);
                        }
                        
                        if (spfDetails.spf_dns_lookups) {
                            this.addTableRow(securityTable, 'DNS Lookups', spfDetails.spf_dns_lookups);
                        }
                        
                        if (spfDetails.spf_reason) {
                            this.addTableRow(securityTable, 'Reason', spfDetails.spf_reason);
                        }
                        
                        // Add warnings if available
                        if (spfDetails.warnings && spfDetails.warnings.length > 0) {
                            this.addWarningRow(securityTable, 'Warnings', spfDetails.warnings.join(', '));
                        }
                        
                        // Add errors if available
                        if (spfDetails.errors && spfDetails.errors.length > 0) {
                            const errorMessage = spfDetails.errors.join(', ');
                            this.addWarningRow(securityTable, 'Errors', errorMessage);
                        }
                        
                        // Add DNS lookup log if available
                        if (spfDetails.dns_lookup_log && spfDetails.dns_lookup_log.length > 0) {
                            this.addTableSeparator(securityTable);
                            this.addSubheaderRow(securityTable, 'SPF DNS Lookup Log');
                            
                            spfDetails.dns_lookup_log.forEach((log, index) => {
                                this.addTableRow(securityTable, `Lookup ${index+1}`, 
                                    `Mechanism: ${log.mechanism}, Lookups: ${log.lookups_used}, Total: ${log.total_so_far}`);
                            });
                        }
                    }
                } catch (e) {
                    console.error('Error parsing SPF details:', e);
                }
            }
            
            this.addSecurityRow(securityTable, 'DKIM Status', record.dkim_status);
            this.addSecurityRow(securityTable, 'DMARC Status', record.dmarc_status);
            
            this.addTableSeparator(securityTable);
            
            // Server and policy information
            this.addHeaderRow(securityTable, 'Server Information');
            this.addTableRow(securityTable, 'Server Policies', record.server_policies || 'N/A');
            this.addStatusRow(securityTable, 'Disposable Email', record.disposable, 'Yes', 'No');
            this.addTableRow(securityTable, 'Blacklist Info', record.blacklist_info || 'N/A');
            
            this.addTableSeparator(securityTable);
            
            // Protocol support
            this.addHeaderRow(securityTable, 'Protocol Support');
            this.addSecurityRow(securityTable, 'IMAP Status', record.imap_status);
            this.addTableRow(securityTable, 'IMAP Info', record.imap_info || 'N/A');
            this.addTableRow(securityTable, 'IMAP Security', record.imap_security || 'N/A');
            this.addSecurityRow(securityTable, 'POP3 Status', record.pop3_status);
            this.addTableRow(securityTable, 'POP3 Info', record.pop3_info || 'N/A');
            this.addTableRow(securityTable, 'POP3 Security', record.pop3_security || 'N/A');
        } else {
            this.addTableRow(securityTable, 'Security Details', 'No security data available');
        }
    }

    /**
     * Populate DMARC analysis section
     * @param {Object} data - Validation details data
     */
    populateDMARCAnalysis(data) {
        // Check if we have domain info
        if (!data || !data.email_validation_record || !data.email_validation_record.domain) return;
        
        const domain = data.email_validation_record.domain;
        
        // Initialize DMARC analyzer if needed
        if (!window.dmarcAnalyzer) {
            if (window.DmarcAnalyzer) {
                window.dmarcAnalyzer = new DmarcAnalyzer();
                window.dmarcAnalyzer.init();
            } else {
                console.error('DmarcAnalyzer class not found');
                return;
            }
        }
        
        // Set loading state
        const dmarcLoading = document.getElementById('dmarcLoading');
        const dmarcDetails = document.getElementById('dmarcDetails');
        
        if (dmarcLoading) dmarcLoading.style.display = 'block';
        if (dmarcDetails) dmarcDetails.innerHTML = '';
        
        // Analyze domain and display results
        window.dmarcAnalyzer.analyzeDomain(domain)
            .then(dmarcInfo => {
                window.dmarcAnalyzer.displayResults(dmarcInfo);
            })
            .catch(error => {
                console.error('Error analyzing DMARC:', error);
                // Display error in DMARC section
                if (dmarcDetails) {
                    dmarcDetails.innerHTML = `
                        <div class="message error">
                            <strong>Error:</strong> Failed to analyze DMARC
                        </div>
                    `;
                }
            });
    }

    /**
     * Populate timing details table with formatted times
     */
    populateTimingDetails(data) {
        const timingTable = document.getElementById('timingDetailsTable');
        if (!timingTable) return;
        
        timingTable.innerHTML = '';
        timingTable.className = 'details-table'; // Use CSS class from components.css
        
        if (data.email_validation_record) {
            const record = data.email_validation_record;
            const executionTimeDisplay = record.execution_time_formatted || 
                                      (record.execution_time ? 
                                       this.formatExecutionTime(record.execution_time) : 'N/A');
                                       
            this.addTableRow(timingTable, 'Execution Time', executionTimeDisplay);
            this.addTableRow(timingTable, 'Timestamp', this.formatDate(record.timestamp) || 'N/A');
            this.addTableRow(timingTable, 'Check Count', record.check_count || 'N/A');
            this.addStatusRow(timingTable, 'Validation Complete', record.validation_complete, 'Yes', 'No');
            this.addCodeRow(timingTable, 'Timing Details', record.timing_details || 'N/A');
        } else {
            this.addTableRow(timingTable, 'Timing Details', 'No timing data available');
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
     * Add IP address group to table with improved styling
     */
    addIPAddressGroup(table, label, addresses) {
        if (addresses.length > 0) {
            this.addSubheaderRow(table, label);
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
     * Add a standard row to a table
     */
    addTableRow(table, label, value, customValueCell = null) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        if (customValueCell) {
            tr.appendChild(customValueCell);
        } else {
            const valueCell = document.createElement('td');
            valueCell.textContent = value;
            tr.appendChild(valueCell);
        }
        
        table.appendChild(tr);
    }

    /**
     * Add a status row with success/error styling
     */
    addStatusRow(table, label, status, trueText, falseText) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        if (status) {
            valueCell.innerHTML = `<span class="valid-result">✓ ${trueText}</span>`;
        } else {
            valueCell.innerHTML = `<span class="invalid-result">✗ ${falseText}</span>`;
        }
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add a security status row with appropriate styling
     */
    addSecurityRow(table, label, status) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        if (status && status.toLowerCase() !== 'n/a') {
            if (status.toLowerCase().includes('pass') || status.toLowerCase().includes('valid')) {
                valueCell.innerHTML = `<span class="valid-result">✓ ${status}</span>`;
            } else if (status.toLowerCase().includes('fail') || status.toLowerCase().includes('invalid')) {
                valueCell.innerHTML = `<span class="invalid-result">✗ ${status}</span>`;
            } else {
                valueCell.textContent = status;
            }
        } else {
            valueCell.innerHTML = `<span class="text-muted">${status || 'N/A'}</span>`;
        }
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add a header row for grouping
     */
    addHeaderRow(table, title) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.innerHTML = `<strong style="color: var(--primary-color);">${title}</strong>`;
        td.style.padding = '12px 8px 8px 8px';
        td.style.borderBottom = '2px solid var(--primary-color)';
        tr.appendChild(td);
        table.appendChild(tr);
    }

    /**
     * Add a subheader row for sections
     */
    addSubheaderRow(table, title) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.innerHTML = `<em style="color: var(--text-muted);">${title}</em>`;
        td.style.padding = '8px';
        td.style.fontWeight = '500';
        tr.appendChild(td);
        table.appendChild(tr);
    }

    /**
     * Add a code-styled row for technical information
     */
    addCodeRow(table, label, value) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        const codeSpan = document.createElement('span');
        codeSpan.style.backgroundColor = 'var(--code-bg)';
        codeSpan.style.color = 'var(--code-text)';
        codeSpan.style.padding = '2px 4px';
        codeSpan.style.borderRadius = '3px';
        codeSpan.style.fontFamily = 'monospace';
        codeSpan.textContent = value;
        valueCell.appendChild(codeSpan);
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add a warning-styled row
     */
    addWarningRow(table, label, value) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        valueCell.innerHTML = `<span style="color: var(--warning-color); font-weight: bold;">⚠️ ${value}</span>`;
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add an info-styled row
     */
    addInfoRow(table, label, value) {
        const tr = document.createElement('tr');
        
        const labelCell = document.createElement('td');
        labelCell.textContent = label;
        labelCell.style.fontWeight = 'bold';
        tr.appendChild(labelCell);
        
        const valueCell = document.createElement('td');
        valueCell.innerHTML = `<span style="color: var(--info-color);">ℹ️ ${value}</span>`;
        tr.appendChild(valueCell);
        
        table.appendChild(tr);
    }

    /**
     * Add table separator with CSS styling
     */
    addTableSeparator(table, thick = false, mini = false) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 2;
        td.style.borderBottom = mini ? 
            '1px dashed var(--border-color)' : 
            (thick ? '2px solid var(--border-color)' : '1px solid var(--border-color)');
        td.style.height = mini ? '5px' : (thick ? '15px' : '10px');
        tr.appendChild(td);
        table.appendChild(tr);
    }

    /**
     * Initialize accordion functionality with CSS integration
     */
    initAccordion() {
        document.querySelectorAll('.accordion-header').forEach(header => {
            // Ensure proper CSS classes are applied
            header.classList.add('accordion-header');
            
            header.addEventListener('click', () => {
                const item = header.parentElement;
                const content = item.querySelector('.accordion-content');
                
                if (item.classList.contains('active')) {
                    content.style.maxHeight = '0px';
                    setTimeout(() => {
                        item.classList.remove('active');
                    }, 300); // Match CSS transition timing
                } else {
                    item.classList.add('active');
                    content.style.transition = 'none';
                    content.style.maxHeight = 'none';
                    const actualHeight = content.scrollHeight;
                    content.style.maxHeight = '0px';
                    
                    void content.offsetHeight; // Force reflow
                    
                    content.style.transition = 'max-height 0.3s ease'; // Match CSS transition
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
     * Collapse all accordions using CSS classes
     */
    collapseAllAccordions() {
        document.querySelectorAll('.accordion-item').forEach(item => {
            const content = item.querySelector('.accordion-content');
            content.style.maxHeight = '0px';
            setTimeout(() => {
                item.classList.remove('active');
            }, 300);
        });
    }

    /**
     * Expand all accordions using CSS classes
     */
    expandAllAccordions() {
        document.querySelectorAll('.accordion-item').forEach(item => {
            const content = item.querySelector('.accordion-content');
            item.classList.add('active');
            content.style.maxHeight = content.scrollHeight + 'px';
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
     * Set element with icon based on status using CSS classes
     */
    setElementWithIcon(elementId, status, trueText, falseText) {
        const element = document.getElementById(elementId);
        if (element) {
            if (status) {
                element.innerHTML = `<span class="valid-result">✓ ${trueText}</span>`;
            } else {
                element.innerHTML = `<span class="invalid-result">✗ ${falseText}</span>`;
            }
        }
    }

    /**
     * Show toast notification using the global system
     */
    showToast(message, type = 'info') {
        // Use the global showToast function
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
        } else {
            console.log(`${type.toUpperCase()}: ${message}`);
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