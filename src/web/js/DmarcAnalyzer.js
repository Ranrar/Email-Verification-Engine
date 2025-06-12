/**
 * DMARC Analyzer
 * Handles DMARC analysis and visualization for Email Verification Engine
 */

class DmarcAnalyzer {
    constructor() {
        this.currentDomain = null;
        this.dmarcData = null;
    }

    /**
     * Initialize the DMARC analyzer
     */
    init() {
        return true;
    }

    /**
     * Analyze DMARC for a domain
     * @param {string} domain - Domain to analyze
     * @returns {Promise} - Promise that resolves when analysis is complete
     */
    async analyzeDomain(domain) {
        if (!domain) return null;
        
        this.currentDomain = domain;
        
        try {
            // Show loading indicator
            const dmarcLoading = document.getElementById('dmarcLoading');
            const dmarcDetails = document.getElementById('dmarcDetails');
            
            if (dmarcLoading) dmarcLoading.style.display = 'block';
            if (dmarcDetails) dmarcDetails.innerHTML = '';
            
            // Get DMARC info from backend
            const dmarcInfo = await eel.get_dmarc_info(domain)();
            this.dmarcData = dmarcInfo;
            
            return dmarcInfo;
        } catch (error) {
            console.error('Error analyzing DMARC:', error);
            return {
                success: false,
                error: `Failed to analyze DMARC: ${error.message || error}`
            };
        } finally {
            // Hide loading indicator
            const dmarcLoading = document.getElementById('dmarcLoading');
            if (dmarcLoading) dmarcLoading.style.display = 'none';
        }
    }

    /**
     * Display DMARC analysis results
     * @param {Object} dmarcInfo - DMARC analysis data
     */
    displayResults(dmarcInfo = null) {
        const data = dmarcInfo || this.dmarcData;
        if (!data) return;
        
        const dmarcDetails = document.getElementById('dmarcDetails');
        if (!dmarcDetails) return;
        
        if (!data.success) {
            dmarcDetails.innerHTML = `
                <div class="message error">
                    <strong>Error:</strong> ${data.error || 'Failed to analyze DMARC'}
                </div>
            `;
            return;
        }
        
        // Determine policy status class for styling
        let policyStatusClass = 'warning';
        if (data.policy === 'reject') {
            policyStatusClass = 'success';
        } else if (data.policy === 'none') {
            policyStatusClass = 'error';
        }
        
        let html = `
            <div class="results-container">
                <h3>DMARC Status for ${data.domain}</h3>
                <div class="grid-2col mb-15">
                    <div class="message ${data.has_dmarc ? 'success' : 'error'}">
                        <strong>DMARC Record:</strong> ${data.has_dmarc ? 'Present' : 'Missing'}
                    </div>
                    <div class="message ${policyStatusClass}">
                        <strong>Policy:</strong> ${data.policy.toUpperCase()} (${data.policy_strength})
                    </div>
                </div>`;
                
        if (data.has_dmarc) {
            // Show DMARC details in a table using the existing details-table class
            html += `
                <table class="details-table">
                    <tr>
                        <td>Subdomain Policy:</td>
                        <td>${data.subdomain_policy || 'Same as domain policy'}</td>
                    </tr>
                    <tr>
                        <td>Alignment Mode:</td>
                        <td>${data.alignment_mode || 'relaxed'}</td>
                    </tr>
                    <tr>
                        <td>Percentage Covered:</td>
                        <td>${data.percentage_covered}%</td>
                    </tr>
                    <tr>
                        <td>Aggregate Reporting:</td>
                        <td>${data.aggregate_reporting ? 'Enabled' : 'Disabled'}</td>
                    </tr>
                    <tr>
                        <td>Forensic Reporting:</td>
                        <td>${data.forensic_reporting ? 'Enabled' : 'Disabled'}</td>
                    </tr>`;
                
            if (data.execution_time_ms) {
                html += `
                    <tr>
                        <td>Analysis Time:</td>
                        <td>${(data.execution_time_ms / 1000).toFixed(2)}s</td>
                    </tr>`;
            }
                
            html += `</table>`;
                
            // Display DMARC record if available
            if (data.record && data.record.raw) {
                html += `
                    <h4 class="mt-15 mb-10">Record Details</h4>
                    <div class="json-display">
                        ${data.record.raw}
                    </div>`;
            }
            
            // Display recommendations if available
            if (data.recommendations && data.recommendations.length > 0) {
                html += `
                    <h4 class="mt-15 mb-10">Recommendations</h4>
                    <ul class="mb-15">`;
                    
                data.recommendations.forEach(rec => {
                    html += `<li>${rec}</li>`;
                });
                
                html += `</ul>`;
            }
        } else {
            html += `
                <div class="message warning">
                    <p><strong>No DMARC Record Found</strong></p>
                    <p>We recommend implementing DMARC to improve email security and deliverability. 
                    DMARC helps protect your domain from unauthorized use and provides visibility into email authentication.</p>
                </div>`;
        }
        
        // Add warnings if any
        if (data.warnings && data.warnings.length > 0) {
            html += `
                <h4 class="mt-15 mb-10">Warnings</h4>
                <ul class="mb-15">`;
                
            data.warnings.forEach(warning => {
                html += `<li class="text-muted">${warning}</li>`;
            });
            
            html += `</ul>`;
        }
        
        html += `</div>`;
        dmarcDetails.innerHTML = html;
    }
}

// Export for use in other modules
window.DmarcAnalyzer = DmarcAnalyzer;