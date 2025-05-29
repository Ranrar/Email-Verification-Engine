/**
 * Email Validation Engine
 * Handles email validation form interactions, progress tracking, and API communication
 */

class ValidationEngine {
    constructor() {
        this.isValidating = false;
        this.verifyButton = null;
        this.emailInput = null;
        this.resultDiv = null;
        this.detailedResults = null;
        this.progressBar = null;
        this.progressFill = null;
        this.percentText = null;
        this.stepText = null;
        
        this.validationSteps = [
            "Checking email format...",
            "Validating domain...",
            "Checking MX records...",
            "Looking for disposable patterns...",
            "Performing SMTP validation...",
            "Calculating confidence score..."
        ];
    }

    /**
     * Initialize the validation engine
     */
    init() {
        this.verifyButton = document.getElementById('verifyButton');
        this.emailInput = document.getElementById('emailInput');
        this.resultDiv = document.getElementById('result');
        this.detailedResults = document.getElementById('detailedResults');
        this.progressBar = document.getElementById('validationProgress');
        this.progressFill = document.getElementById('validation-progress-fill');
        this.percentText = document.getElementById('validation-percent');
        this.stepText = document.getElementById('validation-step');
        this.smtpResultsDiv = document.getElementById('smtpResults');

        if (!this.verifyButton || !this.emailInput) {
            console.error('ValidationEngine: Required DOM elements not found');
            return false;
        }

        this.attachEventListeners();
        return true;
    }

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        // Verify button click handler
        this.verifyButton.addEventListener('click', () => this.handleVerifyClick());
        
        // Enter key support for form submission
        this.emailInput.addEventListener('keypress', (e) => this.handleKeyPress(e));
    }

    /**
     * Handle verify button click
     */
    handleVerifyClick() {
        const email = this.emailInput.value;
        
        if (this.verifyButton.textContent === "New Validation") {
            this.resetValidationForm();
            return;
        }
        
        if (this.validateEmailFormat(email)) {
            this.startValidation(email);
        } else {
            this.showError('Please enter a valid email address.');
        }
    }

    /**
     * Handle key press events
     */
    handleKeyPress(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            
            if (!this.verifyButton.disabled && this.verifyButton.textContent !== "New Validation") {
                this.handleVerifyClick();
            } else if (this.verifyButton.textContent === "New Validation") {
                this.resetValidationForm();
            }
        }
    }

    /**
     * Start the email validation process
     */
    async startValidation(email) {
        if (this.isValidating) return;
        
        this.isValidating = true;
        this.emailInput.disabled = true;
        this.verifyButton.disabled = true;
        
        // Clear previous results
        this.resultDiv.innerText = "";
        this.resultDiv.className = '';
        this.detailedResults.style.display = 'none';
        
        // Hide show more button
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
        }
        
        try {
            // Show progress and start validation
            await this.showValidationProgress();
            
            // Call the Python validation function
            const response = await eel.verify_email(email)();
            console.log("Validation response:", response);  // Debug output
            
            // Process the response
            this.handleValidationResponse(response);
            
        } catch (error) {
            console.error('Validation error:', error);
            this.showError('An error occurred during validation. Please try again.');
        } finally {
            this.isValidating = false;
            this.hideValidationProgress();
            this.verifyButton.disabled = false;
        }
    }

    /**
     * Show validation progress animation
     */
    async showValidationProgress() {
        if (!this.progressBar) return;
        
        this.progressBar.style.display = 'block';
        
        const stepDuration = 400; // milliseconds per step
        const intervalTime = 50;
        let progress = 0;
        let currentStep = 0;
        
        if (this.stepText) {
            this.stepText.textContent = this.validationSteps[0];
        }
        
        return new Promise((resolve) => {
            const progressInterval = setInterval(() => {
                const expectedProgress = Math.min(100, Math.floor((progress / (this.validationSteps.length * stepDuration)) * 100));
                
                // Update visual elements
                if (this.progressFill) {
                    this.progressFill.style.width = `${expectedProgress}%`;
                }
                if (this.percentText) {
                    this.percentText.textContent = `${expectedProgress}%`;
                }
                
                // Move to next step if needed
                if (progress > 0 && progress % stepDuration === 0 && currentStep < this.validationSteps.length - 1) {
                    currentStep++;
                    if (this.stepText) {
                        this.stepText.textContent = this.validationSteps[currentStep];
                    }
                }
                
                progress += intervalTime;
                
                // Complete when reaching 100%
                if (expectedProgress >= 100) {
                    clearInterval(progressInterval);
                    resolve();
                }
            }, intervalTime);
        });
    }

    /**
     * Hide validation progress
     */
    hideValidationProgress() {
        if (this.progressBar) {
            this.progressBar.style.display = 'none';
        }
    }

    /**
     * Handle validation response from backend
     */
    handleValidationResponse(response) {
        // Set the basic result message
        this.resultDiv.innerText = response.message;
        this.resultDiv.className = response.valid ? 'message success' : 'message error';
        
        // Add error message if available
        if (!response.valid && response.details && response.details.error_message) {
            this.resultDiv.innerText += "\n" + response.details.error_message;
        }
        
        // Extract SMTP details if available
        const smtpDetails = response.details.smtp_details || {};
        
        // Display SMTP results if the div exists
        if (this.smtpResultsDiv) {
            // Clear previous SMTP results
            this.smtpResultsDiv.innerHTML = '';
            
            // Only show the SMTP results section if we have details to display
            if (Object.keys(smtpDetails).length > 0) {
                this.smtpResultsDiv.style.display = 'block';
                
                // Create and append SMTP results
                const smtpItems = [
                    { label: 'SMTP Connection:', value: smtpDetails.connection_success ? '✓ Connected' : '✗ Failed', 
                      class: smtpDetails.connection_success ? 'success' : 'error' },
                    { label: 'Server Response:', value: smtpDetails.smtp_flow_success ? '✓ Accepted' : '✗ Rejected', 
                      class: smtpDetails.smtp_flow_success ? 'success' : 'error' },
                    { label: 'SMTP Code:', value: smtpDetails.smtp_error_code || 'N/A', 
                      class: (smtpDetails.smtp_error_code && smtpDetails.smtp_error_code >= 200 && smtpDetails.smtp_error_code < 300) ? 'success' : 
                             (smtpDetails.smtp_error_code && smtpDetails.smtp_error_code >= 500) ? 'error' : '' }
                ];
                
                // Create SMTP details list
                const smtpList = document.createElement('ul');
                smtpList.className = 'smtp-results-list';
                
                smtpItems.forEach(item => {
                    const li = document.createElement('li');
                    
                    const label = document.createElement('span');
                    label.className = 'smtp-label';
                    label.textContent = item.label;
                    li.appendChild(label);
                    
                    const value = document.createElement('span');
                    value.className = `smtp-value ${item.class}`;
                    value.textContent = item.value;
                    li.appendChild(value);
                    
                    smtpList.appendChild(li);
                });
                
                this.smtpResultsDiv.appendChild(smtpList);
                
                // Add server message if available
                if (smtpDetails.server_message) {
                    const serverMessage = document.createElement('div');
                    serverMessage.className = 'smtp-server-message';
                    serverMessage.innerHTML = `<strong>Server Message:</strong> <span>${smtpDetails.server_message.replace(/\n/g, '<br>')}</span>`;
                    this.smtpResultsDiv.appendChild(serverMessage);
                }
                
                // Remove references to static SMTP result items
                // No longer needed as we removed these elements from the HTML
            } else {
                this.smtpResultsDiv.style.display = 'none';
            }
        }
        
        // Use ResultsDisplay to handle detailed results
        if (window.ResultsDisplay) {
            // Change from using window.ResultsDisplay directly to using the instance
            window.resultsDisplay.displayResults(response.details);
        }
        
        // Show detailed results container
        this.detailedResults.style.display = 'block';
        
        // Show the "Show More" button if we have a trace ID
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton && response.details.trace_id) {
            showMoreButton.style.display = 'block';
        }
        
        // Change button to "New Validation"
        this.verifyButton.textContent = "New Validation";
        
        // Add this code to show blacklist/disposable warnings
        if (response.details && response.details.blacklist_info && response.details.blacklist_info.blacklisted) {
             const blacklistWarning = document.createElement('div');
             blacklistWarning.className = 'blacklist-warning';
             blacklistWarning.textContent = '⚠️ Domain is blacklisted: ' + 
                 (response.details.blacklist_info.source || 'Unknown source');
             this.resultDiv.appendChild(blacklistWarning);
         }
         
        if (response.details && response.details.is_disposable) {
             const disposableWarning = document.createElement('div');
             disposableWarning.className = 'disposable-warning';
             disposableWarning.textContent = '⚠️ Disposable email address detected';
             this.resultDiv.appendChild(disposableWarning);
         }
    }

    /**
     * Show error message
     */
    showError(message) {
        this.resultDiv.innerText = message;
        this.resultDiv.className = 'message error';
        this.detailedResults.style.display = 'none';
    }

    /**
     * Reset the validation form
     */
    resetValidationForm() {
        // Clear the input
        this.emailInput.value = '';
        this.emailInput.disabled = false;
        
        // Clear the results
        this.resultDiv.innerText = '';
        this.resultDiv.className = '';
        this.detailedResults.style.display = 'none';
        
        // Clear SMTP results if they exist
        if (this.smtpResultsDiv) {
            this.smtpResultsDiv.innerHTML = '';
            this.smtpResultsDiv.style.display = 'none';
        }
        
        // Remove references to static SMTP result items
        // No longer needed as we removed these elements from the HTML
        
        // Hide buttons and expanded details
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
        }
        
        const expandedDetails = document.getElementById('expandedDetails');
        if (expandedDetails) {
            expandedDetails.style.display = 'none';
        }
        
        // Reset the button
        this.verifyButton.textContent = "Verify Email";
        
        // Set focus to the input field
        this.emailInput.focus();
    }

    /**
     * Validate email format
     */
    validateEmailFormat(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(String(email).toLowerCase());
    }
}

// Export for use in other modules
window.ValidationEngine = ValidationEngine;