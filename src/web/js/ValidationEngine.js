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
        this.animationElement = null; // New reference for our animation element
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
        
        // Basic client-side validation - check for @ and . characters
        if (email.trim() !== '') {
            if (email.includes('@') && email.includes('.')) {
                this.startValidation(email);
            } else {
                this.showError('Please enter a valid email address.');
            }
        } else {
            this.showError('Please enter an email address.');
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
        // Create or get the animation container
        let animContainer = document.getElementById('validationAnimation');
        if (!animContainer) {
            animContainer = document.createElement('div');
            animContainer.id = 'validationAnimation';
            animContainer.className = 'validation-animation';
            
            // Insert after the verify button instead of email input
            this.verifyButton.parentNode.insertBefore(animContainer, this.verifyButton.nextSibling);
        }
        
        // Show the animation container
        animContainer.style.display = 'block';
        
        // Create the text element and dots container
        animContainer.innerHTML = `
            <span class="validation-text">Validating please wait</span>
            <span class="dots">
                <span class="dot dot1">.</span>
                <span class="dot dot2">.</span>
                <span class="dot dot3">.</span>
            </span>
        `;
        
        // Hide the old progress bar if it exists
        if (this.progressBar) {
            this.progressBar.style.display = 'none';
        }
        
        // Return a promise that resolves when validation is complete
        return new Promise(resolve => {
            // Store the animation element so we can hide it later
            this.animationElement = animContainer;
            
            // Set a minimum display time to ensure animation is visible
            setTimeout(() => {
                resolve();
            }, 1500);
        });
    }

    /**
     * Hide validation progress
     */
    hideValidationProgress() {
        if (this.progressBar) {
            this.progressBar.style.display = 'none';
        }
        
        // Also hide our new animation
        if (this.animationElement) {
            this.animationElement.style.display = 'none';
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
        
        // Extract SMTP details - look for them at the root level of response or in details
        const smtpDetails = {
            smtp_result: response.smtp_result || (response.details && response.details.smtp_result) || false,
            smtp_banner: response.smtp_banner || (response.details && response.details.smtp_banner) || '',
            smtp_vrfy: response.smtp_vrfy || (response.details && response.details.smtp_vrfy) || false,
            supports_tls: response.smtp_supports_tls || (response.details && response.details.smtp_supports_tls) || false,
            supports_auth: response.smtp_supports_auth || (response.details && response.details.smtp_supports_auth) || false,
            smtp_flow_success: response.smtp_flow_success || (response.details && response.details.smtp_flow_success) || false,
            smtp_error_code: response.smtp_error_code || (response.details && response.details.smtp_error_code) || null,
            server_message: response.smtp_server_message || (response.details && response.details.smtp_server_message) || '',
            connection_success: response.connection_success || (response.details && response.details.connection_success) || false
        };
        
        // IMPORTANT: Make sure detailedResults is displayed BEFORE ResultsDisplay
        this.detailedResults.style.display = 'block';
        
        // Use ResultsDisplay to handle detailed results
        if (window.ResultsDisplay) {
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
        
        // Reset Show More button - both hide and reset its state
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
            // Reset button text in case it was toggled to "Show Less"
            showMoreButton.textContent = "Show More";
            // Remove any active/expanded classes
            showMoreButton.classList.remove('expanded');
        }
        
        // Hide expanded details
        const expandedDetails = document.getElementById('expandedDetails');
        if (expandedDetails) {
            expandedDetails.style.display = 'none';
        }
        
        // Reset any other expanded sections that might be controlled by the Show More button
        const traceSection = document.getElementById('traceSection');
        if (traceSection) {
            traceSection.style.display = 'none';
        }
        
        // Reset the button
        this.verifyButton.textContent = "Verify Email";
        
        // Set focus to the input field
        this.emailInput.focus();
    }
}

// Export for use in other modules
window.ValidationEngine = ValidationEngine;