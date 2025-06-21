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
        this.animationElement = null;
        this.progressContainer = null;
        this.listenersAttached = false;
    }

    /**
     * Initialize the validation engine
     */
    init() {
        console.log('Initializing ValidationEngine');
        
        this.verifyButton = document.getElementById('verifyButton');
        this.emailInput = document.getElementById('emailInput');
        this.resultDiv = document.getElementById('result');
        this.detailedResults = document.getElementById('detailedResults');
        this.progressContainer = document.getElementById('validationProgress');
        this.progressFill = document.getElementById('validation-progress-fill');
        this.percentText = document.getElementById('validation-percent');
        this.stepText = document.getElementById('validation-step');
        this.smtpResultsDiv = document.getElementById('smtpResults');

        console.log('- DOM elements found:');
        console.log('- verifyButton:', !!this.verifyButton);
        console.log('- emailInput:', !!this.emailInput);
        console.log('- resultDiv:', !!this.resultDiv);
        console.log('- detailedResults:', !!this.detailedResults);

        if (!this.verifyButton || !this.emailInput) {
            console.error('- ValidationEngine: Required DOM elements not found');
            console.error('- verifyButton missing:', !this.verifyButton);
            console.error('- emailInput missing:', !this.emailInput);
            return false;
        }

        console.log('Attaching event listeners');
        this.attachEventListeners();
        console.log('ValidationEngine initialized successfully');
        return true;
    }

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        if (this.listenersAttached) {
            console.log('Event listeners already attached, skipping');
            return;
        }

        console.log('Attaching event listeners to ValidationEngine');
        
        // Verify button click handler
        this.verifyButton.addEventListener('click', () => {
            console.log('Verify button click event triggered');
            this.handleVerifyClick();
        });
        
        // Enter key support for form submission
        this.emailInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                console.log('Enter key detected');
                this.handleKeyPress(e);
            }
        });
        
        this.listenersAttached = true;
        console.log('Event listeners attached');
    }

    /**
     * Handle verify button click
     */
    handleVerifyClick() {
        console.log('Verify button clicked');
        const email = this.emailInput.value;
        console.log('Email input value:', email);
        
        if (this.verifyButton.textContent === "New Validation") {
            console.log('Resetting validation form');
            this.resetValidationForm();
            return;
        }
        
        // Basic client-side validation - check for @ and . characters
        if (email.trim() !== '') {
            if (email.includes('@') && email.includes('.')) {
                console.log('Email format valid, starting validation');
                this.startValidation(email);
            } else {
                console.log('Invalid email format');
                this.showError('Please enter a valid email address.');
            }
        } else {
            console.log('Empty email field');
            this.showError('Please enter an email address.');
        }
    }

    /**
     * Handle key press events
     */
    handleKeyPress(e) {
        console.log('Key pressed:', e.key);
        if (e.key === 'Enter') {
            e.preventDefault();
            console.log('Enter key detected');
            
            if (!this.verifyButton.disabled && this.verifyButton.textContent !== "New Validation") {
                console.log('Calling handleVerifyClick from Enter key');
                this.handleVerifyClick();
            } else if (this.verifyButton.textContent === "New Validation") {
                console.log('Resetting from Enter key');
                this.resetValidationForm();
            } else {
                console.log('Button disabled or validation in progress');
            }
        }
    }

    /**
     * Start the email validation process
     */
    async startValidation(email) {
        console.log('Starting validation for:', email);
        
        if (this.isValidating) {
            console.log('Already validating, skipping');
            return;
        }
        
        this.isValidating = true;
        this.emailInput.disabled = true;
        this.verifyButton.disabled = true;
        
        console.log('UI locked for validation');
        
        // Clear previous results
        this.clearResults();
        
        try {
            // Show progress and start validation
            this.showValidationProgress();
            console.log('Progress shown, calling eel.verify_email');
            
            // Call the Python validation function
            const response = await eel.verify_email(email)();
            console.log("Validation response received:", response);
            
            // Process the response
            this.handleValidationResponse(response);
            
        } catch (error) {
            console.error('Validation error:', error);
            this.showError('An error occurred during validation. Please try again.');
        } finally {
            console.log('Unlocking UI');
            this.isValidating = false;
            this.hideValidationProgress();
            this.verifyButton.disabled = false;
        }
    }

    /**
     * Clear all previous results
     */
    clearResults() {
        // Clear result message
        this.resultDiv.innerHTML = "";
        this.resultDiv.className = '';
        
        // Hide detailed results
        this.detailedResults.style.display = 'none';
        
        // Hide show more button
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
        }
        
        // Hide expanded details
        const expandedDetails = document.getElementById('expandedDetails');
        if (expandedDetails) {
            expandedDetails.style.display = 'none';
        }
    }

    /**
     * Show validation progress with improved animation
     */
    showValidationProgress() {
        // Remove any existing animation
        if (this.animationElement) {
            this.animationElement.remove();
        }
        
        // Create new validation animation using CSS classes
        this.animationElement = document.createElement('div');
        this.animationElement.className = 'validation-animation mb-20';
        this.animationElement.innerHTML = `
            <div class="text-center">
                <span>Validating email</span>
                <div class="dots">
                    <span class="dot">.</span>
                    <span class="dot">.</span>
                    <span class="dot">.</span>
                </div>
            </div>
        `;
        
        // Insert after the input container
        const inputContainer = this.emailInput.closest('.email-input-container');
        if (inputContainer) {
            inputContainer.parentNode.insertBefore(this.animationElement, inputContainer.nextSibling);
        } else {
            // Fallback: insert after email input
            this.emailInput.parentNode.insertBefore(this.animationElement, this.emailInput.nextSibling);
        }
        
        // Show the progress container if it exists in HTML
        if (this.progressContainer) {
            this.progressContainer.style.display = 'block';
            
            // Hide the text labels
            if (this.percentText) {
                this.percentText.style.display = 'none';
            }
            if (this.stepText) {
                this.stepText.style.display = 'none';
            }
        }
    }

    /**
     * Update validation progress (if using progress bar)
     */
    updateProgress(percent, step) {
        if (this.progressFill) {
            this.progressFill.style.width = `${percent}%`;
        }
        if (this.percentText) {
            this.percentText.textContent = `${percent}%`;
        }
        if (this.stepText) {
            this.stepText.textContent = step;
        }
    }

    /**
     * Hide validation progress
     */
    hideValidationProgress() {
        // Hide progress container
        if (this.progressContainer) {
            this.progressContainer.style.display = 'none';
        }
        
        // Remove animation element
        if (this.animationElement) {
            this.animationElement.remove();
            this.animationElement = null;
        }
    }

    /**
     * Handle validation response from backend
     */
    handleValidationResponse(response) {
        // Create result message with proper CSS classes
        this.resultDiv.className = response.valid ? 'message success mb-20' : 'message error mb-20';
        
        // Create main result content
        const resultContent = document.createElement('div');
        resultContent.textContent = response.message;
        this.resultDiv.appendChild(resultContent);
        
        // Add error message if available
        if (!response.valid && response.details && response.details.error_message) {
            const errorDetail = document.createElement('div');
            errorDetail.className = 'mt-10 text-muted';
            errorDetail.textContent = response.details.error_message;
            this.resultDiv.appendChild(errorDetail);
        }
        
        // Add warning messages using new CSS classes
        this.addWarningMessages(response.details);
        
        // Show detailed results
        this.showDetailedResults(response);
        
        // Change button to "New Validation"
        this.verifyButton.textContent = "New Validation";
        this.verifyButton.className = 'btn btn-secondary';
    }

    /**
     * Add warning messages for blacklist/disposable emails
     */
    addWarningMessages(details) {
        if (!details) return;
        
        // Blacklist warning
        if (details.blacklist_info && details.blacklist_info.blacklisted) {
            const blacklistWarning = document.createElement('div');
            blacklistWarning.className = 'message warning mt-10';
            blacklistWarning.innerHTML = `
                <strong>⚠️ Domain Blacklisted:</strong> 
                ${details.blacklist_info.source || 'Unknown source'}
            `;
            this.resultDiv.appendChild(blacklistWarning);
        }
        
        // Disposable email warning
        if (details.is_disposable) {
            const disposableWarning = document.createElement('div');
            disposableWarning.className = 'message warning mt-10';
            disposableWarning.innerHTML = `
                <strong>⚠️ Disposable Email:</strong> 
                This appears to be a temporary email address
            `;
            this.resultDiv.appendChild(disposableWarning);
        }
    }

    /**
     * Show detailed results using new CSS structure
     */
    showDetailedResults(response) {
        // Make sure detailedResults is displayed
        this.detailedResults.style.display = 'block';
        
        // Use ResultsDisplay to handle detailed results
        if (window.ResultsDisplay && window.resultsDisplay) {
            window.resultsDisplay.displayResults(response.details);
        }
        
        // Show the "Show More" button if we have a trace ID
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton && response.details && response.details.trace_id) {
            showMoreButton.style.display = 'block';
            showMoreButton.className = 'btn btn-secondary';
        }
    }

    /**
     * Show error message with improved styling
     */
    showError(message) {
        this.resultDiv.innerHTML = '';
        this.resultDiv.className = 'message error mb-20';
        
        const errorContent = document.createElement('div');
        errorContent.innerHTML = `<strong>Error:</strong> ${message}`;
        this.resultDiv.appendChild(errorContent);
        
        this.detailedResults.style.display = 'none';
    }

    /**
     * Reset the validation form
     */
    resetValidationForm() {
        // Clear the input
        this.emailInput.value = '';
        this.emailInput.disabled = false;
        
        // Clear all results
        this.clearResults();
        
        // Clear SMTP results if they exist
        if (this.smtpResultsDiv) {
            this.smtpResultsDiv.innerHTML = '';
            this.smtpResultsDiv.style.display = 'none';
        }
        
        // Reset Show More button
        const showMoreButton = document.getElementById('showMoreButton');
        if (showMoreButton) {
            showMoreButton.style.display = 'none';
            showMoreButton.textContent = "Show More Details";
            showMoreButton.className = 'btn btn-secondary';
            showMoreButton.classList.remove('expanded');
        }
        
        // Reset any trace sections
        const traceSection = document.getElementById('traceSection');
        if (traceSection) {
            traceSection.style.display = 'none';
        }
        
        // Reset the button
        this.verifyButton.textContent = "Verify Email";
        this.verifyButton.className = 'btn';
        
        // Set focus to the input field
        this.emailInput.focus();
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
}

// Export for use in other modules
window.ValidationEngine = ValidationEngine;