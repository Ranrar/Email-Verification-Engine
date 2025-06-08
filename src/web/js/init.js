// ASCII logo
const asciiLogo = `
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░`;

document.getElementById('logo').textContent = asciiLogo;

// After setting the logo text content, add class to apply styling
const logoElement = document.getElementById('logo');
logoElement.textContent = asciiLogo;
logoElement.className = 'ascii-art';

// OS theme detection and application (consistent with main.js)
function detectOSTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Dispatch theme changed event for consistency
    document.dispatchEvent(new CustomEvent('themeChanged', {
        detail: { theme: theme }
    }));
}

// Check for saved theme or use OS preference
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    applyTheme(savedTheme);
} else {
    applyTheme(detectOSTheme());
}

// Listen for OS theme changes
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    // Only update if user hasn't set a manual preference
    if (!localStorage.getItem('theme')) {
        applyTheme(e.matches ? 'dark' : 'light');
    }
});

// Listen for initialization updates from Python
eel.expose(updateInitProgress);
function updateInitProgress(step, total, message, percent) {
    document.getElementById('current-step').textContent = message;
    document.getElementById('step-counter').textContent = `${step}/${total}`;
    document.getElementById('progress-fill').style.width = `${percent}%`;
}

// Listen for initialization completion
eel.expose(initializationComplete);
function initializationComplete() {
    // Redirect to main page after a short delay
    setTimeout(() => {
        window.location.href = 'main.html';
    }, 1500);
}

// Signal to Python that the page is loaded and ready
document.addEventListener('DOMContentLoaded', function() {
    // Set up the logo AFTER DOM is loaded
    const logoElement = document.getElementById('logo');
    if (logoElement) {
        logoElement.textContent = asciiLogo;
        logoElement.className = 'ascii-art';
    }
    
    // Make sure we apply the theme immediately when DOM content is loaded
    const currentTheme = localStorage.getItem('theme') || detectOSTheme();
    document.documentElement.setAttribute('data-theme', currentTheme);
    
    // Start initialization
    eel.start_initialization();
});