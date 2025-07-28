document.addEventListener("DOMContentLoaded", function() {
    // Get form element
    const urlCheckForm = document.getElementById("urlCheckForm");
    
    // Add event listener to form submission
    if (urlCheckForm) {
        urlCheckForm.addEventListener("submit", function(e) {
            e.preventDefault();
            checkUrl();
        });
    }
});

/**
 * Generate a simple device fingerprint for caching purposes
 * This helps optimize API costs by tracking device-specific request history
 */
function generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
    
    const fingerprint = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        canvas.toDataURL()
    ].join('|');
    
    // Create a simple hash
    let hash = 0;
    for (let i = 0; i < fingerprint.length; i++) {
        const char = fingerprint.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    
    return Math.abs(hash).toString(36);
}

/**
 * Get or create device ID for request tracking
 */
function getDeviceId() {
    let deviceId = localStorage.getItem('device_id');
    if (!deviceId) {
        deviceId = generateDeviceFingerprint();
        localStorage.setItem('device_id', deviceId);
    }
    return deviceId;
}

/**
 * Check URL safety by submitting form to backend
 */
function checkUrl() {
    // Get form and UI elements
    const urlInput = document.getElementById("url");
    const loadingSpinner = document.getElementById("loadingSpinner");
    const buttonText = document.getElementById("buttonText");
    const checkButton = document.getElementById("checkButton");
    const resultsCard = document.getElementById("resultsCard");
    const errorAlert = document.getElementById("errorAlert");
    
    // Validate URL
    const url = urlInput.value.trim();
    if (!url) {
        showError("Please enter a URL");
        return;
    }
    
    // Show loading state
    loadingSpinner.classList.remove("d-none");
    buttonText.textContent = "Checking...";
    checkButton.disabled = true;
    resultsCard.classList.add("d-none");
    errorAlert.classList.add("d-none");
    
    // Create form data for submission
    const formData = new FormData();
    formData.append("url", url);
    formData.append("device_id", getDeviceId()); // Add device tracking
    
    // Send request to backend
    fetch("/check", {
        method: "POST",
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.message || "Error checking URL");
            });
        }
        return response.json();
    })
    .then(data => {
        displayResults(data);
    })
    .catch(error => {
        showError(error.message || "Error checking URL");
    })
    .finally(() => {
        // Hide loading state
        loadingSpinner.classList.add("d-none");
        buttonText.textContent = "Check URL Safety";
        checkButton.disabled = false;
    });
}

/**
 * Display results in the UI
 * @param {Object} data - Results from the API
 */
function displayResults(data) {
    const resultsCard = document.getElementById("resultsCard");
    const resultTitle = document.getElementById("resultTitle");
    const resultMessage = document.getElementById("resultMessage");
    const resultDetails = document.getElementById("resultDetails");
    const recommendationAlert = document.getElementById("recommendationAlert");
    const statusIcon = document.getElementById("statusIcon");
    const alertIcon = document.getElementById("alertIcon");
    const alertTitle = document.getElementById("alertTitle");
    
    // Show results card
    resultsCard.classList.remove("d-none");
    
    // Use the UI status if provided, otherwise fall back to the original status
    const status = data.ui_status || data.status;
    
    // Update status icon and styling based on status
    if (status === "safe" || status === "likely_safe") {
        // Safe URL
        statusIcon.innerHTML = `
            <div class="d-inline-flex align-items-center justify-content-center mb-2" style="width: 80px; height: 80px; background: linear-gradient(135deg, #10b981, #059669); border-radius: 20px;">
                <i class="fa-solid fa-shield-check text-white" style="font-size: 2rem;"></i>
            </div>
        `;
        resultTitle.textContent = "URL is Safe";
        resultTitle.className = "card-title text-center text-success";
        recommendationAlert.className = "alert alert-success";
        alertIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
        alertTitle.textContent = "Safe to Visit";
    } else if (status === "unsafe") {
        // Unsafe URL
        statusIcon.innerHTML = `
            <div class="d-inline-flex align-items-center justify-content-center mb-2" style="width: 80px; height: 80px; background: linear-gradient(135deg, #ef4444, #dc2626); border-radius: 20px;">
                <i class="fa-solid fa-shield-exclamation text-white" style="font-size: 2rem;"></i>
            </div>
        `;
        resultTitle.textContent = "URL is Unsafe";
        resultTitle.className = "card-title text-center text-danger";
        recommendationAlert.className = "alert alert-danger";
        alertIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
        alertTitle.textContent = "Security Threat Detected";
    } else if (status === "caution" || status === "unknown") {
        // Caution - potentially suspicious URL
        statusIcon.innerHTML = `
            <div class="d-inline-flex align-items-center justify-content-center mb-2" style="width: 80px; height: 80px; background: linear-gradient(135deg, #f59e0b, #d97706); border-radius: 20px;">
                <i class="fa-solid fa-shield-halved text-white" style="font-size: 2rem;"></i>
            </div>
        `;
        resultTitle.textContent = "Use Caution";
        resultTitle.className = "card-title text-center text-warning";
        recommendationAlert.className = "alert alert-warning";
        alertIcon.innerHTML = '<i class="fa-solid fa-exclamation-circle"></i>';
        alertTitle.textContent = "Proceed with Caution";
    } else if (status === "error") {
        // Error checking URL
        statusIcon.innerHTML = `
            <div class="d-inline-flex align-items-center justify-content-center mb-2" style="width: 80px; height: 80px; background: linear-gradient(135deg, #6b7280, #4b5563); border-radius: 20px;">
                <i class="fa-solid fa-question text-white" style="font-size: 2rem;"></i>
            </div>
        `;
        resultTitle.textContent = "Safety Check Incomplete";
        resultTitle.className = "card-title text-center text-secondary";
        recommendationAlert.className = "alert alert-secondary";
        alertIcon.innerHTML = '<i class="fa-solid fa-info-circle"></i>';
        alertTitle.textContent = "Analysis Incomplete";
    } else {
        // Default for any other status
        statusIcon.innerHTML = `
            <div class="d-inline-flex align-items-center justify-content-center mb-2" style="width: 80px; height: 80px; background: linear-gradient(135deg, #f59e0b, #d97706); border-radius: 20px;">
                <i class="fa-solid fa-shield-halved text-white" style="font-size: 2rem;"></i>
            </div>
        `;
        resultTitle.textContent = "URL Check Result";
        resultTitle.className = "card-title text-center text-warning";
        recommendationAlert.className = "alert alert-warning";
        alertIcon.innerHTML = '<i class="fa-solid fa-question-circle"></i>';
        alertTitle.textContent = "Analysis Result";
    }
    
    // Add source information if using fallback
    let detailsText = data.details || "";
    if (detailsText.includes("API verification unavailable")) {
        detailsText += " (using basic URL analysis)";
    }
    
    // Update other result elements
    resultMessage.textContent = data.message || "";
    resultDetails.textContent = detailsText;
    
    // Update recommendation text
    const recommendationText = data.recommendation || "";
    if (recommendationText) {
        resultDetails.textContent = detailsText ? `${detailsText} ${recommendationText}` : recommendationText;
    }
}

/**
 * Show error message in the UI
 * @param {string} message - Error message to display
 */
function showError(message) {
    const errorAlert = document.getElementById("errorAlert");
    const errorMessage = document.getElementById("errorMessage");
    
    errorMessage.textContent = message;
    errorAlert.classList.remove("d-none");
}

/**
 * Dismiss the error alert
 */
function dismissError() {
    const errorAlert = document.getElementById("errorAlert");
    errorAlert.classList.add("d-none");
}

/**
 * Reset the form and hide results
 */
function resetForm() {
    const urlInput = document.getElementById("url");
    const resultsCard = document.getElementById("resultsCard");
    const errorAlert = document.getElementById("errorAlert");
    
    urlInput.value = "";
    resultsCard.classList.add("d-none");
    errorAlert.classList.add("d-none");
    urlInput.focus();
}
