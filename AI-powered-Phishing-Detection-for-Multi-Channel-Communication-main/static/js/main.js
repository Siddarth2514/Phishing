// Main JavaScript for AI-Powered Phishing Detection System

// Global variables
let currentTheme = 'light';
let notificationPermission = false;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    checkNotificationPermission();
    setupGlobalEventListeners();
});

function initializeApp() {
    // Update last update time in footer
    updateLastUpdateTime();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Setup auto-refresh for dashboard
    if (window.location.pathname === '/') {
        setupDashboardRefresh();
    }
    
    // Setup form validation
    setupFormValidation();
    
    console.log('Phishing Detection System initialized');
}

function updateLastUpdateTime() {
    const lastUpdateElement = document.getElementById('last-update');
    if (lastUpdateElement) {
        const now = new Date();
        lastUpdateElement.textContent = now.toLocaleString();
    }
}

function initializeTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

function setupDashboardRefresh() {
    // Auto-refresh dashboard every 30 seconds
    setInterval(function() {
        refreshDashboardStats();
    }, 30000);
}

function setupFormValidation() {
    // Add custom validation to forms
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

function setupGlobalEventListeners() {
    // Global keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+/ for help (if implemented)
        if (e.ctrlKey && e.key === '/') {
            e.preventDefault();
            showHelpModal();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
    
    // Handle network status
    window.addEventListener('online', function() {
        showNetworkStatus('online');
    });
    
    window.addEventListener('offline', function() {
        showNetworkStatus('offline');
    });
}

// Utility Functions
function showLoadingSpinner(element) {
    if (element) {
        element.innerHTML = '<span class="loading-spinner"></span> Loading...';
        element.disabled = true;
    }
}

function hideLoadingSpinner(element, originalText) {
    if (element) {
        element.innerHTML = originalText;
        element.disabled = false;
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                        data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 5000 });
    toast.show();
    
    // Remove toast element after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '1055';
    document.body.appendChild(container);
    return container;
}

function showNetworkStatus(status) {
    const message = status === 'online' ? 'Connection restored' : 'Connection lost';
    const type = status === 'online' ? 'success' : 'warning';
    showToast(message, type);
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) {
        return 'just now';
    } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
}

// API Helper Functions
async function apiCall(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const finalOptions = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, finalOptions);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('API call failed:', error);
        showToast('Network error: ' + error.message, 'danger');
        throw error;
    }
}

async function refreshDashboardStats() {
    try {
        const data = await apiCall('/api/stats');
        if (data.success) {
            updateDashboardElements(data.stats);
        }
    } catch (error) {
        console.error('Failed to refresh dashboard stats:', error);
    }
}

function updateDashboardElements(stats) {
    // Update stat cards if they exist
    const elements = {
        'totalAnalyzed': stats.total_analyzed,
        'phishingDetected': stats.phishing_detected,
        'detectionRate': stats.detection_rate.toFixed(1) + '%',
        'analysesToday': stats.analyses_today || 0
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });
}

// Analysis Functions
function displayAnalysisResult(result, containerId = 'analysisResult') {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const isPhishing = result.is_phishing;
    const riskLevel = result.risk_level || 'UNKNOWN';
    const confidence = (result.confidence || 0) * 100;
    
    const alertClass = isPhishing ? 'alert-danger' : 'alert-success';
    const badgeClass = isPhishing ? 'bg-danger' : 'bg-success';
    const badgeText = isPhishing ? 'PHISHING DETECTED' : 'SAFE MESSAGE';
    
    let threatsHtml = '';
    if (result.threats_detected && result.threats_detected.length > 0) {
        threatsHtml = `
            <hr>
            <h6>Threats Detected:</h6>
            <ul class="mb-0">
                ${result.threats_detected.map(threat => `<li>${threat}</li>`).join('')}
            </ul>
        `;
    }
    
    let urlsHtml = '';
    if (result.urls && result.urls.length > 0) {
        urlsHtml = `
            <hr>
            <h6>URLs Found:</h6>
            <ul class="mb-0">
                ${result.urls.map(url => `<li><code>${url}</code></li>`).join('')}
            </ul>
        `;
    }
    
    container.innerHTML = `
        <div class="alert ${alertClass} fade-in" role="alert">
            <h5 class="alert-heading">
                <span class="badge ${badgeClass} fs-6">${badgeText}</span>
            </h5>
            <hr>
            <div class="row">
                <div class="col-md-3">
                    <strong>Risk Level:</strong><br>
                    <span class="risk-${riskLevel.toLowerCase()}">${riskLevel}</span>
                </div>
                <div class="col-md-3">
                    <strong>Confidence:</strong><br>
                    ${confidence.toFixed(1)}%
                </div>
                <div class="col-md-3">
                    <strong>Risk Score:</strong><br>
                    ${result.risk_score || 0}/100
                </div>
                <div class="col-md-3">
                    <strong>Channel:</strong><br>
                    ${(result.channel || 'Unknown').toUpperCase()}
                </div>
            </div>
            ${threatsHtml}
            ${urlsHtml}
        </div>
    `;
    
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Modal Functions
function showHelpModal() {
    // Implementation for help modal
    showToast('Help modal would be implemented here', 'info');
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal.show');
    modals.forEach(modal => {
        const bsModal = bootstrap.Modal.getInstance(modal);
        if (bsModal) {
            bsModal.hide();
        }
    });
}

// Notification Functions
function checkNotificationPermission() {
    if ('Notification' in window) {
        if (Notification.permission === 'granted') {
            notificationPermission = true;
        } else if (Notification.permission !== 'denied') {
            Notification.requestPermission().then(permission => {
                notificationPermission = permission === 'granted';
            });
        }
    }
}

function showDesktopNotification(title, message, type = 'info') {
    if (!notificationPermission) return;
    
    const icon = '/static/favicon.ico'; // Add favicon if available
    const notification = new Notification(title, {
        body: message,
        icon: icon,
        tag: 'phishing-detection'
    });
    
    setTimeout(() => notification.close(), 5000);
}

// Export functions for global use
window.PhishingDetection = {
    showToast,
    showLoadingSpinner,
    hideLoadingSpinner,
    displayAnalysisResult,
    apiCall,
    formatDateTime,
    formatTimeAgo,
    showDesktopNotification
};

// Real-time updates (if WebSocket is implemented)
function initializeWebSocket() {
    // WebSocket implementation would go here for real-time updates
    console.log('WebSocket initialization placeholder');
}

// Theme Management
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('theme', currentTheme);
}

function loadSavedTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        currentTheme = savedTheme;
        document.documentElement.setAttribute('data-theme', currentTheme);
    }
}

// Load saved theme on page load
loadSavedTheme();

// Performance monitoring
function trackPageLoad() {
    window.addEventListener('load', function() {
        const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
        console.log(`Page loaded in ${loadTime}ms`);
    });
}

trackPageLoad();