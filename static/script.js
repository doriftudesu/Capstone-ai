// This file contains general JavaScript for your web application.

// --- Removed: JavaScript for tab close logout ---
// The unload event listener has been removed as it was causing unintended logouts
// on internal navigation within the application.
// Session management for browser close is handled by Flask's SESSION_COOKIE_PERMANENT=False
// and long-term persistence by Flask-Login's "Remember Me" cookie.
// --- End Removed ---

// --- Sidebar toggle logic (assuming sidebar and logo elements exist in HTML) ---
// These elements are not in the provided HTML, but the JS functions are kept for completeness.
const sidebar = document.getElementById('sidebar');
const logo = document.getElementById('logo');

function toggleSidebar() {
    if (sidebar) { // Check if sidebar exists before toggling
        sidebar.classList.toggle('collapsed');
        if (logo) { // Check if logo exists
            if (sidebar.classList.contains('collapsed')) {
                logo.style.display = 'none';
            } else {
                logo.style.display = 'block';
            }
        }
    }
}

// --- Theme toggle with persistence ---
function toggleTheme() {
    const isLight = document.body.classList.toggle('light');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

// --- Load theme on page load ---
function loadTheme() {
    if (localStorage.getItem('theme') === 'light') {
        document.body.classList.add('light');
    }
}

// --- Navigation page loader (example for client-side navigation if needed) ---
function loadPage(page) {
    if (page === 'dashboard') {
        window.location.href = '/';
    } else {
        window.location.href = `/${page}`;
    }
}

// --- Drag and drop upload support (assuming dropzone and fileInput elements exist in HTML) ---
const dz = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');

if (dz && fileInput) { // Ensure elements exist before adding listeners
    dz.addEventListener('click', () => fileInput.click());

    dz.addEventListener('dragover', (e) => {
        e.preventDefault();
        dz.classList.add('hover');
    });

    dz.addEventListener('dragleave', () => {
        dz.classList.remove('hover');
    });

    dz.addEventListener('drop', (e) => {
        e.preventDefault();
        dz.classList.remove('hover');
        fileInput.files = e.dataTransfer.files;
        // Assuming the file input is part of a form with id 'uploadForm'
        const uploadForm = document.getElementById('uploadForm');
        if (uploadForm) {
            uploadForm.submit();
        } else {
            console.error("Upload form with ID 'uploadForm' not found.");
        }
    });
}

// --- Socket.IO Notifications ---
function setupSocket() {
    const socket = io();

    socket.on('connect', () => {
        console.log('Connected to server via Socket.IO');
    });

    socket.on('file_uploaded', (data) => {
        const notificationList = document.getElementById('notification-list');
        if (notificationList) {
            const listItem = document.createElement('li');
            listItem.textContent = `New file uploaded: ${data.filename} by ${data.user}`;
            notificationList.appendChild(listItem);
        } else {
            console.warn("Notification list (id='notification-list') not found.");
        }
    });
}

// --- Chart.js Data Fetching and Rendering ---
function setupCharts() {
    // Only attempt to fetch and render chart if the canvas element exists
    const myChartCanvas = document.getElementById('myChart');
    if (myChartCanvas) {
        fetch('/chart_data')
            .then(response => response.json())
            .then(data => {
                const ctx = myChartCanvas.getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Sample Data',
                            data: data.values,
                            backgroundColor: 'rgba(75, 192, 192, 0.2)',
                            borderColor: 'rgba(75, 192, 192, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            })
            .catch(error => console.error('Error fetching chart data:', error));
    } else {
        console.log("Chart canvas (id='myChart') not found, skipping chart setup.");
    }
}

// --- On page load: Initialize all necessary functionalities ---
window.onload = () => {
    loadTheme(); // Load saved theme settings
    setupSocket(); // Initialize Socket.IO for real-time notifications
    setupCharts(); // Initialize Chart.js for data visualization
};
