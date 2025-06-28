// This file contains general JavaScript for your web application.

// --- JavaScript for tab close logout ---
// This event listener attempts to log out the user when the page is unloaded (e.g., tab closed, navigated away).
// It's a best-effort approach as browsers might not always send the request reliably in all scenarios (like crashes).
window.addEventListener('unload', function(event) {
    // Check if the browser supports navigator.sendBeacon, which is preferred for non-blocking requests on unload.
    if (navigator.sendBeacon) {
        // Use sendBeacon to send a POST request to the logout endpoint.
        // This is a "fire-and-forget" request that the browser tries to send in the background.
        // We use a direct path "/logout" as this static file doesn't process Jinja2 like templates.
        navigator.sendBeacon("/logout");
        console.log("Logout beacon sent."); // Log to console for debugging purposes
    } else {
        // Fallback for older browsers that do not support sendBeacon.
        // A synchronous XMLHttpRequest is used, which will block the page unload.
        // While effective, it can cause a slight delay in page closure.
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "/logout", false); // 'false' makes the request synchronous
        xhr.send();
        console.log("Synchronous XHR logout sent (fallback)."); // Log to console for debugging
    }
});
// --- End JavaScript for tab close logout ---

// --- Sidebar toggle logic ---
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

// --- Navigation page loader ---
function loadPage(page) {
    if (page === 'dashboard') {
        window.location.href = '/';
    } else {
        window.location.href = `/${page}`;
    }
}

// --- Drag and drop upload support ---
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
            listItem.textContent = `New file uploaded: ${data.filename}`;
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

