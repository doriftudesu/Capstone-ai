// This file contains general JavaScript for your web application.

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

// --- NEW: Book Search Functionality ---
async function searchBooks() {
    const query = document.getElementById('bookSearchQuery').value;
    const searchResultsDiv = document.getElementById('searchResults');
    const searchStatus = document.getElementById('searchStatus');

    if (!query) {
        searchResultsDiv.innerHTML = '';
        searchStatus.textContent = "Please enter a search query.";
        return;
    }

    searchStatus.textContent = "Searching...";
    searchResultsDiv.innerHTML = ''; // Clear previous results

    try {
        const response = await fetch(`/search_books?query=${encodeURIComponent(query)}`);
        const books = await response.json();

        if (books.error) {
            searchStatus.textContent = `Error: ${books.error}`;
            return;
        }

        if (books.length === 0) {
            searchStatus.textContent = "No books found. Try a different query.";
            return;
        }

        searchStatus.textContent = ""; // Clear status message
        books.forEach(book => {
            const bookCard = document.createElement('div');
            bookCard.classList.add('book-card');
            bookCard.innerHTML = `
                <img src="${book.cover_image_url || 'https://placehold.co/128x192/e0e0e0/333?text=No+Cover'}" alt="Cover of ${book.title}" class="book-cover" onerror="this.onerror=null;this.src='https://placehold.co/128x192/e0e0e0/333?text=No+Cover';">
                <h4>${book.title}</h4>
                <p>by ${book.author || 'Unknown'}</p>
                ${book.isbn ? `<p class="book-isbn">ISBN: ${book.isbn}</p>` : ''}
                <button class="add-from-search-button"
                        data-title="${book.title}"
                        data-author="${book.author || ''}"
                        data-isbn="${book.isbn || ''}"
                        data-cover-image-url="${book.cover_image_url || ''}">Add to Library</button>
            `;
            searchResultsDiv.appendChild(bookCard);
        });

        // Add event listeners to the new "Add to Library" buttons
        document.querySelectorAll('.add-from-search-button').forEach(button => {
            button.addEventListener('click', async (event) => {
                const btn = event.target;
                const title = btn.dataset.title;
                const author = btn.dataset.author;
                const isbn = btn.dataset.isbn;
                const coverImage = btn.dataset.coverImageUrl;

                // Send data to the Flask add_book endpoint
                const formData = new FormData();
                formData.append('title', title);
                formData.append('author', author);
                formData.append('isbn', isbn);
                formData.append('cover_image_url', coverImage);

                try {
                    const response = await fetch('/add_book', {
                        method: 'POST',
                        body: formData
                    });
                    const responseText = await response.text(); // Get raw text to check for redirect
                    
                    // Flask's redirect will return an HTML response with a meta refresh or script redirect
                    // We need to check if it's a redirect and follow it
                    if (response.redirected) {
                        window.location.href = response.url; // Follow the redirect
                    } else {
                        // If not redirected, something went wrong or it's a JSON error
                        const result = JSON.parse(responseText); // Try parsing as JSON
                        if (result.error) {
                            alert(`Error adding book: ${result.error}`); // Use alert for direct error feedback
                        } else {
                            // This case should ideally not happen if Flask always redirects on success/failure
                            alert("Book added successfully (but no redirect detected). Please refresh.");
                            console.log(result);
                        }
                    }
                } catch (error) {
                    console.error('Error adding book from search:', error);
                    alert('An error occurred while adding the book.');
                }
            });
        });

    } catch (error) {
        console.error('Error searching books:', error);
        searchStatus.textContent = "Failed to search for books. Please try again.";
    }
}


// --- On page load: Initialize all necessary functionalities ---
window.onload = () => {
    loadTheme(); // Load saved theme settings
    setupSocket(); // Initialize Socket.IO for real-time notifications
    setupCharts(); // Initialize Chart.js for data visualization
};
