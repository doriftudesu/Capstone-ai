// This file contains general JavaScript for your web application.

// --- Theme toggle with persistence ---
function toggleTheme() {
    // The user's provided code uses a 'light' class, while my previous code used a 'dark' class.
    // I'll update it to be consistent with the user's provided code.
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
// Ensure you have the Socket.IO client library included in your HTML:
// <script src="/socket.io/socket.io.js"></script>
function setupSocket() {
    if (typeof io !== 'undefined') {
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
    } else {
        console.warn("Socket.IO client library not found. Skipping socket setup.");
    }
}

// --- Chart.js Data Fetching and Rendering ---
// Ensure you have the Chart.js library included in your HTML:
// <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
function setupCharts() {
    const myChartCanvas = document.getElementById('myChart');
    if (myChartCanvas && typeof Chart !== 'undefined') {
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
        console.log("Chart canvas (id='myChart') or Chart.js library not found, skipping chart setup.");
    }
}

// -------------------------------------------------------------------------------------------------
// --- Book Search and OCR Functionality from Previous Conversation (Re-integrated) ---
// -------------------------------------------------------------------------------------------------

/**
 * Creates and returns an HTML element for a book card.
 * @param {object} book The book data object.
 * @returns {HTMLDivElement} The book card element.
 */
function createBookCard(book) {
    const bookCard = document.createElement('div');
    bookCard.className = 'book-card';
    bookCard.innerHTML = `
        <img src="${book.cover_image_url || 'https://placehold.co/128x192/e0e0e0/333?text=No+Cover'}"
            alt="Cover of ${book.title}"
            class="book-cover"
            onerror="this.onerror=null;this.src='https://placehold.co/128x192/e0e0e0/333?text=No+Cover';"
        >
        <h4>${book.title}</h4>
        <p>by ${book.author || 'Unknown'}</p>
        <p class="book-isbn">ISBN: ${book.isbn || 'N/A'}</p>
        <button class="add-book-button bg-indigo-500 text-white font-semibold py-2 px-4 rounded-lg mt-4 hover:bg-indigo-600 transition-colors" data-book='${JSON.stringify(book)}'>Add to Library</button>
    `;
    return bookCard;
}

/**
 * Fetches book data from the server based on a text query and displays the results.
 * @param {string} query The search query string.
 */
async function performBookSearch(query) {
    const bookCardsContainer = document.getElementById('bookCardsContainer');
    const searchStatus = document.getElementById('searchStatus');
    const searchButton = document.getElementById('searchButton');
    
    bookCardsContainer.innerHTML = '';
    searchStatus.textContent = 'Searching for books...';
    // Disable search button to prevent multiple requests
    if (searchButton) searchButton.disabled = true;
    
    try {
        const response = await fetch(`/search_books?query=${encodeURIComponent(query)}`);
        
        // --- MODIFIED CODE START ---
        if (!response.ok) {
            // If the response is not successful, it's likely an HTML error page.
            // We should not try to parse it as JSON.
            const errorText = await response.text();
            console.error('Server responded with an error:', response.status, response.statusText);
            console.error('Server response content:', errorText);
            searchStatus.textContent = `Error: Server responded with status ${response.status}. Please try a different query.`;
            return; // Stop execution here
        }

        const books = await response.json();
        // --- MODIFIED CODE END ---

        if (books && books.length > 0) {
            searchStatus.textContent = ''; // Clear status message
            books.forEach(book => {
                const bookCard = createBookCard(book);
                bookCardsContainer.appendChild(bookCard);
            });
        } else {
            searchStatus.textContent = 'No books found. Try a different search.';
        }
    } catch (error) {
        console.error('Error fetching search results:', error);
        searchStatus.textContent = 'An error occurred during the search.';
    } finally {
        if (searchButton) searchButton.disabled = false;
    }
}

/**
 * Uploads an image file for OCR, then performs a book search using the extracted text.
 */
async function uploadImageForOcr() {
    const ocrImageInput = document.getElementById('ocrImageInput');
    const ocrStatus = document.getElementById('ocrStatus');
    const ocrButton = document.getElementById('ocrButton');
    const bookSearchQuery = document.getElementById('bookSearchQuery');

    if (!ocrImageInput || !ocrStatus || !ocrButton || !bookSearchQuery) {
        console.error('Required OCR or search elements not found on the page. Skipping OCR functionality.');
        return;
    }

    const file = ocrImageInput.files[0];
    if (!file) {
        ocrStatus.textContent = 'Please select an image file first.';
        return;
    }

    const formData = new FormData();
    formData.append('image', file);
    
    ocrButton.disabled = true;
    ocrButton.textContent = 'Scanning...';
    ocrStatus.textContent = 'Processing image and searching for book...';

    try {
        const response = await fetch('/ocr_upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server responded with an error:', response.status, response.statusText);
            console.error('Server response content:', errorText);
            ocrStatus.textContent = `Error: Server responded with status ${response.status}. See console for details.`;
            return;
        }

        const result = await response.json();
        
        if (result && result.full_text) {
             // Populate the manual search box with the extracted text
             bookSearchQuery.value = result.full_text;
             console.log('Populated manual search box with OCR text.');
             
             // Now perform the search using the extracted text
             performBookSearch(result.full_text);
             ocrStatus.textContent = `OCR successful! Found text: "${result.full_text}". Now searching...`;
        } else {
            ocrStatus.textContent = 'No text was found in the image. Please try a manual search.';
        }

    } catch (error) {
        console.error('Error during OCR search:', error);
        ocrStatus.textContent = 'An error occurred while processing the image.';
    } finally {
        ocrButton.disabled = false;
        ocrButton.textContent = 'Process Image & Search';
    }
}

// -------------------------------------------------------------------------------------------------
// --- Event listener for when the page is fully loaded and parsed ---
// -------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    console.log("DEBUG: DOMContentLoaded event fired.");
    loadTheme();
    setupSocket();
    setupCharts();

    // Event listener for manual book search
    const searchButton = document.getElementById('searchButton');
    const bookSearchQuery = document.getElementById('bookSearchQuery');
    if (searchButton && bookSearchQuery) {
        searchButton.addEventListener('click', () => {
            const query = bookSearchQuery.value.trim();
            if (query) {
                performBookSearch(query);
            }
        });
        // Allow searching with the Enter key
        bookSearchQuery.addEventListener('keyup', (event) => {
            if (event.key === 'Enter') {
                searchButton.click();
            }
        });
    } else {
        console.error("DEBUG: Search button or input not found.");
    }
    
    // Event listener for OCR search
    const ocrUploadButton = document.querySelector('.ocr-upload-form button');
    // The user's provided code had a different selector, this one is more robust
    const ocrButton = document.getElementById('ocrButton');
    if (ocrUploadButton || ocrButton) {
        const buttonToListen = ocrButton || ocrUploadButton;
        buttonToListen.addEventListener('click', (e) => {
            e.preventDefault();
            uploadImageForOcr();
        });
    } else {
        console.error("DEBUG: OCR button not found.");
    }

    // Event listener for adding books to the library (event delegation)
    const bookCardsContainer = document.getElementById('bookCardsContainer');
    if (bookCardsContainer) {
        bookCardsContainer.addEventListener('click', async (event) => {
            if (event.target.classList.contains('add-book-button')) {
                const button = event.target;
                const bookData = JSON.parse(button.dataset.book);
                
                try {
                    const response = await fetch('/add_book_to_library', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(bookData)
                    });
                    const result = await response.json();

                    if (result.success) {
                        button.textContent = 'Added!';
                        button.disabled = true;
                        button.classList.add('bg-green-500', 'hover:bg-green-600', 'cursor-not-allowed');
                        // The user's provided code used inline styling, this is a more robust class-based approach.
                    } else {
                        // Use a custom modal or a simple alert for feedback.
                        alert('Failed to add book: ' + result.message);
                    }
                } catch (error) {
                    console.error('Error adding book to library:', error);
                    alert('An error occurred. Could not add book.');
                }
            }
        });
    }
});
