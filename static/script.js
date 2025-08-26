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

// --- Custom Modal for Confirmations/Alerts ---
const confirmModal = document.getElementById('confirmModal');
const modalMessage = document.getElementById('modalMessage');
const modalConfirmBtn = document.getElementById('modalConfirmBtn');
const modalCancelBtn = document.getElementById('modalCancelBtn');

function showModal(message, onConfirm, showCancel = false) {
    modalMessage.textContent = message;
    confirmModal.classList.remove('hidden');

    modalConfirmBtn.onclick = () => {
        confirmModal.classList.add('hidden');
        if (onConfirm) {
            onConfirm();
        }
    };

    if (showCancel) {
        modalCancelBtn.classList.remove('hidden');
        modalCancelBtn.onclick = () => {
            confirmModal.classList.add('hidden');
        };
    } else {
        modalCancelBtn.classList.add('hidden');
    }
}


document.addEventListener('DOMContentLoaded', () => {
    // --- OCR Upload Page Functionality ---
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const uploadForm = document.getElementById('uploadForm');

    // Handle form submission via drag & drop or file select
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (event) => {
            event.preventDefault(); // Stop the default form submission

            const file = fileInput.files[0];
            if (!file) {
                showModal('Please select a file to upload.', null);
                return;
            }

            if (!file.type.startsWith('image/')) {
                showModal('Please upload a valid image file.', null);
                return;
            }

            // Display a loading message
            const loadingMessage = document.createElement('p');
            loadingMessage.id = 'loadingMessage';
            loadingMessage.className = 'text-center mt-4 text-gray-500 dark:text-gray-400';
            loadingMessage.textContent = 'Processing image... This may take a moment.';
            uploadForm.parentNode.insertBefore(loadingMessage, uploadForm.nextSibling);
            
            // Disable the form elements while processing
            uploadForm.classList.add('pointer-events-none', 'opacity-50');

            const formData = new FormData();
            formData.append('file', file);

            try {
                // Submit the file for OCR processing
                const response = await fetch(uploadForm.action, {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();

                if (result.success) {
                    // Store the results in sessionStorage
                    sessionStorage.setItem('ocrResults', JSON.stringify({
                        books: result.book_info,
                        ocrText: result.ocr_text
                    }));
                    // Redirect to the results page
                    window.location.href = '/ocr_results';
                } else {
                    showModal('OCR processing failed: ' + result.message, null);
                }
            } catch (error) {
                console.error('Error during OCR processing:', error);
                showModal('An error occurred. Could not process image.', null);
            } finally {
                // Re-enable form elements and remove loading message in case of error
                loadingMessage.remove();
                uploadForm.classList.remove('pointer-events-none', 'opacity-50');
            }
        });
    }

    // Handle drag & drop functionality
    if (dropzone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, () => dropzone.classList.add('bg-gray-100', 'dark:bg-gray-700'), false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, () => dropzone.classList.remove('bg-gray-100', 'dark:bg-gray-700'), false);
        });

        dropzone.addEventListener('drop', handleDrop, false);
        dropzone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleFileSelect);

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                fileInput.files = files;
                uploadForm.submit();
            }
        }

        function handleFileSelect(e) {
            const files = e.target.files;
            if (files.length > 0) {
                // Trigger form submission as if a button was clicked
                uploadForm.submit();
            }
        }
    }


    // --- OCR Results Page Functionality ---
    const bookCardsGrid = document.getElementById('book-cards-grid');
    const ocrTextSearchInput = document.getElementById('ocrTextSearch');
    const manualSearchBtn = document.getElementById('manualSearchBtn');

    // This function will render the book cards
    function renderBookCards(books, ocrText) {
        const loadingMessage = document.getElementById('loadingMessage');
        if (loadingMessage) {
            loadingMessage.classList.add('hidden');
        }

        if (books && books.length > 0) {
            bookCardsGrid.innerHTML = '';
            books.forEach(book => {
                const bookCard = document.createElement('div');
                bookCard.classList.add('book-card', 'bg-white', 'dark:bg-gray-800', 'p-4', 'rounded-lg', 'shadow-md', 'flex', 'flex-col', 'items-center', 'text-center');

                const coverImage = book.cover_image_url ? 
                    `<img src="${book.cover_image_url}" alt="${book.title} Cover" class="book-cover mb-4 rounded-lg shadow-sm" onerror="this.onerror=null; this.src='https://placehold.co/128x192/E0E0E0/333333?text=No+Image';">` :
                    `<div class="book-cover-placeholder w-32 h-48 bg-gray-200 dark:bg-gray-700 rounded-lg flex items-center justify-center mb-4 text-sm text-gray-500 dark:text-gray-400">No Image</div>`;

                const bookInfo = `
                    <h4 class="text-lg font-semibold mb-1 text-gray-900 dark:text-gray-100">${book.title}</h4>
                    <p class="text-sm text-gray-600 dark:text-gray-400">by ${book.author}</p>
                    ${book.isbn ? `<p class="book-isbn text-xs text-gray-500 dark:text-gray-500 mt-2">ISBN: ${book.isbn}</p>` : ''}
                    <button class="add-book-button mt-4 bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded-lg transition-all" data-book='${JSON.stringify(book)}'>Add to Library</button>
                `;

                bookCard.innerHTML = coverImage + bookInfo;
                bookCardsGrid.appendChild(bookCard);
            });
        } else {
            bookCardsGrid.innerHTML = `<p class="text-center text-red-500 dark:text-red-400">No books found from the OCR text. Try a manual search.</p>`;
        }
        
        // Populate the search bar with the extracted text for manual search
        if (ocrTextSearchInput && ocrText) {
             ocrTextSearchInput.value = ocrText;
        }
    }

    // Handle manual search button click
    if (manualSearchBtn) {
        manualSearchBtn.addEventListener('click', async () => {
            const query = ocrTextSearchInput.value;
            if (!query) {
                showModal('Please enter a title or author to search.', null);
                return;
            }

            const loadingMessage = document.getElementById('loadingMessage');
            if (loadingMessage) {
                loadingMessage.classList.remove('hidden');
                bookCardsGrid.innerHTML = '';
                loadingMessage.textContent = 'Searching manually...';
            }

            try {
                const response = await fetch('/search_manual', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title: query }) // Using title for simplicity in manual search
                });
                const result = await response.json();
                if (result.success) {
                    renderBookCards(result.book_info, query);
                } else {
                    showModal(result.message, null);
                    loadingMessage.classList.add('hidden');
                }
            } catch (error) {
                console.error('Error during manual search:', error);
                showModal('An error occurred during the manual search.', null);
                loadingMessage.classList.add('hidden');
            }
        });
    }

    // Trigger the OCR fetch when the page loads, if results data is present
    if (window.location.pathname === '/ocr_results') {
        const ocrResultsData = sessionStorage.getItem('ocrResults');
        if (ocrResultsData) {
            const results = JSON.parse(ocrResultsData);
            renderBookCards(results.books, results.ocrText);
            sessionStorage.removeItem('ocrResults');
        } else {
            if (bookCardsGrid) {
                bookCardsGrid.innerHTML = `<p class="text-center text-gray-500 dark:text-gray-400">No image data found. Please go back to the <a href="/ocr_upload" class="text-blue-500 hover:underline">upload page</a>.</p>`;
            }
        }
    }

    // --- Add book functionality using the custom modal ---
    const bookCardsContainer = document.getElementById('book-cards-grid');
    if (bookCardsContainer) {
        bookCardsContainer.addEventListener('click', async (event) => {
            if (event.target.classList.contains('add-book-button')) {
                const button = event.target;
                const bookData = JSON.parse(button.dataset.book);
                
                try {
                    const response = await fetch('/add_book_to_library', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(bookData)
                    });
                    const result = await response.json();
                    if (result.success) {
                        button.textContent = 'Added!';
                        button.disabled = true;
                        button.classList.add('bg-green-500', 'hover:bg-green-600', 'cursor-not-allowed');
                        showModal('Book added to your library successfully!', null);
                    } else {
                        showModal('Failed to add book: ' + result.message, null);
                    }
                } catch (error) {
                    console.error('Error adding book to library:', error);
                    showModal('An error occurred. Could not add book.', null);
                }
            }
        });
    }

    // --- Delete book functionality using the custom modal ---
    const libraryContainer = document.querySelector('.library-container');
    if (libraryContainer) {
        libraryContainer.addEventListener('click', (event) => {
            if (event.target.classList.contains('delete-button')) {
                const button = event.target;
                const bookId = button.dataset.bookId;
                showModal('Are you sure you want to delete this book?', () => {
                    // If confirmed, submit the delete form
                    const form = document.createElement('form');
                    form.action = `/delete_book/${bookId}`;
                    form.method = 'post';
                    document.body.appendChild(form);
                    form.submit();
                }, true);
            }
        });
    }

    // Load the theme when the page loads
    loadTheme();
});
