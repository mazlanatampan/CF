// Create Help Page for "Word"
function loadHelpPage() {
    // Create basic HTML structure
    const helpContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Help - Word</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
                color: #333;
            }
            header {
                background-color: #0078d4;
                color: white;
                padding: 10px 20px;
                text-align: center;
            }
            main {
                padding: 20px;
                line-height: 1.6;
            }
            h1, h2 {
                color: #0078d4;
            }
            ul {
                margin: 20px 0;
                padding-left: 20px;
            }
            li {
                margin-bottom: 10px;
            }
            footer {
                text-align: center;
                padding: 10px;
                background-color: #333;
                color: white;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <header>
            <h1>Help - Word</h1>
        </header>
        <main>
            <h2>Welcome to Word Help Center</h2>
            <p>Here you can find answers to common questions and learn how to use Word effectively.</p>
            
            <h3>Topics Covered:</h3>
            <ul>
                <li><strong>Creating a New Document:</strong> Learn how to start a new document.</li>
                <li><strong>Formatting Text:</strong> Tips for bold, italic, underline, and more.</li>
                <li><strong>Saving and Exporting:</strong> How to save and export documents in different formats.</li>
                <li><strong>Using Templates:</strong> Explore pre-designed templates to save time.</li>
                <li><strong>Collaborating:</strong> Share and edit documents with others in real-time.</li>
            </ul>

            <h3>FAQ</h3>
            <p><strong>Q:</strong> How do I save a document?<br>
               <strong>A:</strong> Click "File" > "Save As" and choose your preferred location and format.
            </p>
            <p><strong>Q:</strong> Can I recover unsaved documents?<br>
               <strong>A:</strong> Yes, Word has an AutoRecover feature. Check the recovery pane when you reopen Word.
            </p>
        </main>
        <footer>
            <p>&copy; 2025 Word Help Center. All rights reserved.</p>
        </footer>
    </body>
    </html>
    `;

    // Open in a new tab
    const newWindow = window.open("", "_blank");
    newWindow.document.open();
    newWindow.document.write(helpContent);
    newWindow.document.close();
}

// Button to trigger the Help Page
document.body.innerHTML = `
    <div style="text-align: center; margin-top: 50px;">
        <button style="padding: 10px 20px; font-size: 16px; background-color: #0078d4; color: white; border: none; cursor: pointer; border-radius: 5px;" onclick="loadHelpPage()">
            Open Word Help
        </button>
    </div>
`;
