(function() {
    'use strict';

    // Initialize terminal with green-on-black theme
    var term = new Terminal({
        theme: {
            background: '#000000',
            foreground: '#00ff00',
            cursor: '#00ff00',
            cursorAccent: '#000000'
        },
        fontFamily: '"Fira Code", "Cascadia Code", "Source Code Pro", monospace',
        fontSize: 14,
        cursorBlink: true,
        scrollback: 1000
    });

    var fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(document.getElementById('terminal'));
    fitAddon.fit();

    // Resize handling
    window.addEventListener('resize', function() {
        fitAddon.fit();
    });

    // State
    var inputBuffer = '';
    var isProcessing = false;

    // ANSI color helpers
    function writeGreen(text) {
        term.write('\x1b[32m' + text + '\x1b[0m');
    }

    function writeRed(text) {
        term.write('\x1b[31m' + text + '\x1b[0m');
    }

    function writeYellow(text) {
        term.write('\x1b[33m' + text + '\x1b[0m');
    }

    function writeCyan(text) {
        term.write('\x1b[36m' + text + '\x1b[0m');
    }

    function writeLine(text) {
        term.writeln(text);
    }

    // Show welcome banner
    function showBanner() {
        writeLine('');
        writeCyan('  JWT Authentication Service\r\n');
        writeLine('  ─────────────────────────────────────');
        writeLine('');
        writeLine('  Paste your JWT token and press Enter to authenticate.');
        writeLine('  Your token will be validated and a session cookie will be set.');
        writeLine('');
        showPrompt();
    }

    function showPrompt() {
        writeGreen('jwt> ');
    }

    // Mask long tokens for display
    function maskToken(token) {
        if (token.length <= 20) {
            return token;
        }
        return token.substring(0, 10) + '...' + token.substring(token.length - 10);
    }

    // Clear the current line and redraw prompt with masked input
    function redrawLine() {
        term.write('\r\x1b[K');
        showPrompt();
        if (inputBuffer.length > 40) {
            term.write(maskToken(inputBuffer));
        } else {
            term.write(inputBuffer);
        }
    }

    // Submit token for validation
    async function submitToken(token) {
        if (isProcessing) {
            return;
        }
        isProcessing = true;

        // Clean token: strip whitespace and newlines
        token = token.trim().replace(/[\r\n\s]+/g, '');

        if (!token) {
            writeLine('');
            writeRed('  Error: No token provided\r\n');
            writeLine('');
            showPrompt();
            isProcessing = false;
            return;
        }

        writeLine('');
        writeYellow('  Validating token...\r\n');

        try {
            // Step 1: Fetch CSRF token
            var csrfResp = await fetch('/csrf');
            if (!csrfResp.ok) {
                throw new Error('Failed to fetch CSRF token: ' + csrfResp.status);
            }
            var csrfData = await csrfResp.json();

            // Step 2: Submit JWT with CSRF token
            var validateResp = await fetch('/api/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfData.token
                },
                body: JSON.stringify({ token: token })
            });

            var result = await validateResp.json();

            if (validateResp.ok && result.valid) {
                writeLine('');
                writeGreen('  Authentication successful!\r\n');
                writeLine('');
                writeLine('  User ID:    ' + result.user_id);
                writeLine('  Token type: ' + result.token_type);
                if (result.expires_at) {
                    writeLine('  Expires:    ' + new Date(result.expires_at).toLocaleString());
                }
                writeLine('');
                writeLine('  Session cookie has been set.');
                writeLine('  You can now access protected services.');
                writeLine('');
            } else {
                writeRed('  Authentication failed\r\n');
                writeLine('');
                if (result.error) {
                    writeLine('  Error: ' + result.error);
                }
                if (result.message) {
                    writeLine('  ' + result.message);
                }
                writeLine('');
                showPrompt();
            }
        } catch (err) {
            writeRed('  Error: ' + err.message + '\r\n');
            writeLine('');
            showPrompt();
        }

        isProcessing = false;
    }

    // Handle keyboard input
    term.onData(function(data) {
        if (isProcessing) {
            return;
        }

        // Handle Enter
        if (data === '\r') {
            submitToken(inputBuffer);
            inputBuffer = '';
            return;
        }

        // Handle Backspace (DEL character)
        if (data === '\x7f') {
            if (inputBuffer.length > 0) {
                inputBuffer = inputBuffer.slice(0, -1);
                if (inputBuffer.length > 40) {
                    redrawLine();
                } else {
                    term.write('\b \b');
                }
            }
            return;
        }

        // Handle Ctrl+C
        if (data === '\x03') {
            inputBuffer = '';
            writeLine('^C');
            showPrompt();
            return;
        }

        // Handle Ctrl+U (clear line)
        if (data === '\x15') {
            inputBuffer = '';
            redrawLine();
            return;
        }

        // Handle paste (multi-character data) and regular input
        // Strip newlines from pasted content
        var cleanData = data.replace(/[\r\n]/g, '');
        if (cleanData.length > 0) {
            inputBuffer += cleanData;
            if (inputBuffer.length > 40) {
                redrawLine();
            } else {
                term.write(cleanData);
            }
        }
    });

    // Start
    showBanner();
})();
