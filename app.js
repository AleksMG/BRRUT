class VigenereCipher {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.setAlphabet(alphabet);
    }

    setAlphabet(alphabet) {
        if (typeof alphabet !== 'string' || alphabet.length === 0) {
            throw new Error('Alphabet must be a non-empty string');
        }

        // Check for duplicate characters
        const uniqueChars = new Set(alphabet.toUpperCase());
        if (uniqueChars.size !== alphabet.length) {
            throw new Error('Alphabet must contain unique characters');
        }

        this.alphabet = alphabet.toUpperCase();
        this.alphabetMap = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetMap[this.alphabet[i]] = i;
        }
    }

    encrypt(plaintext, key, preserveCase = true, preserveNonAlphabetic = true) {
        return this._processText(plaintext, key, true, preserveCase, preserveNonAlphabetic);
    }

    decrypt(ciphertext, key, preserveCase = true, preserveNonAlphabetic = true) {
        return this._processText(ciphertext, key, false, preserveCase, preserveNonAlphabetic);
    }

    _processText(text, key, encrypt, preserveCase, preserveNonAlphabetic) {
        if (typeof text !== 'string' || typeof key !== 'string') {
            throw new Error('Text and key must be strings');
        }

        if (key.length === 0) {
            throw new Error('Key cannot be empty');
        }

        let result = '';
        const keyUpper = key.toUpperCase();
        let keyIndex = 0;

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const upperChar = char.toUpperCase();

            if (this.alphabetMap[upperChar] !== undefined) {
                const textPos = this.alphabetMap[upperChar];
                const keyPos = this.alphabetMap[keyUpper[keyIndex % keyUpper.length]];
                
                let newPos;
                if (encrypt) {
                    newPos = (textPos + keyPos) % this.alphabet.length;
                } else {
                    newPos = (textPos - keyPos + this.alphabet.length) % this.alphabet.length;
                }

                let newChar = this.alphabet[newPos];
                if (preserveCase && char === char.toLowerCase()) {
                    newChar = newChar.toLowerCase();
                }

                result += newChar;
                keyIndex++;
            } else {
                if (preserveNonAlphabetic) {
                    result += char;
                }
            }
        }

        return result;
    }

    generateAllPossibleKeys(maxLength) {
        const keys = [];
        for (let length = 1; length <= maxLength; length++) {
            this._generateKeysOfLength('', length, keys);
        }
        return keys;
    }

    _generateKeysOfLength(current, length, keys) {
        if (current.length === length) {
            keys.push(current);
            return;
        }

        for (const char of this.alphabet) {
            this._generateKeysOfLength(current + char, length, keys);
        }
    }
}

class CipherAnalyzer {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.setAlphabet(alphabet);
        this.loadQuadgrams();
    }

    setAlphabet(alphabet) {
        this.cipher = new VigenereCipher(alphabet);
    }

    loadQuadgrams() {
        // English quadgram frequencies (simplified for this example)
        // In a real application, this would be loaded from a more comprehensive dataset
        this.quadgrams = {
            'TION': 0.0314, 'THER': 0.0267, 'NTHE': 0.0263, 'THAT': 0.0253,
            'OFTH': 0.0246, 'FTHE': 0.0244, 'THES': 0.0234, 'WITH': 0.0232,
            'INTH': 0.0213, 'ATIO': 0.0208, 'OTHE': 0.0206, 'TTHA': 0.0198,
            'NDTH': 0.0196, 'ETHE': 0.0194, 'TOTH': 0.0189, 'DTHE': 0.0187,
            'INGT': 0.0185, 'INGA': 0.0183, 'OFTH': 0.0181, 'REQU': 0.0179
        };
    }

    scoreText(text, method = 'quadgrams') {
        text = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (text.length < 4) return -Infinity;

        let score = 0;
        const n = text.length;

        if (method === 'quadgrams') {
            for (let i = 0; i < n - 3; i++) {
                const quadgram = text.substr(i, 4);
                score += Math.log10(this.quadgrams[quadgram] || 1e-10);
            }
            return score;
        } else if (method === 'ic') {
            return this.indexOfCoincidence(text);
        } else if (method === 'chi2') {
            return this.chiSquared(text);
        }

        return score;
    }

    indexOfCoincidence(text) {
        const freq = {};
        let count = 0;
        
        for (const char of text) {
            freq[char] = (freq[char] || 0) + 1;
            count++;
        }
        
        if (count < 2) return 0;
        
        let sum = 0;
        for (const char in freq) {
            sum += freq[char] * (freq[char] - 1);
        }
        
        return sum / (count * (count - 1));
    }

    chiSquared(text) {
        // English letter frequencies (percentages)
        const englishFreq = {
            'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
            'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
            'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
            'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
            'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
        };
        
        const freq = {};
        let count = 0;
        
        for (const char of text.toUpperCase()) {
            if (englishFreq[char]) {
                freq[char] = (freq[char] || 0) + 1;
                count++;
            }
        }
        
        if (count === 0) return Infinity;
        
        let chi2 = 0;
        for (const char in englishFreq) {
            const expected = englishFreq[char] / 100 * count;
            const observed = freq[char] || 0;
            chi2 += Math.pow(observed - expected, 2) / expected;
        }
        
        return chi2;
    }

    findRepeatingSequences(text, minLength = 3) {
        const sequences = {};
        
        for (let length = minLength; length <= Math.floor(text.length / 2); length++) {
            for (let i = 0; i <= text.length - length; i++) {
                const seq = text.substr(i, length);
                if (seq in sequences) {
                    sequences[seq].push(i);
                } else {
                    sequences[seq] = [i];
                }
            }
        }
        
        // Filter sequences that appear at least twice
        const repeating = {};
        for (const seq in sequences) {
            if (sequences[seq].length >= 2) {
                repeating[seq] = sequences[seq];
            }
        }
        
        return repeating;
    }

    estimateKeyLength(ciphertext, maxLength = 20) {
        const sequences = this.findRepeatingSequences(ciphertext);
        if (Object.keys(sequences).length === 0) {
            return null;
        }
        
        // Calculate distances between repeating sequences
        const distances = [];
        for (const seq in sequences) {
            const positions = sequences[seq];
            for (let i = 1; i < positions.length; i++) {
                distances.push(positions[i] - positions[i - 1]);
            }
        }
        
        if (distances.length === 0) {
            return null;
        }
        
        // Find the most likely key length by finding common factors
        const factorCounts = {};
        for (const distance of distances) {
            const factors = this.getFactors(distance, maxLength);
            for (const factor of factors) {
                factorCounts[factor] = (factorCounts[factor] || 0) + 1;
            }
        }
        
        // Find the factor with the highest count
        let bestLength = null;
        let highestCount = 0;
        for (const length in factorCounts) {
            if (factorCounts[length] > highestCount) {
                highestCount = factorCounts[length];
                bestLength = parseInt(length);
            }
        }
        
        return bestLength;
    }

    getFactors(n, max) {
        const factors = new Set();
        for (let i = 1; i <= Math.min(n, max); i++) {
            if (n % i === 0) {
                factors.add(i);
            }
        }
        return Array.from(factors);
    }
}

class Cracker {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.analyzer = new CipherAnalyzer(alphabet);
        this.cipher = new VigenereCipher(alphabet);
        this.alphabet = alphabet;
        this.workers = [];
        this.isRunning = false;
        this.results = [];
        this.keysTested = 0;
        this.startTime = null;
        this.lastUpdateTime = null;
        this.keysPerSecond = 0;
    }

    async crack(ciphertext, options = {}) {
        if (this.isRunning) {
            throw new Error('Cracking already in progress');
        }

        this.isRunning = true;
        this.results = [];
        this.keysTested = 0;
        this.startTime = performance.now();
        this.lastUpdateTime = this.startTime;

        const {
            maxKeyLength = 10,
            workersCount = 4,
            batchSize = 1000,
            method = 'frequency',
            knownPlaintext = '',
            scoringMethod = 'quadgrams'
        } = options;

        // Estimate key length if not specified
        const estimatedLength = this.analyzer.estimateKeyLength(ciphertext, maxKeyLength);
        const keyLengthsToTry = estimatedLength ? 
            [estimatedLength] : 
            Array.from({length: maxKeyLength}, (_, i) => i + 1);

        // Generate key batches
        const keyBatches = [];
        for (const length of keyLengthsToTry) {
            const keys = this.cipher.generateAllPossibleKeys(length);
            for (let i = 0; i < keys.length; i += batchSize) {
                keyBatches.push(keys.slice(i, i + batchSize));
            }
        }

        // Create workers
        this.workers = [];
        const workerPromises = [];
        const batchesPerWorker = Math.ceil(keyBatches.length / workersCount);

        for (let i = 0; i < workersCount; i++) {
            const start = i * batchesPerWorker;
            const end = Math.min(start + batchesPerWorker, keyBatches.length);
            if (start >= end) continue;

            const worker = new Worker('worker.js');
            this.workers.push(worker);

            worker.onmessage = (event) => {
                const { keysTested, results } = event.data;
                this.keysTested += keysTested;
                this.results.push(...results);
                this.updateSpeed();
                this.updateUI();
            };

            worker.postMessage({
                type: 'start',
                ciphertext,
                keyBatches: keyBatches.slice(start, end),
                alphabet: this.alphabet,
                method,
                knownPlaintext,
                scoringMethod
            });

            workerPromises.push(new Promise((resolve) => {
                worker.onmessage = (event) => {
                    if (event.data.type === 'done') {
                        resolve();
                    }
                };
            }));
        }

        // Wait for all workers to finish
        await Promise.all(workerPromises);

        this.isRunning = false;
        this.updateUI();
        return this.getTopResults();
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        for (const worker of this.workers) {
            worker.terminate();
        }
        this.workers = [];
    }

    updateSpeed() {
        const now = performance.now();
        const timeElapsed = (now - this.lastUpdateTime) / 1000; // in seconds
        if (timeElapsed > 0) {
            this.keysPerSecond = Math.round(this.keysTested / timeElapsed);
        }
        this.lastUpdateTime = now;
    }

    updateUI() {
        // This would be implemented to update the DOM
        // In a real app, you'd have references to DOM elements
        console.log(`Keys tested: ${this.keysTested}, Speed: ${this.keysPerSecond} keys/sec`);
    }

    getTopResults(count = 10) {
        return this.results
            .sort((a, b) => b.score - a.score)
            .slice(0, count);
    }

    getProgress() {
        if (!this.startTime) return 0;
        // This would be more sophisticated in a real implementation
        return Math.min(this.keysTested / 100000, 1); // Simplified for example
    }

    getTimeRemaining() {
        if (!this.startTime || this.keysPerSecond === 0) return '-';

        const keysRemaining = 100000 - this.keysTested; // Simplified for example
        const secondsRemaining = keysRemaining / this.keysPerSecond;

        if (secondsRemaining > 3600) {
            return `${Math.round(secondsRemaining / 3600)} hours`;
        } else if (secondsRemaining > 60) {
            return `${Math.round(secondsRemaining / 60)} minutes`;
        } else {
            return `${Math.round(secondsRemaining)} seconds`;
        }
    }
}

// DOM Interaction Code
document.addEventListener('DOMContentLoaded', () => {
    // Initialize cipher with default alphabet
    const defaultAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const cipher = new VigenereCipher(defaultAlphabet);
    const analyzer = new CipherAnalyzer(defaultAlphabet);
    const cracker = new Cracker(defaultAlphabet);

    // DOM Elements
    const elements = {
        customAlphabet: document.getElementById('custom-alphabet'),
        resetAlphabet: document.getElementById('reset-alphabet'),
        plaintext: document.getElementById('plaintext'),
        encryptKey: document.getElementById('encrypt-key'),
        encryptBtn: document.getElementById('encrypt-btn'),
        ciphertextOutput: document.getElementById('ciphertext-output'),
        ciphertext: document.getElementById('ciphertext'),
        decryptKey: document.getElementById('decrypt-key'),
        decryptBtn: document.getElementById('decrypt-btn'),
        plaintextOutput: document.getElementById('plaintext-output'),
        ciphertextToCrack: document.getElementById('ciphertext-to-crack'),
        knownPlaintext: document.getElementById('known-plaintext'),
        keyLength: document.getElementById('key-length'),
        keyLengthValue: document.getElementById('key-length-value'),
        workersCount: document.getElementById('workers-count'),
        workersCountValue: document.getElementById('workers-count-value'),
        batchSize: document.getElementById('batch-size'),
        batchSizeValue: document.getElementById('batch-size-value'),
        crackMethod: document.getElementById('crack-method'),
        crackBtn: document.getElementById('crack-btn'),
        stopBtn: document.getElementById('stop-btn'),
        progressBar: document.getElementById('progress-bar'),
        status: document.getElementById('status'),
        activeWorkers: document.getElementById('active-workers'),
        totalWorkers: document.getElementById('total-workers'),
        keysTested: document.getElementById('keys-tested'),
        keysPerSecond: document.getElementById('keys-per-second'),
        timeRemaining: document.getElementById('time-remaining'),
        resultsContainer: document.getElementById('results-container'),
        scoringMethod: document.getElementById('scoring-method'),
        caseSensitive: document.getElementById('case-sensitive'),
        preserveSpaces: document.getElementById('preserve-spaces'),
        preservePunctuation: document.getElementById('preserve-punctuation'),
        resetSettings: document.getElementById('reset-settings')
    };

    // Event Listeners
    elements.resetAlphabet.addEventListener('click', () => {
        elements.customAlphabet.value = defaultAlphabet;
        updateAlphabet();
    });

    elements.encryptBtn.addEventListener('click', encryptText);
    elements.decryptBtn.addEventListener('click', decryptText);
    elements.crackBtn.addEventListener('click', startCracking);
    elements.stopBtn.addEventListener('click', stopCracking);
    elements.resetSettings.addEventListener('click', resetSettings);

    elements.keyLength.addEventListener('input', () => {
        elements.keyLengthValue.textContent = elements.keyLength.value;
    });

    elements.workersCount.addEventListener('input', () => {
        elements.workersCountValue.textContent = elements.workersCount.value;
    });

    elements.batchSize.addEventListener('input', () => {
        elements.batchSizeValue.textContent = elements.batchSize.value;
    });

    elements.customAlphabet.addEventListener('change', updateAlphabet);

    // Initialize UI
    elements.keyLengthValue.textContent = elements.keyLength.value;
    elements.workersCountValue.textContent = elements.workersCount.value;
    elements.batchSizeValue.textContent = elements.batchSize.value;

    // Functions
    function updateAlphabet() {
        try {
            const newAlphabet = elements.customAlphabet.value.toUpperCase();
            cipher.setAlphabet(newAlphabet);
            analyzer.setAlphabet(newAlphabet);
            cracker.alphabet = newAlphabet;
            showMessage('Alphabet updated successfully', 'success');
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    }

    function encryptText() {
        try {
            const plaintext = elements.plaintext.value;
            const key = elements.encryptKey.value;
            const preserveCase = elements.caseSensitive.checked;
            const preserveNonAlphabetic = elements.preservePunctuation.checked || elements.preserveSpaces.checked;
            
            if (!plaintext || !key) {
                throw new Error('Plaintext and key are required');
            }
            
            const ciphertext = cipher.encrypt(plaintext, key, preserveCase, preserveNonAlphabetic);
            elements.ciphertextOutput.value = ciphertext;
            showMessage('Text encrypted successfully', 'success');
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    }

    function decryptText() {
        try {
            const ciphertext = elements.ciphertext.value;
            const key = elements.decryptKey.value;
            const preserveCase = elements.caseSensitive.checked;
            const preserveNonAlphabetic = elements.preservePunctuation.checked || elements.preserveSpaces.checked;
            
            if (!ciphertext || !key) {
                throw new Error('Ciphertext and key are required');
            }
            
            const plaintext = cipher.decrypt(ciphertext, key, preserveCase, preserveNonAlphabetic);
            elements.plaintextOutput.value = plaintext;
            showMessage('Text decrypted successfully', 'success');
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    }

    async function startCracking() {
        try {
            const ciphertext = elements.ciphertextToCrack.value;
            if (!ciphertext) {
                throw new Error('Ciphertext is required');
            }

            // Update UI for cracking in progress
            elements.crackBtn.disabled = true;
            elements.stopBtn.disabled = false;
            elements.status.textContent = 'Running';
            elements.totalWorkers.textContent = elements.workersCount.value;
            elements.activeWorkers.textContent = '0';
            elements.keysTested.textContent = '0';
            elements.keysPerSecond.textContent = '0';
            elements.timeRemaining.textContent = '-';
            elements.progressBar.style.width = '0%';
            elements.resultsContainer.innerHTML = '';

            const options = {
                maxKeyLength: parseInt(elements.keyLength.value),
                workersCount: parseInt(elements.workersCount.value),
                batchSize: parseInt(elements.batchSize.value),
                method: elements.crackMethod.value,
                knownPlaintext: elements.knownPlaintext.value,
                scoringMethod: elements.scoringMethod.value
            };

            // Start cracking
            await cracker.crack(ciphertext, options);

            // Display results
            const results = cracker.getTopResults(10);
            displayResults(results);

            showMessage('Cracking completed', 'success');
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        } finally {
            elements.crackBtn.disabled = false;
            elements.stopBtn.disabled = true;
            elements.status.textContent = 'Ready';
        }
    }

    function stopCracking() {
        cracker.stop();
        elements.status.textContent = 'Stopped';
        elements.crackBtn.disabled = false;
        elements.stopBtn.disabled = true;
        showMessage('Cracking stopped', 'info');
    }

    function displayResults(results) {
        elements.resultsContainer.innerHTML = '';
        
        if (results.length === 0) {
            elements.resultsContainer.innerHTML = '<p>No results found. Try different settings.</p>';
            return;
        }
        
        results.forEach((result, index) => {
            const resultElement = document.createElement('div');
            resultElement.className = 'result-item';
            resultElement.innerHTML = `
                <h4>Result ${index + 1}</h4>
                <p>Key: <span class="key">${result.key}</span> <span class="score">Score: ${result.score.toFixed(2)}</span></p>
                <div class="plaintext">${result.plaintext}</div>
            `;
            elements.resultsContainer.appendChild(resultElement);
        });
    }

    function resetSettings() {
        elements.scoringMethod.value = 'quadgrams';
        elements.caseSensitive.checked = true;
        elements.preserveSpaces.checked = true;
        elements.preservePunctuation.checked = true;
        showMessage('Settings reset to defaults', 'info');
    }

    function showMessage(message, type) {
        // In a real app, you'd show this in a dedicated message area
        console.log(`${type}: ${message}`);
    }

    // Update progress periodically
    setInterval(() => {
        if (cracker.isRunning) {
            const progress = cracker.getProgress() * 100;
            elements.progressBar.style.width = `${progress}%`;
            elements.activeWorkers.textContent = cracker.workers.length;
            elements.keysTested.textContent = cracker.keysTested.toLocaleString();
            elements.keysPerSecond.textContent = cracker.keysPerSecond.toLocaleString();
            elements.timeRemaining.textContent = cracker.getTimeRemaining();
        }
    }, 500);
});
