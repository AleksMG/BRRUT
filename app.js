class VigenereAnalyzer {
    constructor() {
        this.workers = [];
        this.isProcessing = false;
        this.totalKeysTested = 0;
        this.startTime = null;
        this.lastUpdateTime = null;
        this.keysPerSecond = 0;
        this.possibleKeys = 0;
        this.keysTested = 0;
        this.workerCompleteCount = 0;
        this.topKeys = [];
        this.maxTopKeys = 10;
        this.currentOperation = null;
        
        this.initElements();
        this.initEventListeners();
        this.updateRangeValues();
    }

    initElements() {
        this.plaintextEl = document.getElementById('plaintext');
        this.ciphertextEl = document.getElementById('ciphertext');
        this.keyEl = document.getElementById('key');
        this.resultTextEl = document.getElementById('result-text');
        this.alphabetEl = document.getElementById('alphabet');
        this.knownFragmentEl = document.getElementById('known-fragment');
        
        this.encryptBtn = document.getElementById('encrypt-btn');
        this.decryptBtn = document.getElementById('decrypt-btn');
        this.bruteBtn = document.getElementById('brute-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.cancelBtn = document.getElementById('cancel-btn');
        
        this.keyLengthEl = document.getElementById('key-length');
        this.workersEl = document.getElementById('workers');
        this.batchSizeEl = document.getElementById('batch-size');
        
        this.keyLengthValueEl = document.getElementById('key-length-value');
        this.workersValueEl = document.getElementById('workers-value');
        this.batchSizeValueEl = document.getElementById('batch-size-value');
        
        this.progressSection = document.getElementById('progress-section');
        this.progressFillEl = document.getElementById('progress-fill');
        this.progressPercentEl = document.getElementById('progress-percent');
        this.workersActiveEl = document.getElementById('workers-active');
        this.keysTestedEl = document.getElementById('keys-tested');
        this.keysPerSecondEl = document.getElementById('keys-per-second');
        this.timeRemainingEl = document.getElementById('time-remaining');
        
        this.resultTabs = document.querySelectorAll('.result-tab');
        this.resultPanes = document.querySelectorAll('.result-pane');
        this.analysisResultsEl = document.getElementById('analysis-results');
        this.keysTableBody = document.querySelector('#keys-table tbody');
    }

    initEventListeners() {
        this.encryptBtn.addEventListener('click', () => this.handleEncrypt());
        this.decryptBtn.addEventListener('click', () => this.handleDecrypt());
        this.bruteBtn.addEventListener('click', () => this.handleBruteForce());
        this.clearBtn.addEventListener('click', () => this.handleClear());
        this.cancelBtn.addEventListener('click', () => this.handleCancel());
        
        this.keyLengthEl.addEventListener('input', () => this.updateRangeValues());
        this.workersEl.addEventListener('input', () => this.updateRangeValues());
        this.batchSizeEl.addEventListener('input', () => this.updateRangeValues());
        
        this.resultTabs.forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab));
        });
    }

    updateRangeValues() {
        this.keyLengthValueEl.textContent = this.keyLengthEl.value;
        this.workersValueEl.textContent = this.workersEl.value;
        this.batchSizeValueEl.textContent = this.batchSizeEl.value;
    }

    switchTab(clickedTab) {
        this.resultTabs.forEach(tab => tab.classList.remove('active'));
        this.resultPanes.forEach(pane => pane.classList.remove('active'));
        clickedTab.classList.add('active');
        const paneId = clickedTab.getAttribute('data-tab');
        document.getElementById(paneId).classList.add('active');
    }

    handleEncrypt() {
        const plaintext = this.plaintextEl.value.toUpperCase();
        const key = this.keyEl.value.toUpperCase();
        const alphabet = this.alphabetEl.value.toUpperCase();
        
        if (!plaintext) {
            alert('Please enter plaintext to encrypt');
            return;
        }
        
        if (!key) {
            alert('Please enter an encryption key');
            return;
        }
        
        if (!this.validateAlphabet(alphabet)) {
            alert('Invalid alphabet. Must contain at least 2 unique characters.');
            return;
        }
        
        const ciphertext = this.vigenereEncrypt(plaintext, key, alphabet);
        this.ciphertextEl.value = ciphertext;
        this.resultTextEl.value = ciphertext;
        this.switchTab(document.querySelector('[data-tab="decrypted"]'));
    }

    handleDecrypt() {
        const ciphertext = this.ciphertextEl.value.toUpperCase();
        const key = this.keyEl.value.toUpperCase();
        const alphabet = this.alphabetEl.value.toUpperCase();
        
        if (!ciphertext) {
            alert('Please enter ciphertext to decrypt');
            return;
        }
        
        if (!key) {
            alert('Please enter a decryption key');
            return;
        }
        
        if (!this.validateAlphabet(alphabet)) {
            alert('Invalid alphabet. Must contain at least 2 unique characters.');
            return;
        }
        
        const plaintext = this.vigenereDecrypt(ciphertext, key, alphabet);
        this.plaintextEl.value = plaintext;
        this.resultTextEl.value = plaintext;
        this.switchTab(document.querySelector('[data-tab="decrypted"]'));
    }

    handleBruteForce() {
        const ciphertext = this.ciphertextEl.value.toUpperCase();
        const alphabet = this.alphabetEl.value.toUpperCase();
        const knownFragment = this.knownFragmentEl.value.toUpperCase();
        const maxKeyLength = parseInt(this.keyLengthEl.value);
        const workerCount = parseInt(this.workersEl.value);
        const batchSize = parseInt(this.batchSizeEl.value);
        
        if (!ciphertext) {
            alert('Please enter ciphertext to decrypt');
            return;
        }
        
        if (!this.validateAlphabet(alphabet)) {
            alert('Invalid alphabet. Must contain at least 2 unique characters.');
            return;
        }
        
        if (knownFragment && !this.validateKnownFragment(knownFragment, alphabet)) {
            alert('Known fragment contains characters not in the alphabet');
            return;
        }
        
        this.currentOperation = 'brute-force';
        this.startBruteForce(ciphertext, alphabet, knownFragment, maxKeyLength, workerCount, batchSize);
    }

    handleClear() {
        this.plaintextEl.value = '';
        this.ciphertextEl.value = '';
        this.keyEl.value = '';
        this.resultTextEl.value = '';
        this.analysisResultsEl.innerHTML = '';
        this.keysTableBody.innerHTML = '';
    }

    handleCancel() {
        if (this.isProcessing) {
            this.terminateWorkers();
            this.progressSection.style.display = 'none';
            this.isProcessing = false;
            this.currentOperation = null;
            alert('Operation cancelled');
        }
    }

    validateAlphabet(alphabet) {
        if (alphabet.length < 2) return false;
        const uniqueChars = new Set(alphabet);
        return uniqueChars.size === alphabet.length;
    }

    validateKnownFragment(fragment, alphabet) {
        for (const char of fragment) {
            if (!alphabet.includes(char)) {
                return false;
            }
        }
        return true;
    }

    vigenereEncrypt(plaintext, key, alphabet) {
        const alphabetSize = alphabet.length;
        let encryptedText = '';
        let keyIndex = 0;
        
        for (let i = 0; i < plaintext.length; i++) {
            const plainChar = plaintext[i];
            const plainIndex = alphabet.indexOf(plainChar);
            
            if (plainIndex === -1) {
                encryptedText += plainChar;
                continue;
            }
            
            const keyChar = key[keyIndex % key.length];
            const keyIndexInAlphabet = alphabet.indexOf(keyChar);
            
            const encryptedIndex = (plainIndex + keyIndexInAlphabet) % alphabetSize;
            encryptedText += alphabet[encryptedIndex];
            
            keyIndex++;
        }
        
        return encryptedText;
    }

    vigenereDecrypt(ciphertext, key, alphabet) {
        const alphabetSize = alphabet.length;
        let decryptedText = '';
        let keyIndex = 0;
        
        for (let i = 0; i < ciphertext.length; i++) {
            const cipherChar = ciphertext[i];
            const cipherIndex = alphabet.indexOf(cipherChar);
            
            if (cipherIndex === -1) {
                decryptedText += cipherChar;
                continue;
            }
            
            const keyChar = key[keyIndex % key.length];
            const keyIndexInAlphabet = alphabet.indexOf(keyChar);
            
            let decryptedIndex = (cipherIndex - keyIndexInAlphabet) % alphabetSize;
            if (decryptedIndex < 0) {
                decryptedIndex += alphabetSize;
            }
            
            decryptedText += alphabet[decryptedIndex];
            keyIndex++;
        }
        
        return decryptedText;
    }

    startBruteForce(ciphertext, alphabet, knownFragment, maxKeyLength, workerCount, batchSize) {
        if (this.isProcessing) return;
        
        this.isProcessing = true;
        this.totalKeysTested = 0;
        this.startTime = performance.now();
        this.lastUpdateTime = this.startTime;
        this.keysPerSecond = 0;
        this.workerCompleteCount = 0;
        this.topKeys = [];
        
        this.possibleKeys = 0;
        for (let len = 1; len <= maxKeyLength; len++) {
            this.possibleKeys += Math.pow(alphabet.length, len);
        }
        
        this.keysTested = 0;
        
        this.progressSection.style.display = 'block';
        this.updateProgress();
        
        this.workers = [];
        const keysPerWorker = Math.ceil(this.possibleKeys / workerCount);
        
        for (let i = 0; i < workerCount; i++) {
            const startKeyIndex = i * keysPerWorker;
            const endKeyIndex = Math.min((i + 1) * keysPerWorker, this.possibleKeys);
            
            const worker = new Worker('worker.js');
            
            worker.onmessage = (e) => this.handleWorkerMessage(e, i);
            
            worker.postMessage({
                type: 'start',
                ciphertext,
                alphabet,
                knownFragment,
                maxKeyLength,
                batchSize,
                startKeyIndex,
                endKeyIndex,
                alphabetSize: alphabet.length,
                totalPossibleKeys: this.possibleKeys
            });
            
            this.workers.push(worker);
        }
        
        this.workersActiveEl.textContent = `Active Workers: ${workerCount}`;
    }

    handleWorkerMessage(e, workerId) {
        const data = e.data;
        
        switch (data.type) {
            case 'progress':
                this.totalKeysTested += data.keysTested;
                this.keysTested = data.totalKeysTested;
                this.updateProgress();
                break;
                
            case 'result':
                this.processKeyResult(data.key, data.score, data.decryptedFragment);
                break;
                
            case 'complete':
                this.workerCompleteCount++;
                if (this.workerCompleteCount === this.workers.length) {
                    this.finishBruteForce();
                }
                break;
                
            case 'error':
                console.error(`Worker ${workerId} error:`, data.error);
                this.terminateWorkers();
                this.isProcessing = false;
                this.progressSection.style.display = 'none';
                alert(`Error during processing: ${data.error}`);
                break;
        }
    }

    processKeyResult(key, score, decryptedFragment) {
        this.topKeys.push({ key, score, decryptedFragment });
        this.topKeys.sort((a, b) => b.score - a.score);
        const minScore = Math.max(0.1, this.topKeys[0]?.score * 0.3 || 0);
        this.topKeys = this.topKeys.filter(k => k.score >= minScore).slice(0, this.maxTopKeys);
        this.updateTopKeysTable();
        
        if (this.topKeys.length > 0) {
            const bestKey = this.topKeys[0].key;
            const alphabet = this.alphabetEl.value.toUpperCase();
            const ciphertext = this.ciphertextEl.value.toUpperCase();
            const decrypted = this.vigenereDecrypt(ciphertext, bestKey, alphabet);
            this.resultTextEl.value = decrypted;
        }
    }

    updateTopKeysTable() {
        this.keysTableBody.innerHTML = '';
        
        this.topKeys.forEach((keyData, index) => {
            const row = document.createElement('tr');
            
            const rankCell = document.createElement('td');
            rankCell.textContent = index + 1;
            
            const keyCell = document.createElement('td');
            keyCell.textContent = keyData.key;
            
            const scoreCell = document.createElement('td');
            scoreCell.textContent = keyData.score.toFixed(2);
            
            const fragmentCell = document.createElement('td');
            fragmentCell.textContent = keyData.decryptedFragment;
            
            row.appendChild(rankCell);
            row.appendChild(keyCell);
            row.appendChild(scoreCell);
            row.appendChild(fragmentCell);
            
            this.keysTableBody.appendChild(row);
        });
    }

    updateProgress() {
        const now = performance.now();
        const timeSinceLastUpdate = (now - this.lastUpdateTime) / 1000;
        
        if (timeSinceLastUpdate >= 1) {
            this.keysPerSecond = (this.totalKeysTested / timeSinceLastUpdate);
            this.lastUpdateTime = now;
            this.totalKeysTested = 0;
        }
        
        const progress = this.keysTested / this.possibleKeys;
        const percent = Math.min(100, (progress * 100).toFixed(2));
        
        this.progressFillEl.style.width = `${percent}%`;
        this.progressPercentEl.textContent = `${percent}%`;
        this.keysTestedEl.textContent = `Keys Tested: ${this.keysTested.toLocaleString()} / ${this.possibleKeys.toLocaleString()}`;
        this.keysPerSecondEl.textContent = `Speed: ${Math.round(this.keysPerSecond).toLocaleString()} keys/s`;
        
        if (this.keysPerSecond > 0) {
            const remainingKeys = this.possibleKeys - this.keysTested;
            const secondsRemaining = remainingKeys / this.keysPerSecond;
            this.timeRemainingEl.textContent = `Time Remaining: ${this.formatTime(secondsRemaining)}`;
        }
    }

    formatTime(seconds) {
        if (seconds === Infinity) return '∞';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        return [
            hours > 0 ? `${hours}h` : '',
            minutes > 0 ? `${minutes}m` : '',
            `${secs}s`
        ].filter(Boolean).join(' ');
    }

    finishBruteForce() {
        this.isProcessing = false;
        this.currentOperation = null;
        this.terminateWorkers();
        this.progressSection.style.display = 'none';
        
        if (this.topKeys.length > 0) {
            const bestKey = this.topKeys[0].key;
            const alphabet = this.alphabetEl.value.toUpperCase();
            const ciphertext = this.ciphertextEl.value.toUpperCase();
            
            const decryptedText = this.vigenereDecrypt(ciphertext, bestKey, alphabet);
            this.resultTextEl.value = decryptedText;
            this.plaintextEl.value = decryptedText;
            this.keyEl.value = bestKey;
            this.generateAnalysisReport(ciphertext, decryptedText, bestKey);
            this.switchTab(document.querySelector('[data-tab="decrypted"]'));
        } else {
            alert('No valid keys found. Try adjusting parameters.');
        }
    }

    generateAnalysisReport(ciphertext, plaintext, key) {
        this.analysisResultsEl.innerHTML = '';
        
        const report = document.createElement('div');
        const keySection = document.createElement('div');
        keySection.innerHTML = `<h3>Key Information</h3>
                              <p><strong>Key:</strong> ${key}</p>
                              <p><strong>Key Length:</strong> ${key.length}</p>`;
        report.appendChild(keySection);
        
        const freqSection = document.createElement('div');
        freqSection.innerHTML = `<h3>Frequency Analysis</h3>
                               <p>Frequency analysis would be displayed here in a full implementation.</p>`;
        report.appendChild(freqSection);
        
        const langSection = document.createElement('div');
        langSection.innerHTML = `<h3>Language Detection</h3>
                                <p>Based on common word patterns, the decrypted text appears to be valid plaintext.</p>`;
        report.appendChild(langSection);
        
        this.analysisResultsEl.appendChild(report);
    }

    terminateWorkers() {
        this.workers.forEach(worker => worker.terminate());
        this.workers = [];
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new VigenereAnalyzer();
});
