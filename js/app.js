import { VigenereAnalyzer } from './lib/vigenere-analyzer.js';
import { KeyLengthAnalyzer } from './lib/keylength-analyzer.js';
import { ResultManager } from './lib/result-manager.js';
import { WorkerManager } from './lib/worker-manager.js';

class VigenereCrackerPro {
    constructor() {
        this.analyzer = new VigenereAnalyzer();
        this.keyLengthAnalyzer = new KeyLengthAnalyzer();
        this.resultManager = new ResultManager();
        this.workerManager = new WorkerManager();
        
        this.initDOMReferences();
        this.setupEventListeners();
        this.setupWorkerCallbacks();
    }

    initDOMReferences() {
        this.dom = {
            ciphertext: document.getElementById('ciphertext'),
            keyLength: document.getElementById('keyLength'),
            language: document.getElementById('language'),
            alphabet: document.getElementById('alphabet'),
            keyChars: document.getElementById('keyChars'),
            knownPrefix: document.getElementById('knownPrefix'),
            maxWorkers: document.getElementById('maxWorkers'),
            workersValue: document.getElementById('workersValue'),
            batchSize: document.getElementById('batchSize'),
            batchValue: document.getElementById('batchValue'),
            toggleAdvanced: document.getElementById('toggleAdvanced'),
            advancedOptions: document.getElementById('advancedOptions'),
            btnAnalyzeKeyLength: document.getElementById('btnAnalyzeKeyLength'),
            btnStart: document.getElementById('btnStart'),
            btnStop: document.getElementById('btnStop'),
            btnReset: document.getElementById('btnReset'),
            progressContainer: document.getElementById('progressContainer'),
            progressBar: document.getElementById('progressBar'),
            progressText: document.getElementById('progressText'),
            keysTested: document.getElementById('keysTested'),
            keysPerSecond: document.getElementById('keysPerSecond'),
            workerStatus: document.getElementById('workerStatus'),
            resultsLimit: document.getElementById('resultsLimit'),
            resultsGrid: document.getElementById('resultsGrid')
        };
    }

    setupEventListeners() {
        // UI Interactions
        this.dom.toggleAdvanced.addEventListener('click', () => this.toggleAdvancedOptions());
        this.dom.maxWorkers.addEventListener('input', () => this.updateWorkerCount());
        this.dom.batchSize.addEventListener('input', () => this.updateBatchSize());
        this.dom.language.addEventListener('change', () => this.handleLanguageChange());
        
        // Button Actions
        this.dom.btnAnalyzeKeyLength.addEventListener('click', () => this.analyzeKeyLength());
        this.dom.btnStart.addEventListener('click', () => this.startAttack());
        this.dom.btnStop.addEventListener('click', () => this.stopAttack());
        this.dom.btnReset.addEventListener('click', () => this.reset());
        this.dom.resultsLimit.addEventListener('change', () => this.resultManager.updateDisplay());
    }

    setupWorkerCallbacks() {
        this.workerManager.onProgress = (progress) => this.updateProgress(progress);
        this.workerManager.onResult = (result) => this.handleWorkerResult(result);
        this.workerManager.onComplete = () => this.handleCompletion();
        this.workerManager.onError = (error) => this.handleWorkerError(error);
    }

    toggleAdvancedOptions() {
        const isHidden = this.dom.advancedOptions.classList.toggle('hidden');
        this.dom.toggleAdvanced.textContent = isHidden ? '▼ Show Advanced Options' : '▲ Hide Advanced Options';
    }

    updateWorkerCount() {
        const value = this.dom.maxWorkers.value;
        this.dom.workersValue.textContent = value;
        this.workerManager.setMaxWorkers(parseInt(value));
    }

    updateBatchSize() {
        const value = this.dom.batchSize.value;
        this.dom.batchValue.textContent = value;
        this.workerManager.setBatchSize(parseInt(value));
    }

    handleLanguageChange() {
        const language = this.dom.language.value;
        if (language !== 'custom') {
            this.analyzer.setLanguageProfile(language);
        }
    }

    async analyzeKeyLength() {
        const ciphertext = this.dom.ciphertext.value.trim();
        if (!ciphertext) {
            alert('Please enter ciphertext first');
            return;
        }

        try {
            this.showLoading('Analyzing possible key lengths...');
            const analysis = await this.keyLengthAnalyzer.analyze(ciphertext);
            this.displayKeyLengthAnalysis(analysis);
        } catch (error) {
            this.showError('Key length analysis failed', error);
        } finally {
            this.hideLoading();
        }
    }

    displayKeyLengthAnalysis(analysis) {
        // Implementation for displaying key length analysis results
        console.log('Key length analysis:', analysis);
        alert(`Most probable key lengths:\n${analysis.topResults.map(r => `- ${r.length} (score: ${r.score.toFixed(2)})`).join('\n')}`);
    }

    async startAttack() {
        if (this.workerManager.isRunning) return;

        try {
            const params = this.getAttackParameters();
            this.validateParameters(params);

            this.prepareUIForAttack();
            this.resultManager.clearResults();

            await this.workerManager.startAttack(params);
        } catch (error) {
            this.showError('Attack failed to start', error);
            this.stopAttack();
        }
    }

    getAttackParameters() {
        return {
            ciphertext: this.dom.ciphertext.value.trim(),
            keyLength: this.dom.keyLength.value.trim(),
            language: this.dom.language.value,
            alphabet: this.dom.alphabet.value.trim(),
            keyChars: this.dom.keyChars.value.trim(),
            knownPrefix: this.dom.knownPrefix.value.trim(),
            maxWorkers: parseInt(this.dom.maxWorkers.value),
            batchSize: parseInt(this.dom.batchSize.value)
        };
    }

    validateParameters(params) {
        if (!params.ciphertext) throw new Error('Ciphertext is required');
        if (!params.alphabet) throw new Error('Alphabet is required');
        
        // Validate key length format (single number or range)
        if (!/^\d+(-\d+)?$/.test(params.keyLength)) {
            throw new Error('Key length must be a number or range (e.g. "5" or "5-10")');
        }
    }

    prepareUIForAttack() {
        this.dom.btnStart.disabled = true;
        this.dom.btnStop.disabled = false;
        this.dom.progressContainer.classList.remove('hidden');
        this.dom.progressBar.style.width = '0%';
    }

    stopAttack() {
        this.workerManager.stopAttack();
        this.dom.btnStart.disabled = false;
        this.dom.btnStop.disabled = true;
    }

    reset() {
        this.stopAttack();
        this.resultManager.clearResults();
        this.dom.progressContainer.classList.add('hidden');
        this.dom.progressBar.style.width = '0%';
        this.dom.progressText.textContent = '0%';
        this.dom.keysTested.textContent = '0 keys';
        this.dom.keysPerSecond.textContent = '0 keys/sec';
        this.dom.workerStatus.textContent = 'Workers: 0 active';
    }

    updateProgress({ tested, total, keysPerSecond, activeWorkers }) {
        const percent = (tested / total) * 100;
        this.dom.progressBar.style.width = `${percent}%`;
        this.dom.progressText.textContent = `${percent.toFixed(2)}%`;
        this.dom.keysTested.textContent = `${tested.toLocaleString()} keys`;
        this.dom.keysPerSecond.textContent = `${keysPerSecond.toLocaleString()} keys/sec`;
        this.dom.workerStatus.textContent = `Workers: ${activeWorkers} active`;
    }

    handleWorkerResult(result) {
        this.resultManager.addResult(result);
    }

    handleCompletion() {
        this.dom.btnStart.disabled = false;
        this.dom.btnStop.disabled = true;
        this.showNotification('Attack completed successfully');
    }

    handleWorkerError(error) {
        console.error('Worker error:', error);
        this.stopAttack();
        this.showError('Worker encountered an error', error);
    }

    showLoading(message) {
        // Implement loading indicator
        console.log('Loading:', message);
    }

    hideLoading() {
        // Hide loading indicator
    }

    showNotification(message) {
        // Implement notification system
        console.log('Notification:', message);
    }

    showError(message, error) {
        // Implement error display
        console.error('Error:', message, error);
        alert(`${message}: ${error.message}`);
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VigenereCrackerPro();
});
