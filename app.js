class VigenereCracker {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.alphabet = alphabet;
        this.workers = [];
        this.isRunning = false;
        this.currentTask = null;
        this.startTime = null;
        this.keysTested = 0;
        this.totalKeys = 0;
    }

    async initializeWorkers(count) {
        this.terminateWorkers();
        
        this.workers = Array.from({ length: count }, () => {
            const worker = new Worker('worker.js');
            worker.onerror = (e) => this.handleWorkerError(e);
            return worker;
        });

        await Promise.all(
            this.workers.map(worker => 
                new Promise(resolve => {
                    const handler = (e) => {
                        if (e.data.type === 'READY') {
                            worker.removeEventListener('message', handler);
                            resolve();
                        }
                    };
                    worker.addEventListener('message', handler);
                    worker.postMessage({ 
                        type: 'INIT',
                        alphabet: this.alphabet
                    });
                })
            )
        );
    }

    async crack(ciphertext, options) {
        if (this.isRunning) {
            throw new Error('Cracking already in progress');
        }

        this.isRunning = true;
        this.startTime = performance.now();
        this.keysTested = 0;
        this.currentTask = {
            ciphertext,
            options,
            results: []
        };

        try {
            await this.initializeWorkers(options.workersCount);
            
            const keyBatches = this.generateKeyBatches(
                options.maxKeyLength,
                options.batchSize
            );
            
            this.totalKeys = keyBatches.reduce((sum, batch) => sum + batch.length, 0);
            
            const results = await this.processBatches(keyBatches);
            return this.sortResults(results);
        } finally {
            this.terminateWorkers();
            this.isRunning = false;
        }
    }

    generateKeyBatches(maxLength, batchSize) {
        const batches = [];
        const alphabetSize = this.alphabet.length;
        
        for (let length = 1; length <= maxLength; length++) {
            const totalKeys = Math.pow(alphabetSize, length);
            for (let i = 0; i < totalKeys; i += batchSize) {
                batches.push(this.generateKeys(i, Math.min(batchSize, totalKeys - i), length));
            }
        }
        
        return batches;
    }

    generateKeys(offset, count, length) {
        const keys = [];
        const alphabetSize = this.alphabet.length;
        
        for (let i = 0; i < count; i++) {
            let key = '';
            let num = offset + i;
            
            for (let j = 0; j < length; j++) {
                const index = num % alphabetSize;
                key = this.alphabet[index] + key;
                num = Math.floor(num / alphabetSize);
            }
            
            keys.push(key);
        }
        
        return keys;
    }

    async processBatches(batches) {
        return new Promise((resolve, reject) => {
            this.currentTask.resolve = resolve;
            this.currentTask.reject = reject;
            this.currentTask.pendingBatches = batches.length;
            this.currentTask.results = [];
            
            batches.forEach((batch, i) => {
                const worker = this.workers[i % this.workers.length];
                
                worker.onmessage = (e) => this.handleWorkerMessage(e);
                
                worker.postMessage({
                    type: 'PROCESS',
                    batch,
                    ciphertext: this.currentTask.ciphertext,
                    knownPlaintext: this.currentTask.options.knownPlaintext,
                    scoringMethod: this.currentTask.options.scoringMethod
                });
            });
        });
    }

    handleWorkerMessage(e) {
        const { type, data } = e.data;
        
        switch (type) {
            case 'PROGRESS':
                this.keysTested += data.processed;
                this.updateProgress();
                break;
                
            case 'RESULT':
                this.keysTested += data.processed;
                this.currentTask.results.push(...data.results);
                this.currentTask.pendingBatches--;
                this.updateProgress();
                
                if (this.currentTask.pendingBatches === 0) {
                    this.currentTask.resolve(this.currentTask.results);
                }
                break;
                
            case 'ERROR':
                this.currentTask.reject(new Error(data.message));
                break;
        }
    }

    handleWorkerError(e) {
        console.error('Worker error:', e);
        if (this.currentTask) {
            this.currentTask.reject(new Error('Worker crashed'));
        }
    }

    updateProgress() {
        const elapsed = (performance.now() - this.startTime) / 1000;
        const keysPerSecond = this.keysTested / elapsed;
        const progress = (this.keysTested / this.totalKeys) * 100;
        
        // Здесь можно обновлять UI с прогрессом
        console.log(`Progress: ${progress.toFixed(2)}% | Speed: ${keysPerSecond.toFixed(0)} keys/sec`);
    }

    sortResults(results) {
        return results.sort((a, b) => b.score - a.score);
    }

    terminateWorkers() {
        this.workers.forEach(worker => {
            try {
                worker.terminate();
            } catch (e) {
                console.error('Error terminating worker:', e);
            }
        });
        this.workers = [];
    }

    stop() {
        if (this.isRunning) {
            this.terminateWorkers();
            this.isRunning = false;
            return true;
        }
        return false;
    }
}

// Интеграция с UI
document.addEventListener('DOMContentLoaded', () => {
    const cracker = new VigenereCracker();
    const startBtn = document.getElementById('crack-btn');
    const stopBtn = document.getElementById('stop-btn');
    
    startBtn.addEventListener('click', async () => {
        try {
            const ciphertext = document.getElementById('ciphertext-to-crack').value;
            const options = {
                maxKeyLength: parseInt(document.getElementById('key-length').value),
                workersCount: parseInt(document.getElementById('workers-count').value),
                batchSize: parseInt(document.getElementById('batch-size').value),
                knownPlaintext: document.getElementById('known-plaintext').value,
                scoringMethod: document.getElementById('scoring-method').value
            };
            
            startBtn.disabled = true;
            stopBtn.disabled = false;
            
            const results = await cracker.crack(ciphertext, options);
            displayResults(results);
            
        } catch (error) {
            console.error('Cracking failed:', error);
            alert(`Error: ${error.message}`);
        } finally {
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    });
    
    stopBtn.addEventListener('click', () => {
        if (cracker.stop()) {
            console.log('Cracking stopped');
        }
    });
    
    function displayResults(results) {
        const container = document.getElementById('results-container');
        container.innerHTML = '';
        
        results.slice(0, 10).forEach((result, i) => {
            const div = document.createElement('div');
            div.className = 'result-item';
            div.innerHTML = `
                <h4>Result ${i + 1}</h4>
                <p>Key: <strong>${result.key}</strong> (Score: ${result.score.toFixed(2)})</p>
                <div class="plaintext">${result.plaintext}</div>
            `;
            container.appendChild(div);
        });
    }
});
