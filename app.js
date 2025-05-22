class VigenereAnalyzer {
    constructor() {
        this.workers = [];
        this.isProcessing = false;
        this.totalKeys = 0;
        this.keysTested = 0;
        this.startTime = 0;
        this.topResults = [];
        this.progressUpdateInterval = null;

        // Инициализация элементов UI
        this.ciphertextEl = document.getElementById('ciphertext');
        this.keyEl = document.getElementById('key');
        this.alphabetEl = document.getElementById('alphabet');
        this.knownFragmentEl = document.getElementById('known-fragment');
        this.bruteBtn = document.getElementById('brute-btn');
        this.stopBtn = document.getElementById('stop-btn');
        this.progressBar = document.querySelector('.progress-bar .progress');
        this.progressText = document.getElementById('progress');
        this.speedText = document.getElementById('speed');
        this.resultText = document.getElementById('result-text');
        this.topKeysBody = document.querySelector('#top-keys tbody');

        // Привязка событий
        this.bruteBtn.addEventListener('click', () => this.startBruteForce());
        this.stopBtn.addEventListener('click', () => this.stopProcessing());
    }

    // Основной метод запуска брутфорса
    async startBruteForce() {
        if (this.isProcessing) return;
        
        const params = {
            ciphertext: this.ciphertextEl.value.toUpperCase(),
            alphabet: this.alphabetEl.value.toUpperCase(),
            knownFragment: this.knownFragmentEl.value.toUpperCase(),
            maxKeyLength: 10
        };

        if (!this.validateInput(params)) return;

        this.initializeProcessing(params);
        this.createWorkers(params);
        this.startProgressUpdater();
    }

    // Валидация входных данных
    validateInput({ ciphertext, alphabet }) {
        if (!ciphertext) {
            this.showError('Введите шифротекст!');
            return false;
        }
        
        const uniqueChars = [...new Set(alphabet)];
        if (uniqueChars.length < 2) {
            this.showError('Алфавит должен содержать минимум 2 уникальных символа!');
            return false;
        }
        
        return true;
    }

    // Инициализация параметров обработки
    initializeProcessing({ alphabet, maxKeyLength }) {
        this.isProcessing = true;
        this.keysTested = 0;
        this.totalKeys = this.calculateTotalKeys(alphabet.length, maxKeyLength);
        this.startTime = performance.now();
        this.topResults = [];
        this.updateUI(true);
    }

    // Создание Web Workers
    createWorkers({ ciphertext, alphabet, knownFragment, maxKeyLength }) {
        const workerCount = navigator.hardwareConcurrency || 4;
        const keysPerWorker = Math.ceil(this.totalKeys / workerCount);

        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker('worker.js');
            
            worker.onmessage = (e) => this.handleWorkerMessage(e.data);
            
            worker.postMessage({
                type: 'start',
                id: i,
                ciphertext,
                alphabet,
                knownFragment,
                maxKeyLength,
                startIdx: i * keysPerWorker,
                endIdx: (i + 1) * keysPerWorker
            });

            this.workers.push(worker);
        }
    }

    // Обработка сообщений от воркеров
    handleWorkerMessage(data) {
        switch (data.type) {
            case 'progress':
                this.keysTested += data.keysProcessed;
                break;
                
            case 'result':
                this.handleResult(data.key, data.score, data.fragment);
                break;
                
            case 'error':
                this.handleError(data.message);
                break;
        }
    }

    // Обработка новых результатов
    handleResult(key, score, fragment) {
        this.topResults.push({ key, score, fragment });
        this.topResults.sort((a, b) => b.score - a.score);
        this.topResults = this.topResults.slice(0, 10);
        this.updateResultsTable();

        if (score > 0.75) {
            this.resultText.textContent = fragment;
            this.keyEl.value = key;
        }
    }

    // Обновление таблицы с топовыми ключами
    updateResultsTable() {
        this.topKeysBody.innerHTML = this.topResults
            .map((res, idx) => `
                <tr>
                    <td>${idx + 1}</td>
                    <td>${res.key}</td>
                    <td>${res.score.toFixed(2)}</td>
                    <td>${res.fragment.substring(0, 30)}${res.fragment.length > 30 ? '...' : ''}</td>
                </tr>
            `).join('');
    }

    // Запуск обновления прогресса
    startProgressUpdater() {
        this.progressUpdateInterval = setInterval(() => {
            const elapsed = (performance.now() - this.startTime) / 1000;
            const speed = (this.keysTested / elapsed).toFixed(0);
            const progress = (this.keysTested / this.totalKeys * 100).toFixed(2);

            this.progressBar.style.width = `${progress}%`;
            this.progressText.textContent = `${progress}%`;
            this.speedText.textContent = `${speed} keys/sec`;

            if (speed > 0) {
                const remaining = (this.totalKeys - this.keysTested) / speed;
                document.getElementById('time').textContent = 
                    `Осталось: ${this.formatTime(remaining)}`;
            }
        }, 1000);
    }

    // Остановка обработки
    stopProcessing() {
        this.isProcessing = false;
        clearInterval(this.progressUpdateInterval);
        this.workers.forEach(w => w.terminate());
        this.workers = [];
        this.updateUI(false);
    }

    // Вспомогательные методы
    calculateTotalKeys(alphabetSize, maxLength) {
        return Array.from({ length: maxLength }, (_, i) => 
            Math.pow(alphabetSize, i + 1)
        ).reduce((a, b) => a + b, 0);
    }

    formatTime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        return [h > 0 ? `${h}ч` : '', m > 0 ? `${m}м` : '', `${s}с`].filter(Boolean).join(' ');
    }

    updateUI(processing) {
        this.bruteBtn.disabled = processing;
        this.stopBtn.disabled = !processing;
        document.querySelector('.progress-section').style.display = 
            processing ? 'block' : 'none';
    }

    showError(message) {
        alert(`Ошибка: ${message}`);
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => new VigenereAnalyzer());
