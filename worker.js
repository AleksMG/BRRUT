class CipherWorker {
    constructor() {
        this.commonWords = new Set(['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT']);
        this.lastUpdate = 0;
    }

    // Основной метод обработки
    process(data) {
        try {
            this.initialize(data);
            return this.bruteForce();
        } catch (error) {
            self.postMessage({ type: 'error', message: error.toString() });
            return [];
        }
    }

    // Инициализация параметров
    initialize({ ciphertext, alphabet, knownFragment, maxKeyLength, startIdx, endIdx }) {
        this.ciphertext = ciphertext;
        this.alphabet = [...alphabet];
        this.knownFragment = knownFragment;
        this.maxKeyLength = maxKeyLength;
        this.startIdx = startIdx;
        this.endIdx = endIdx;
        this.keysProcessed = 0;
        
        if (this.alphabet.length < 2) {
            throw new Error('Неверный алфавит');
        }
    }

    // Основной цикл перебора
    bruteForce() {
        const results = [];
        
        for (let idx = this.startIdx; idx < this.endIdx; idx++) {
            const key = this.generateKey(idx);
            const decrypted = this.decrypt(this.ciphertext, key);
            const score = this.calculateScore(decrypted);
            
            if (score > 0.5) {
                results.push({ 
                    key, 
                    score,
                    fragment: decrypted.substring(0, 50) 
                });
            }
            
            this.updateProgress();
        }
        
        return results;
    }

    // Генерация ключа по индексу
    generateKey(index) {
        let key = '';
        let remaining = index;
        
        for (let len = 1; len <= this.maxKeyLength; len++) {
            const maxKeys = Math.pow(this.alphabet.length, len);
            
            if (remaining < maxKeys) {
                for (let i = 0; i < len; i++) {
                    const charIndex = remaining % this.alphabet.length;
                    key = this.alphabet[charIndex] + key;
                    remaining = Math.floor(remaining / this.alphabet.length);
                }
                return key;
            }
            remaining -= maxKeys;
        }
        return '';
    }

    // Дешифровка текста
    decrypt(text, key) {
        let result = '';
        const keyLength = key.length;
        
        for (let i = 0; i < text.length; i++) {
            const textChar = text[i];
            const keyChar = key[i % keyLength];
            
            const textIndex = this.alphabet.indexOf(textChar);
            const keyIndex = this.alphabet.indexOf(keyChar);
            
            if (textIndex === -1 || keyIndex === -1) {
                result += textChar;
                continue;
            }
            
            let decryptedIndex = (textIndex - keyIndex + this.alphabet.length) % this.alphabet.length;
            result += this.alphabet[decryptedIndex];
        }
        return result;
    }

    // Оценка качества расшифровки
    calculateScore(text) {
        let score = 0;
        
        // Совпадение известного фрагмента
        if (this.knownFragment) {
            const pos = text.indexOf(this.knownFragment);
            if (pos !== -1) {
                score += 0.6 - (pos / text.length);
            }
        }
        
        // Частотный анализ
        score += this.calculateFrequencyScore(text) * 0.3;
        
        // Поиск общих слов
        score += this.calculateCommonWordsScore(text) * 0.2;
        
        return Math.min(score, 1.0);
    }

    // Расчет частотного анализа
    calculateFrequencyScore(text) {
        const freqMap = new Map();
        for (const char of text) {
            freqMap.set(char, (freqMap.get(char) || 0) + 1);
        }
        
        let entropy = 0;
        for (const [char, count] of freqMap) {
            const p = count / text.length;
            entropy -= p * Math.log2(p);
        }
        
        return entropy / 5;
    }

    // Расчет совпадения общих слов
    calculateCommonWordsScore(text) {
        const words = text.toUpperCase().split(/[\s,.!?]+/);
        const matches = words.filter(w => this.commonWords.has(w)).length;
        return matches / words.length;
    }

    // Обновление прогресса
    updateProgress() {
        this.keysProcessed++;
        
        if (Date.now() - this.lastUpdate > 500) {
            self.postMessage({ 
                type: 'progress', 
                keysProcessed: this.keysProcessed 
            });
            this.lastUpdate = Date.now();
        }
    }
}

// Обработчик сообщений
self.onmessage = (e) => {
    const worker = new CipherWorker();
    const results = worker.process(e.data);
    
    results.forEach(result => {
        self.postMessage({
            type: 'result',
            key: result.key,
            score: result.score,
            fragment: result.fragment
        });
    });
};
