class VigenereCipher {
    constructor(alphabet) {
        this.alphabet = alphabet.toUpperCase();
        this.alphabetMap = {};
        
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetMap[this.alphabet[i]] = i;
        }
    }
    
    decrypt(ciphertext, key) {
        let result = '';
        const keyUpper = key.toUpperCase();
        let keyIndex = 0;
        
        for (let i = 0; i < ciphertext.length; i++) {
            const char = ciphertext[i];
            const upperChar = char.toUpperCase();
            
            if (this.alphabetMap[upperChar] !== undefined) {
                const textPos = this.alphabetMap[upperChar];
                const keyPos = this.alphabetMap[keyUpper[keyIndex % keyUpper.length]];
                const newPos = (textPos - keyPos + this.alphabet.length) % this.alphabet.length;
                
                let newChar = this.alphabet[newPos];
                if (char === char.toLowerCase()) {
                    newChar = newChar.toLowerCase();
                }
                
                result += newChar;
                keyIndex++;
            } else {
                result += char;
            }
        }
        
        return result;
    }
}

class TextScorer {
    constructor() {
        this.quadgrams = this.loadQuadgrams();
        this.cache = new Map();
    }
    
    loadQuadgrams() {
        return {
            'TION': 0.0314, 'THER': 0.0267, 'NTHE': 0.0263, 'THAT': 0.0253,
            'OFTH': 0.0246, 'FTHE': 0.0244, 'THES': 0.0234, 'WITH': 0.0232,
            'INTH': 0.0213, 'ATIO': 0.0208, 'OTHE': 0.0206, 'TTHA': 0.0198,
            'NDTH': 0.0196, 'ETHE': 0.0194, 'TOTH': 0.0189, 'DTHE': 0.0187,
            'INGT': 0.0185, 'INGA': 0.0183, 'OFTH': 0.0181, 'REQU': 0.0179
        };
    }
    
    score(text, method) {
        const cacheKey = `${method}_${text}`;
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }
        
        const normalized = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (normalized.length < 4) {
            return -Infinity;
        }
        
        let score = 0;
        if (method === 'quadgrams') {
            for (let i = 0; i < normalized.length - 3; i++) {
                const quadgram = normalized.substr(i, 4);
                score += Math.log10(this.quadgrams[quadgram] || 1e-10);
            }
        }
        
        if (this.cache.size < 10000) {
            this.cache.set(cacheKey, score);
        }
        
        return score;
    }
    
    checkMemory() {
        if (typeof performance !== 'undefined' && performance.memory) {
            const used = performance.memory.usedJSHeapSize;
            const limit = performance.memory.jsHeapSizeLimit;
            return (used / limit) * 100;
        }
        return 0;
    }
}

let cipher;
let scorer;

function processBatch(batch, ciphertext, knownPlaintext, scoringMethod) {
    const results = [];
    let processed = 0;
    
    for (const key of batch) {
        try {
            // Проверка памяти каждые 100 ключей
            if (processed > 0 && processed % 100 === 0 && scorer.checkMemory() > 85) {
                scorer.cache.clear();
                self.postMessage({
                    type: 'WARNING',
                    message: 'Memory threshold exceeded, cache cleared'
                });
            }
            
            const decrypted = cipher.decrypt(ciphertext, key);
            
            if (knownPlaintext && !decrypted.includes(knownPlaintext)) {
                processed++;
                continue;
            }
            
            const score = scorer.score(decrypted, scoringMethod);
            
            if (score > -Infinity) {
                results.push({ key, plaintext: decrypted, score });
            }
            
            processed++;
            
            // Отчет о прогрессе каждые 50 ключей
            if (processed % 50 === 0) {
                self.postMessage({
                    type: 'PROGRESS',
                    processed
                });
            }
        } catch (error) {
            console.error(`Error processing key ${key}:`, error);
            processed++;
        }
    }
    
    return { results, processed };
}

self.onmessage = function(e) {
    const { type, data } = e.data;
    
    try {
        switch (type) {
            case 'INIT':
                cipher = new VigenereCipher(data.alphabet);
                scorer = new TextScorer();
                self.postMessage({ type: 'READY' });
                break;
                
            case 'PROCESS':
                const result = processBatch(
                    data.batch,
                    data.ciphertext,
                    data.knownPlaintext,
                    data.scoringMethod
                );
                
                self.postMessage({
                    type: 'RESULT',
                    data: result
                });
                break;
                
            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (error) {
        self.postMessage({
            type: 'ERROR',
            error: {
                message: error.message,
                stack: error.stack
            }
        });
    }
};

self.onerror = function(error) {
    self.postMessage({
        type: 'FATAL_ERROR',
        error: {
            message: 'Worker fatal error',
            stack: error.message
        }
    });
    return true; // Предотвращаем вывод ошибки в консоль
};
