// worker.js - Полностью переработанная версия
class CipherWorker {
  constructor() {
    this.commonWords = new Set([
      'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'ANY', 'CAN',
      'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS'
    ]);
    
    this.strategies = {
      MUTATION: 'mutation',
      RANDOM: 'random',
      PATTERN: 'pattern'
    };
  }

  initialize(params) {
    this.ciphertext = params.ciphertext;
    this.alphabet = params.alphabet;
    this.knownFragment = params.knownFragment;
    this.maxKeyLength = params.maxKeyLength;
    this.batchSize = params.batchSize;
    this.startKeyIndex = params.startKeyIndex;
    this.endKeyIndex = params.endKeyIndex;
    this.alphabetSize = params.alphabetSize;
    this.totalPossibleKeys = params.totalPossibleKeys;
    
    this.currentStrategy = this.selectBestStrategy();
  }

  selectBestStrategy() {
    if (this.knownFragment) return this.strategies.PATTERN;
    if (this.alphabetSize <= 26) return this.strategies.MUTATION;
    return this.strategies.RANDOM;
  }

  // Основной метод обработки
  async process() {
    let results = [];
    
    switch(this.currentStrategy) {
      case this.strategies.MUTATION:
        results = this.processMutationBatch();
        break;
        
      case this.strategies.RANDOM:
        results = this.processRandomBatch();
        break;
        
      case this.strategies.PATTERN:
        results = this.processPatternBatch();
        break;
    }
    
    return this.postProcess(results);
  }

  processMutationBatch() {
    const results = [];
    const baseKey = this.generateBaseKey();
    
    for (let i = 0; i < this.batchSize; i++) {
      const mutatedKey = this.mutateKey(baseKey);
      const { score, decrypted } = this.analyzeKey(mutatedKey);
      
      if (score > 0.4) {
        results.push({ 
          key: mutatedKey,
          score,
          decryptedFragment: decrypted.slice(0, 50)
        });
      }
    }
    
    return results;
  }

  processRandomBatch() {
    const results = [];
    
    for (let i = 0; i < this.batchSize; i++) {
      const key = this.generateRandomKey();
      const { score, decrypted } = this.analyzeKey(key);
      
      if (score > 0.3) {
        results.push({
          key,
          score,
          decryptedFragment: decrypted.slice(0, 50)
        });
      }
    }
    
    return results;
  }

  processPatternBatch() {
    const results = [];
    const pattern = this.analyzePattern();
    
    for (let i = 0; i < this.batchSize; i++) {
      const key = this.generatePatternKey(pattern, i);
      const { score, decrypted } = this.analyzeKey(key);
      
      if (score > 0.6) {
        results.push({
          key,
          score,
          decryptedFragment: decrypted.slice(0, 50)
        });
      }
    }
    
    return results;
  }

  // Генерация ключей
  generateBaseKey() {
    const length = Math.floor(Math.random() * this.maxKeyLength) + 1;
    return Array.from({length}, () => 
      this.alphabet[Math.floor(Math.random() * this.alphabetSize)]
    ).join('');
  }

  mutateKey(baseKey) {
    const mutations = [
      () => baseKey.slice(1) + baseKey[0], // Циклический сдвиг
      () => baseKey.split('').reverse().join(''), // Реверс
      () => baseKey + this.alphabet[Math.floor(Math.random() * this.alphabetSize)], // Добавление символа
      () => baseKey.replace(/.$/, '') // Удаление символа
    ];
    
    return mutations[Math.floor(Math.random() * mutations.length)]();
  }

  generateRandomKey() {
    const length = Math.floor(Math.random() * this.maxKeyLength) + 1;
    return Array.from({length}, () => 
      this.alphabet[Math.floor(Math.random() * this.alphabetSize)]
    ).join('');
  }

  // Анализ и оценка
  analyzeKey(key) {
    const decrypted = this.vigenereDecrypt(this.ciphertext, key);
    return {
      score: this.calculateScore(decrypted),
      decrypted
    };
  }

  calculateScore(text) {
    let score = 0;
    
    // 1. Совпадение известного фрагмента
    if (this.knownFragment) {
      const pos = text.indexOf(this.knownFragment);
      if (pos !== -1) {
        score += 0.5 + (1 - pos/text.length);
      }
    }
    
    // 2. Частотный анализ
    score += this.calculateFrequencyScore(text) * 0.3;
    
    // 3. Границы слов
    score += this.calculateWordBoundaryScore(text) * 0.2;
    
    return Math.min(score, 1.0);
  }

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
    
    return entropy / 5; // Нормализация
  }

  // Дешифровка
  vigenereDecrypt(ciphertext, key) {
    let decrypted = '';
    let keyIndex = 0;
    
    for (let i = 0; i < ciphertext.length; i++) {
      const cipherChar = ciphertext[i];
      const cipherPos = this.alphabet.indexOf(cipherChar);
      
      if (cipherPos === -1) {
        decrypted += cipherChar;
        continue;
      }
      
      const keyChar = key[keyIndex % key.length];
      const keyPos = this.alphabet.indexOf(keyChar);
      let decryptedPos = (cipherPos - keyPos) % this.alphabetSize;
      
      if (decryptedPos < 0) decryptedPos += this.alphabetSize;
      decrypted += this.alphabet[decryptedPos];
      
      keyIndex++;
    }
    
    return decrypted;
  }

  // Взаимодействие с основным потоком
  postProcess(results) {
    return results.sort((a, b) => b.score - a.score)
                  .slice(0, 10);
  }
}

// Обработчик сообщений
self.onmessage = async ({ data }) => {
  const worker = new CipherWorker();
  worker.initialize(data);
  
  const results = await worker.process();
  
  self.postMessage({
    type: 'results',
    batch: results,
    processed: data.batchSize
  });
};
