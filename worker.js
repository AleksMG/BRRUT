// Конфигурационные константы
const CONFIG = {
  MAX_MEMORY_PERCENT: 85, // Максимальное использование памяти
  BATCH_REPORT_SIZE: 100, // Частота отчетов о прогрессе
  CACHE_MAX_SIZE: 10000,  // Максимальный размер кэша
  SAFE_KEY_LIMIT: 500     // Лимит ключей перед проверкой памяти
};

// Глобальные переменные worker'а
let workerState = {
  isInitialized: false,
  cipher: null,
  analyzer: null,
  currentTask: null,
  cache: new Map(),
  cacheHits: 0,
  cacheMisses: 0
};

// Инициализация worker'а
function initWorker(alphabet) {
  workerState.cipher = new VigenereCipher(alphabet);
  workerState.analyzer = new TextAnalyzer();
  workerState.isInitialized = true;
  
  return {
    status: 'READY',
    alphabet: alphabet,
    memory: checkMemoryUsage()
  };
}

// Проверка использования памяти
function checkMemoryUsage() {
  if (typeof performance !== 'undefined' && performance.memory) {
    const usedMB = performance.memory.usedJSHeapSize / (1024 * 1024);
    const totalMB = performance.memory.jsHeapSizeLimit / (1024 * 1024);
    return {
      used: usedMB,
      total: totalMB,
      percent: (usedMB / totalMB) * 100
    };
  }
  return null;
}

// Очистка кэша при нехватке памяти
function clearCacheIfNeeded() {
  const memory = checkMemoryUsage();
  if (memory && memory.percent > CONFIG.MAX_MEMORY_PERCENT) {
    workerState.cache.clear();
    return true;
  }
  return false;
}

// Обработка пакета ключей
function processKeyBatch(batch, ciphertext, knownPlaintext, scoringMethod) {
  const results = [];
  let processed = 0;
  
  for (const key of batch) {
    try {
      // Проверка памяти каждые N ключей
      if (processed > 0 && processed % CONFIG.SAFE_KEY_LIMIT === 0) {
        if (clearCacheIfNeeded()) {
          postMessage({
            type: 'WARNING',
            message: 'Memory threshold exceeded, cache cleared'
          });
        }
      }

      // Дешифровка
      const decrypted = workerState.cipher.decrypt(ciphertext, key);
      
      // Проверка известного текста
      if (knownPlaintext && !decrypted.includes(knownPlaintext)) {
        processed++;
        continue;
      }

      // Оценка текста
      const score = workerState.analyzer.score(decrypted, scoringMethod);
      
      if (score > -Infinity) {
        results.push({ key, plaintext: decrypted, score });
      }

      processed++;

      // Отчет о прогрессе
      if (processed % CONFIG.BATCH_REPORT_SIZE === 0) {
        postMessage({
          type: 'PROGRESS',
          processed,
          total: batch.length
        });
      }
    } catch (error) {
      console.error(`Error processing key ${key}:`, error);
      processed++;
    }
  }

  return { results, processed };
}

// Класс для шифрования/дешифрования
class VigenereCipher {
  constructor(alphabet) {
    this.alphabet = alphabet.toUpperCase();
    this.alphabetMap = this.createAlphabetMap();
  }

  createAlphabetMap() {
    const map = {};
    for (let i = 0; i < this.alphabet.length; i++) {
      map[this.alphabet[i]] = i;
    }
    return map;
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

// Класс для анализа текста
class TextAnalyzer {
  constructor() {
    this.quadgrams = this.loadQuadgrams();
  }

  loadQuadgrams() {
    return {
      'TION': 0.0314, 'THER': 0.0267, 'NTHE': 0.0263, 'THAT': 0.0253,
      // ... другие квадграммы ...
    };
  }

  score(text, method) {
    const cacheKey = `${method}_${text}`;
    
    if (workerState.cache.has(cacheKey)) {
      workerState.cacheHits++;
      return workerState.cache.get(cacheKey);
    }

    workerState.cacheMisses++;
    const normalizedText = text.toUpperCase().replace(/[^A-Z]/g, '');
    
    if (normalizedText.length < 4) {
      return -Infinity;
    }

    let score = 0;

    if (method === 'quadgrams') {
      for (let i = 0; i < normalizedText.length - 3; i++) {
        const quadgram = normalizedText.substr(i, 4);
        score += Math.log10(this.quadgrams[quadgram] || 1e-10);
      }
    }

    if (workerState.cache.size < CONFIG.CACHE_MAX_SIZE) {
      workerState.cache.set(cacheKey, score);
    }

    return score;
  }
}

// Обработчик сообщений
self.onmessage = function(e) {
  const { type, taskId, data } = e.data;

  try {
    switch (type) {
      case 'INIT':
        const initResult = initWorker(data.alphabet);
        self.postMessage({
          type: 'INIT_RESULT',
          taskId,
          data: initResult
        });
        break;

      case 'PROCESS_BATCH':
        if (!workerState.isInitialized) {
          throw new Error('Worker not initialized');
        }

        const { batch, ciphertext, knownPlaintext, scoringMethod } = data;
        const result = processKeyBatch(batch, ciphertext, knownPlaintext, scoringMethod);
        
        self.postMessage({
          type: 'BATCH_RESULT',
          taskId,
          data: {
            ...result,
            cacheStats: {
              hits: workerState.cacheHits,
              misses: workerState.cacheMisses,
              size: workerState.cache.size
            },
            memory: checkMemoryUsage()
          }
        });
        break;

      case 'RESET':
        workerState.cache.clear();
        workerState.cacheHits = 0;
        workerState.cacheMisses = 0;
        self.postMessage({
          type: 'RESET_RESULT',
          taskId
        });
        break;

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  } catch (error) {
    console.error('Worker error:', error);
    self.postMessage({
      type: 'ERROR',
      taskId,
      error: {
        message: error.message,
        stack: error.stack
      }
    });
  }
};

// Обработка ошибок
self.addEventListener('error', function(e) {
  console.error('Unhandled worker error:', e);
  self.postMessage({
    type: 'FATAL_ERROR',
    error: {
      message: e.message,
      stack: e.error?.stack
    }
  });
});
