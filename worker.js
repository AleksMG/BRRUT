const commonWords = new Set([
    'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'ANY', 'CAN',
    'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS',
    'HOW', 'MAN', 'NEW', 'NOW', 'OLD', 'SEE', 'TWO', 'WAY', 'WHO', 'BOY',
    'DID', 'ITS', 'LET', 'PUT', 'SAY', 'SHE', 'TOO', 'USE', 'THAT', 'WITH',
    'THIS', 'FROM', 'YOUR', 'HAVE', 'MORE', 'WILL', 'HOME', 'ABOUT', 'OTHER',
    'WHICH', 'THEIR', 'THERE', 'WOULD', 'THINK', 'WHEN', 'MAKE', 'LIKE', 'TIME',
    'JUST', 'KNOW', 'PEOPLE', 'INTO', 'YEAR', 'GOOD', 'SOME', 'COULD', 'THEM',
    'SEE', 'OTHER', 'THAN', 'THEN', 'LOOK', 'ONLY', 'COME', 'OVER', 'THINK',
    'ALSO', 'BACK', 'AFTER', 'USED', 'TWO', 'HOW', 'OUR', 'WORK', 'FIRST',
    'WELL', 'WAY', 'EVEN', 'NEW', 'WANT', 'BECAUSE', 'ANY', 'THESE', 'GIVE',
    'MOST'
]);

self.onmessage = function(e) {
    const data = e.data;
    if (data.type === 'start') startBruteForce(data);
};

function startBruteForce(params) {
    const {
        ciphertext,
        alphabet,
        knownFragment,
        maxKeyLength,
        batchSize,
        startKeyIndex,
        endKeyIndex,
        alphabetSize,
        totalPossibleKeys
    } = params;
    
    let keysTested = 0;
    let totalKeysTested = 0;
    let lastReportTime = performance.now();
    
    for (let keyIndex = startKeyIndex; keyIndex < endKeyIndex; keyIndex += batchSize) {
        if (performance.now() - lastReportTime > 100) {
            self.postMessage({
                type: 'progress',
                keysTested,
                totalKeysTested: keyIndex - startKeyIndex
            });
            keysTested = 0;
            lastReportTime = performance.now();
        }
        
        const batchEnd = Math.min(keyIndex + batchSize, endKeyIndex);
        const batchResults = processKeyBatch(
            ciphertext,
            alphabet,
            knownFragment,
            maxKeyLength,
            keyIndex,
            batchEnd,
            alphabetSize
        );
        
        keysTested += batchEnd - keyIndex;
        totalKeysTested += batchEnd - keyIndex;
        
        batchResults.forEach(result => {
            self.postMessage({
                type: 'result',
                key: result.key,
                score: result.score,
                decryptedFragment: result.decryptedFragment
            });
        });
    }
    
    self.postMessage({
        type: 'complete',
        totalKeysTested
    });
}

function processKeyBatch(ciphertext, alphabet, knownFragment, maxKeyLength, startKeyIndex, endKeyIndex, alphabetSize) {
    const results = [];
    
    for (let keyNum = startKeyIndex; keyNum < endKeyIndex; keyNum++) {
        const key = generateKeyFromIndex(keyNum, alphabet, maxKeyLength, alphabetSize);
        if (key.length > maxKeyLength) continue;
        
        const decrypted = vigenereDecrypt(ciphertext, key, alphabet);
        const score = scoreDecryptedText(decrypted, knownFragment);
        
        if (score > 0.5) {
            results.push({
                key,
                score,
                decryptedFragment: decrypted.substring(0, Math.min(30, decrypted.length))
            });
        }
    }
    
    return results;
}

function generateKeyFromIndex(index, alphabet, maxKeyLength, alphabetSize) {
    let remaining = index;
    let key = '';
    
    for (let len = 1; len <= maxKeyLength; len++) {
        const keysOfLength = Math.pow(alphabetSize, len);
        
        if (remaining < keysOfLength) {
            for (let i = 0; i < len; i++) {
                const pos = remaining % alphabetSize;
                key = alphabet[pos] + key;
                remaining = Math.floor(remaining / alphabetSize);
            }
            return key;
        }
        remaining -= keysOfLength;
    }
    return '';
}

function vigenereDecrypt(ciphertext, key, alphabet) {
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
        if (decryptedIndex < 0) decryptedIndex += alphabetSize;
        
        decryptedText += alphabet[decryptedIndex];
        keyIndex++;
    }
    
    return decryptedText;
}

function scoreDecryptedText(text, knownFragment) {
    let score = 0;
    const textLower = text.toLowerCase();
    
    if (knownFragment) {
        const fragmentLower = knownFragment.toLowerCase();
        const pos = textLower.indexOf(fragmentLower);
        if (pos > -1) {
            const positionBonus = (1 - pos/text.length) * 0.3;
            const exactMatchBonus = text.substr(pos, knownFragment.length) === knownFragment ? 0.2 : 0;
            score += 0.5 + positionBonus + exactMatchBonus;
        }
    }

    score += calculateAdvancedFreqScore(text) * 0.4;
    score += calculateWordBoundaryScore(text) * 0.2;
    score += calculateCommonWordsScore(textLower) * 0.3;
    
    return Math.min(score, 1.0);
}

function calculateAdvancedFreqScore(text) {
    const charCounts = {};
    const total = text.length;
    
    for (const c of text) charCounts[c] = (charCounts[c] || 0) + 1;
    
    let entropy = 0;
    for (const c in charCounts) {
        const p = charCounts[c]/total;
        entropy -= p * Math.log2(p);
    }
    
    return Math.min(entropy / 4, 1);
}

function calculateWordBoundaryScore(text) {
    const wordSeparators = [' ', '.', ',', '!', '?', ';', ':'];
    let boundaryCount = 0;
    
    for (let i=1; i<text.length; i++) {
        const prev = text[i-1];
        const curr = text[i];
        if (wordSeparators.includes(curr) && !wordSeparators.includes(prev)) {
            boundaryCount++;
        }
    }
    
    return boundaryCount / (text.length / 10);
}

function calculateCommonWordsScore(text) {
    const words = text.split(/[\s\.\?,!;:]+/).filter(w => w.length >= 3);
    if (words.length === 0) return 0;
    
    let matches = 0;
    for (const word of words) {
        if (commonWords.has(word.toUpperCase())) matches++;
    }
    
    return matches / words.length;
}
