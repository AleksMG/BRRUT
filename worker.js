// Worker for parallel Vigenère cipher brute force decryption

// English letter frequencies (for scoring)
const englishFrequencies = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
    'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
    'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
    'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074
};

// Common English words for scoring
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
    
    switch (data.type) {
        case 'start':
            startBruteForce(data);
            break;
    }
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
    
    // Generate keys in batches
    for (let keyIndex = startKeyIndex; keyIndex < endKeyIndex; keyIndex += batchSize) {
        if (performance.now() - lastReportTime > 100) {
            // Report progress
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
        
        // Send any good results back
        batchResults.forEach(result => {
            self.postMessage({
                type: 'result',
                key: result.key,
                score: result.score,
                decryptedFragment: result.decryptedFragment
            });
        });
    }
    
    // Signal completion
    self.postMessage({
        type: 'complete',
        totalKeysTested
    });
}

function processKeyBatch(ciphertext, alphabet, knownFragment, maxKeyLength, startKeyIndex, endKeyIndex, alphabetSize) {
    const results = [];
    
    for (let keyNum = startKeyIndex; keyNum < endKeyIndex; keyNum++) {
        const key = generateKeyFromIndex(keyNum, alphabet, maxKeyLength, alphabetSize);
        
        // Skip keys that are too long
        if (key.length > maxKeyLength) continue;
        
        // Decrypt with this key
        const decrypted = vigenereDecrypt(ciphertext, key, alphabet);
        
        // Score the decrypted text
        const score = scoreDecryptedText(decrypted, knownFragment);
        
        // If score is above threshold, add to results
        if (score > 0.5) {
            const fragment = decrypted.substring(0, Math.min(30, decrypted.length));
            results.push({
                key,
                score,
                decryptedFragment: fragment
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
            // Generate the key of this length
            for (let i = 0; i < len; i++) {
                const pos = remaining % alphabetSize;
                key = alphabet[pos] + key;
                remaining = Math.floor(remaining / alphabetSize);
            }
            return key;
        }
        
        remaining -= keysOfLength;
    }
    
    return ''; // Shouldn't reach here if indexes are correct
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
        if (decryptedIndex < 0) {
            decryptedIndex += alphabetSize;
        }
        
        decryptedText += alphabet[decryptedIndex];
        keyIndex++;
    }
    
    return decryptedText;
}

function scoreDecryptedText(text, knownFragment) {
    let score = 0;
    
    // Check for known fragment
    if (knownFragment && text.includes(knownFragment)) {
        score += 0.5; // Bonus for matching known fragment
    }
    
    // Score based on letter frequencies
    const upperText = text.toUpperCase();
    const charCounts = {};
    let totalLetters = 0;
    
    // Count letter frequencies
    for (const char of upperText) {
        if (/[A-Z]/.test(char)) {
            charCounts[char] = (charCounts[char] || 0) + 1;
            totalLetters++;
        }
    }
    
    // Compare to English frequencies
    if (totalLetters > 0) {
        let freqScore = 0;
        for (const char in charCounts) {
            const freq = charCounts[char] / totalLetters;
            const expectedFreq = englishFrequencies[char] || 0;
            freqScore += Math.min(freq, expectedFreq);
        }
        score += freqScore * 0.5; // Weight frequency score
    }
    
    // Check for common words
    const words = text.split(/\s+/);
    let commonWordCount = 0;
    
    for (const word of words) {
        const upperWord = word.toUpperCase().replace(/[^A-Z]/g, '');
        if (upperWord.length >= 3 && commonWords.has(upperWord)) {
            commonWordCount++;
        }
    }
    
    score += commonWordCount * 0.1;
    
    return score;
}
