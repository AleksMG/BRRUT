// Import the VigenereCipher and CipherAnalyzer classes (simplified for worker)
class VigenereCipher {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.setAlphabet(alphabet);
    }

    setAlphabet(alphabet) {
        this.alphabet = alphabet.toUpperCase();
        this.alphabetMap = {};
        for (let i = 0; i < this.alphabet.length; i++) {
            this.alphabetMap[this.alphabet[i]] = i;
        }
    }

    decrypt(ciphertext, key, preserveCase = true, preserveNonAlphabetic = true) {
        let result = '';
        const keyUpper = key.toUpperCase();
        let keyIndex = 0;

        for (let i = 0; i < ciphertext.length; i++) {
            const char = ciphertext[i];
            const upperChar = char.toUpperCase();

            if (this.alphabetMap[upperChar] !== undefined) {
                const textPos = this.alphabetMap[upperChar];
                const keyPos = this.alphabetMap[keyUpper[keyIndex % keyUpper.length]];
                let newPos = (textPos - keyPos + this.alphabet.length) % this.alphabet.length;
                let newChar = this.alphabet[newPos];
                if (preserveCase && char === char.toLowerCase()) {
                    newChar = newChar.toLowerCase();
                }
                result += newChar;
                keyIndex++;
            } else {
                if (preserveNonAlphabetic) {
                    result += char;
                }
            }
        }

        return result;
    }
}

class CipherAnalyzer {
    constructor(alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        this.setAlphabet(alphabet);
        this.loadQuadgrams();
    }

    setAlphabet(alphabet) {
        this.alphabet = alphabet.toUpperCase();
    }

    loadQuadgrams() {
        // Simplified quadgram frequencies
        this.quadgrams = {
            'TION': 0.0314, 'THER': 0.0267, 'NTHE': 0.0263, 'THAT': 0.0253,
            'OFTH': 0.0246, 'FTHE': 0.0244, 'THES': 0.0234, 'WITH': 0.0232,
            'INTH': 0.0213, 'ATIO': 0.0208, 'OTHE': 0.0206, 'TTHA': 0.0198,
            'NDTH': 0.0196, 'ETHE': 0.0194, 'TOTH': 0.0189, 'DTHE': 0.0187,
            'INGT': 0.0185, 'INGA': 0.0183, 'OFTH': 0.0181, 'REQU': 0.0179
        };
    }

    scoreText(text, method = 'quadgrams') {
        text = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (text.length < 4) return -Infinity;

        let score = 0;
        const n = text.length;

        if (method === 'quadgrams') {
            for (let i = 0; i < n - 3; i++) {
                const quadgram = text.substr(i, 4);
                score += Math.log10(this.quadgrams[quadgram] || 1e-10);
            }
            return score;
        } else if (method === 'ic') {
            return this.indexOfCoincidence(text);
        } else if (method === 'chi2') {
            return this.chiSquared(text);
        }

        return score;
    }

    indexOfCoincidence(text) {
        const freq = {};
        let count = 0;
        
        for (const char of text) {
            freq[char] = (freq[char] || 0) + 1;
            count++;
        }
        
        if (count < 2) return 0;
        
        let sum = 0;
        for (const char in freq) {
            sum += freq[char] * (freq[char] - 1);
        }
        
        return sum / (count * (count - 1));
    }

    chiSquared(text) {
        const englishFreq = {
            'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
            'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
            'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
            'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
            'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
        };
        
        const freq = {};
        let count = 0;
        
        for (const char of text.toUpperCase()) {
            if (englishFreq[char]) {
                freq[char] = (freq[char] || 0) + 1;
                count++;
            }
        }
        
        if (count === 0) return Infinity;
        
        let chi2 = 0;
        for (const char in englishFreq) {
            const expected = englishFreq[char] / 100 * count;
            const observed = freq[char] || 0;
            chi2 += Math.pow(observed - expected, 2) / expected;
        }
        
        return chi2;
    }

    matchesKnownPlaintext(decrypted, known) {
        if (!known) return true;
        return decrypted.toUpperCase().includes(known.toUpperCase());
    }
}

// Worker message handler
self.onmessage = function(event) {
    const { type } = event.data;
    
    if (type === 'start') {
        const {
            ciphertext,
            keyBatches,
            alphabet,
            method,
            knownPlaintext,
            scoringMethod
        } = event.data;

        const cipher = new VigenereCipher(alphabet);
        const analyzer = new CipherAnalyzer(alphabet);
        const results = [];
        let keysTested = 0;

        for (const batch of keyBatches) {
            for (const key of batch) {
                try {
                    const decrypted = cipher.decrypt(ciphertext, key, true, true);
                    
                    // Skip if known plaintext doesn't match
                    if (!analyzer.matchesKnownPlaintext(decrypted, knownPlaintext)) {
                        keysTested++;
                        continue;
                    }
                    
                    const score = analyzer.scoreText(decrypted, scoringMethod);
                    
                    if (score > -Infinity) {
                        results.push({
                            key,
                            plaintext: decrypted,
                            score
                        });
                    }
                    
                    keysTested++;
                } catch (error) {
                    console.error(`Error processing key ${key}:`, error);
                }
            }

            // Send intermediate results
            self.postMessage({
                keysTested,
                results
            });
        }

        // Signal completion
        self.postMessage({
            type: 'done'
        });
    }
};
