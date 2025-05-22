class WorkerVigenere {
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

class WorkerAnalyzer {
    constructor() {
        this.quadgrams = {
            'TION': 0.0314, 'THER': 0.0267, 'NTHE': 0.0263, 'THAT': 0.0253,
            'OFTH': 0.0246, 'FTHE': 0.0244, 'THES': 0.0234, 'WITH': 0.0232,
            'INTH': 0.0213, 'ATIO': 0.0208, 'OTHE': 0.0206, 'TTHA': 0.0198,
            'NDTH': 0.0196, 'ETHE': 0.0194, 'TOTH': 0.0189, 'DTHE': 0.0187,
            'INGT': 0.0185, 'INGA': 0.0183, 'OFTH': 0.0181, 'REQU': 0.0179
        };
    }

    score(text, method) {
        text = text.toUpperCase().replace(/[^A-Z]/g, '');
        if (text.length < 4) return -Infinity;

        let score = 0;
        for (let i = 0; i < text.length - 3; i++) {
            const quadgram = text.substr(i, 4);
            score += Math.log10(this.quadgrams[quadgram] || 1e-10);
        }
        return score;
    }

    matchesKnown(text, known) {
        return !known || text.toUpperCase().includes(known.toUpperCase());
    }
}

self.onmessage = function(e) {
    if (e.data.type !== 'start') return;

    const { ciphertext, keyBatches, alphabet, knownPlaintext, scoringMethod } = e.data;
    const cipher = new WorkerVigenere(alphabet);
    const analyzer = new WorkerAnalyzer();
    const results = [];
    let keysTested = 0;

    try {
        for (const batch of keyBatches) {
            const batchResults = [];
            
            for (const key of batch) {
                try {
                    const decrypted = cipher.decrypt(ciphertext, key);
                    
                    if (!analyzer.matchesKnown(decrypted, knownPlaintext)) {
                        keysTested++;
                        continue;
                    }
                    
                    const score = analyzer.score(decrypted, scoringMethod);
                    
                    if (score > -Infinity) {
                        batchResults.push({
                            key,
                            plaintext: decrypted,
                            score
                        });
                    }
                } catch (err) {
                    console.error(`Key ${key} failed:`, err);
                } finally {
                    keysTested++;
                }
            }

            self.postMessage({
                keysTested,
                results: batchResults
            });
        }
    } catch (err) {
        console.error('Worker fatal error:', err);
    } finally {
        self.postMessage({ type: 'done' });
    }
};
