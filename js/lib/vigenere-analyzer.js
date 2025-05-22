export class VigenereAnalyzer {
    constructor() {
        this.languageProfiles = {
            english: this.createEnglishProfile(),
            german: this.createGermanProfile(),
            french: this.createFrenchProfile(),
            russian: this.createRussianProfile()
        };
        this.currentLanguage = 'english';
    }

    setLanguageProfile(language) {
        this.currentLanguage = language;
    }

    createEnglishProfile() {
        return {
            frequencies: {
                'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
                'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
                'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
                'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
                'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
                'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
                'Y': 0.01974, 'Z': 0.00074
            },
            commonWords: ['THE', 'AND', 'THAT', 'HAVE', 'WITH', 'THIS', 'FROM', 'THEY'],
            illegalPairs: ['QJ', 'ZQ', 'ZX']
        };
    }

    // ... аналогичные методы для других языков ...

    decrypt(ciphertext, key, alphabet) {
        const alphaMap = this.createAlphabetMap(alphabet);
        let plaintext = '';
        
        for (let i = 0; i < ciphertext.length; i++) {
            const c = ciphertext[i];
            const k = key[i % key.length];
            
            const cIdx = alphaMap[c];
            const kIdx = alphaMap[k];
            
            if (cIdx !== undefined && kIdx !== undefined) {
                const pIdx = (cIdx - kIdx + alphabet.length) % alphabet.length;
                plaintext += alphabet[pIdx];
            } else {
                plaintext += '?';
            }
        }
        
        return plaintext;
    }

    createAlphabetMap(alphabet) {
        const map = {};
        for (let i = 0; i < alphabet.length; i++) {
            map[alphabet[i]] = i;
        }
        return map;
    }

    scoreText(text, language = this.currentLanguage) {
        const profile = this.languageProfiles[language] || this.languageProfiles.english;
        let score = 0;
        
        // 1. Frequency analysis
        const freq = this.calculateFrequencies(text);
        for (const char in freq) {
            const expected = profile.frequencies[char] || 0;
            score -= Math.abs(freq[char] - expected) * 10;
        }
        
        // 2. Common words bonus
        for (const word of profile.commonWords) {
            if (text.includes(word)) {
                score += word.length * 0.5;
            }
        }
        
        // 3. Illegal pairs penalty
        for (const pair of profile.illegalPairs) {
            if (text.includes(pair)) {
                score -= 2;
            }
        }
        
        return score;
    }

    calculateFrequencies(text) {
        const freq = {};
        let total = 0;
        
        for (const c of text) {
            if (/[A-Z]/.test(c)) {
                freq[c] = (freq[c] || 0) + 1;
                total++;
            }
        }
        
        for (const c in freq) {
            freq[c] = freq[c] / total;
        }
        
        return freq;
    }

    generateKeySpace(keyLength, alphabet) {
        const keys = [];
        this.generateKeysRecursive('', keyLength, alphabet, keys);
        return keys;
    }

    generateKeysRecursive(current, length, alphabet, keys) {
        if (current.length === length) {
            keys.push(current);
            return;
        }
        
        for (const char of alphabet) {
            this.generateKeysRecursive(current + char, length, alphabet, keys);
        }
    }
}
