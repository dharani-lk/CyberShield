"""
utils/password_analyzer.py
==========================
Password strength analyzer with entropy estimation.

CYBERSECURITY CONCEPTS:
- Entropy: Measure of password randomness/unpredictability
- Brute Force: Trying all possible combinations
- Dictionary Attack: Using common words/passwords
- Character Set: Pool of possible characters (affects cracking time)
"""

import re
import math
import string
from typing import Optional
import secrets


class PasswordAnalyzer:
    """
    Analyzes password strength using multiple criteria.
    
    Strength is evaluated on:
    1. Length (most important factor)
    2. Character diversity (uppercase, lowercase, numbers, symbols)
    3. Pattern detection (sequences, repetition, common patterns)
    4. Entropy calculation (theoretical cracking difficulty)
    """
    
    # Common weak passwords (top 100 from breached databases)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', '123456789', '1234567890', 'password123', 'iloveyou',
        'sunshine', 'princess', 'football', 'baseball', 'soccer',
        'michael', 'shadow', 'ashley', 'daniel', 'jessica', 'charlie',
        'superman', 'batman', 'trustno1', 'passw0rd', 'p@ssword',
        'qwerty123', 'zxcvbn', 'asdfgh', '1q2w3e4r', 'q1w2e3r4',
        'qwertyuiop', 'zaq12wsx', '!qaz2wsx', 'password!', 'pass1234'
    }
    
    # Keyboard patterns (indicate weak passwords)
    KEYBOARD_PATTERNS = [
        'qwerty', 'asdf', 'zxcv', 'qazwsx', '1234', 'abcd',
        'qwer', 'tyui', 'ghjk', 'vbnm', '0987', '7890'
    ]
    
    # Common substitutions (l33tspeak)
    LEET_SUBSTITUTIONS = {
        '@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o',
        '$': 's', '5': 's', '7': 't', '+': 't', '!': 'i'
    }
    
    def analyze(self, password: str) -> dict:
        """
        Perform comprehensive password strength analysis.
        
        Args:
            password: Password string to analyze
            
        Returns:
            Detailed analysis with score, entropy, and recommendations
        """
        if not password:
            return self._empty_password_result()
        
        result = {
            'length': len(password),
            'score': 0,
            'max_score': 100,
            'entropy': 0,
            'crack_time': '',
            'strength': 'very_weak',
            'strength_label': 'Very Weak',
            'checks': {},
            'issues': [],
            'suggestions': []
        }
        
        # === CHARACTER COMPOSITION CHECKS ===
        
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', password))
        
        result['checks'] = {
            'length_ok': len(password) >= 8,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_number': has_digit,
            'has_special': has_special,
            'no_common_password': password.lower() not in self.COMMON_PASSWORDS,
            'no_keyboard_pattern': not self._has_keyboard_pattern(password),
            'no_repetition': not self._has_repetition(password)
        }
        
        # === SCORING ===
        
        # Length scoring (most important - up to 40 points)
        length_score = min(len(password) * 3, 40)
        result['score'] += length_score
        
        # Character diversity (up to 40 points)
        if has_lower:
            result['score'] += 10
        if has_upper:
            result['score'] += 10
        if has_digit:
            result['score'] += 10
        if has_special:
            result['score'] += 10
        
        # Bonus for length > 12 (up to 10 points)
        if len(password) > 12:
            result['score'] += min((len(password) - 12) * 2, 10)
        
        # === PENALTIES ===
        
        # Common password penalty
        if password.lower() in self.COMMON_PASSWORDS:
            result['score'] = max(result['score'] - 40, 5)
            result['issues'].append('This is a commonly used password')
        
        # Keyboard pattern penalty
        if self._has_keyboard_pattern(password):
            result['score'] = max(result['score'] - 15, 5)
            result['issues'].append('Contains keyboard pattern')
        
        # Repetition penalty
        if self._has_repetition(password):
            result['score'] = max(result['score'] - 10, 5)
            result['issues'].append('Contains repeated characters')
        
        # Numeric-only penalty
        if password.isdigit():
            result['score'] = max(result['score'] - 20, 5)
            result['issues'].append('Password is numbers only')
        
        # Short password penalty
        if len(password) < 8:
            result['score'] = max(result['score'] - 15, 5)
            result['issues'].append('Password is too short (minimum 8 characters)')
        
        # === ENTROPY CALCULATION ===
        result['entropy'] = self._calculate_entropy(password)
        result['crack_time'] = self._estimate_crack_time(result['entropy'])
        
        # === DETERMINE STRENGTH ===
        score = result['score']
        
        if score >= 80:
            result['strength'] = 'very_strong'
            result['strength_label'] = 'Very Strong'
        elif score >= 60:
            result['strength'] = 'strong'
            result['strength_label'] = 'Strong'
        elif score >= 40:
            result['strength'] = 'medium'
            result['strength_label'] = 'Medium'
        elif score >= 20:
            result['strength'] = 'weak'
            result['strength_label'] = 'Weak'
        else:
            result['strength'] = 'very_weak'
            result['strength_label'] = 'Very Weak'
        
        # === GENERATE SUGGESTIONS ===
        result['suggestions'] = self._generate_suggestions(result)
        
        return result
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits.
        
        Entropy = log2(pool_size ^ length)
        
        Higher entropy = more secure. 
        - 40 bits: casual attacker
        - 60 bits: determined attacker
        - 80+ bits: nation-state level security
        
        Args:
            password: Password to calculate entropy for
            
        Returns:
            Entropy value in bits
        """
        pool_size = 0
        
        if re.search(r'[a-z]', password):
            pool_size += 26  # lowercase letters
        if re.search(r'[A-Z]', password):
            pool_size += 26  # uppercase letters
        if re.search(r'\d', password):
            pool_size += 10  # digits
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', password):
            pool_size += 32  # common special characters
        
        if pool_size == 0:
            return 0
        
        # Entropy = length * log2(pool_size)
        entropy = len(password) * math.log2(pool_size)
        
        return round(entropy, 2)
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """
        Estimate time to crack based on entropy.
        
        Assumes 10 billion guesses per second (modern GPU cluster).
        This is conservative for well-funded attackers.
        
        Args:
            entropy: Password entropy in bits
            
        Returns:
            Human-readable crack time estimate
        """
        # Combinations = 2^entropy
        # Time = combinations / guesses_per_second
        guesses_per_second = 10_000_000_000  # 10 billion
        
        combinations = 2 ** entropy
        seconds = combinations / guesses_per_second
        
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} years"
        elif seconds < 31536000 * 1000000:
            return f"{int(seconds / 31536000 / 1000)} thousand years"
        else:
            return "Millions of years"
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns like 'qwerty' or '12345'."""
        password_lower = password.lower()
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                return True
        return False
    
    def _has_repetition(self, password: str) -> bool:
        """Check for character repetition (e.g., 'aaa' or '111')."""
        return bool(re.search(r'(.)\1{2,}', password))
    
    def _generate_suggestions(self, analysis: dict) -> list:
        """Generate improvement suggestions based on analysis."""
        suggestions = []
        checks = analysis['checks']
        
        if not checks['length_ok']:
            suggestions.append('Use at least 8 characters (12+ recommended)')
        
        if not checks['has_lowercase']:
            suggestions.append('Add lowercase letters (a-z)')
        
        if not checks['has_uppercase']:
            suggestions.append('Add uppercase letters (A-Z)')
        
        if not checks['has_number']:
            suggestions.append('Add numbers (0-9)')
        
        if not checks['has_special']:
            suggestions.append('Add special characters (!@#$%^&*)')
        
        if not checks['no_common_password']:
            suggestions.append('Avoid common passwords - use unique phrases')
        
        if not checks['no_keyboard_pattern']:
            suggestions.append('Avoid keyboard patterns like "qwerty"')
        
        if not checks['no_repetition']:
            suggestions.append('Avoid repeating characters (aaa, 111)')
        
        if analysis['score'] < 60 and analysis['length'] < 14:
            suggestions.append('Consider using a passphrase (e.g., "correct-horse-battery-staple")')
        
        if not suggestions:
            suggestions.append('Great password! Consider using a password manager')
        
        return suggestions
    
    def _empty_password_result(self) -> dict:
        """Return result for empty password."""
        return {
            'length': 0,
            'score': 0,
            'max_score': 100,
            'entropy': 0,
            'crack_time': 'Instant',
            'strength': 'very_weak',
            'strength_label': 'Very Weak',
            'checks': {
                'length_ok': False,
                'has_lowercase': False,
                'has_uppercase': False,
                'has_number': False,
                'has_special': False
            },
            'issues': ['Password is empty'],
            'suggestions': ['Enter a password to analyze']
        }
    
    def generate_strong_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.
        
        Uses secrets module (not random) for cryptographic security.
        
        Args:
            length: Desired password length (default 16)
            
        Returns:
            Strong random password
        """
        if length < 8:
            length = 8
        
        # Ensure at least one of each required character type
        password_chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice('!@#$%^&*()_+-=')
        ]
        
        # Fill remaining length with random characters from all pools
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-='
        password_chars.extend(
            secrets.choice(all_chars) for _ in range(length - 4)
        )
        
        # Shuffle to avoid predictable pattern
        password_list = list(password_chars)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
