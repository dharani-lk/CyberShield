"""
utils/phishing_detector.py
==========================
Phishing detection module for URLs and email content.

CYBERSECURITY CONCEPTS:
- Phishing: Social engineering attack using fake communications
- URL Analysis: Examining link structure for malicious indicators
- Brand Impersonation: Mimicking legitimate companies to steal credentials
- Homograph Attacks: Using similar-looking characters (e.g., 'rn' vs 'm')
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Optional
import validators


class PhishingDetector:
    """
    Analyzes URLs and email content for phishing indicators.
    
    Detection is based on patterns observed in real phishing campaigns:
    - Suspicious URL structures
    - Urgent/threatening language
    - Credential harvesting attempts
    - Brand impersonation techniques
    """
    
    # Known legitimate domains (whitelist approach)
    TRUSTED_DOMAINS = {
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'paypal.com', 'netflix.com', 'spotify.com', 'dropbox.com'
    }
    
    # Brands commonly impersonated in phishing
    IMPERSONATED_BRANDS = [
        'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
        'facebook', 'instagram', 'whatsapp', 'bank', 'wells fargo',
        'chase', 'citibank', 'american express', 'irs', 'usps', 'fedex',
        'dhl', 'linkedin', 'dropbox', 'docusign', 'zoom', 'office365'
    ]
    
    # Suspicious keywords in URLs
    SUSPICIOUS_URL_KEYWORDS = [
        'login', 'signin', 'verify', 'secure', 'account', 'update',
        'confirm', 'password', 'credential', 'authenticate', 'validate',
        'suspend', 'locked', 'unusual', 'activity', 'billing', 'payment',
        'wallet', 'crypto', 'prize', 'winner', 'free', 'gift', 'reward'
    ]
    
    # URL shortener services (often used to hide malicious URLs)
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'tiny.cc'
    ]
    
    # Phishing language patterns in emails
    EMAIL_PHISHING_PATTERNS = {
        'urgency': [
            r'immediate(?:ly)?', r'urgent(?:ly)?', r'right away', r'asap',
            r'within \d+ (?:hour|day)', r'expires? (?:soon|today|tomorrow)',
            r'act now', r'don\'t delay', r'time.sensitive', r'limited time'
        ],
        'threats': [
            r'suspend(?:ed)?', r'terminat(?:e|ed|ion)', r'clos(?:e|ed|ing)',
            r'delet(?:e|ed|ing)', r'deactivat(?:e|ed)', r'restrict(?:ed)?',
            r'block(?:ed)?', r'unauthori[sz]ed', r'illegal', r'violation'
        ],
        'credential_requests': [
            r'verify your (?:identity|account|email|password)',
            r'confirm your (?:identity|account|details|information)',
            r'update your (?:payment|billing|account|password)',
            r'(?:re-?)?enter your (?:password|credentials|pin)',
            r'log.?in (?:to )?(?:verify|confirm|secure)',
            r'click (?:here|below|the link) to (?:verify|confirm|update)'
        ],
        'security_warnings': [
            r'security (?:alert|warning|notice|breach)',
            r'suspicious (?:activity|login|sign.?in)',
            r'unusual (?:activity|access|sign.?in)',
            r'someone (?:tried|attempted) to (?:access|log)',
            r'your account (?:has been|was) (?:compromised|hacked|breached)'
        ],
        'rewards_scams': [
            r'you(?:\'ve)? won', r'winner', r'congratulations',
            r'claim your (?:prize|reward|gift)', r'free (?:gift|iphone|money)',
            r'lottery', r'inheritance', r'million (?:dollar|pound|euro)'
        ]
    }
    
    def analyze_url(self, url: str) -> dict:
        """
        Perform comprehensive URL analysis for phishing indicators.
        
        Detection methodology:
        1. Structure analysis (length, subdomains, special characters)
        2. Domain reputation (IP addresses, shorteners, suspicious TLDs)
        3. Content analysis (keywords, brand impersonation)
        4. Technical indicators (encoded characters, redirects)
        
        Args:
            url: URL string to analyze
            
        Returns:
            Analysis results with risk score and details
        """
        # Normalize URL
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Initialize result
        result = {
            'url': url,
            'is_valid': False,
            'risk_score': 0,
            'threat_level': 'safe',
            'indicators': [],
            'recommendations': []
        }
        
        # Validate URL format
        if not validators.url(url):
            result['indicators'].append({
                'type': 'invalid_format',
                'severity': 'high',
                'description': 'URL format is invalid or malformed'
            })
            result['risk_score'] = 100
            result['threat_level'] = 'critical'
            return result
        
        result['is_valid'] = True
        
        try:
            parsed = urlparse(url)
        except Exception:
            result['risk_score'] = 100
            result['threat_level'] = 'critical'
            return result
        
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
        
        # === ANALYSIS CHECKS ===
        
        # 1. URL Length Check
        # Phishing URLs often excessively long to hide malicious parts
        if len(url) > 75:
            severity = 'medium' if len(url) < 100 else 'high'
            result['indicators'].append({
                'type': 'excessive_length',
                'severity': severity,
                'description': f'Unusually long URL ({len(url)} characters)'
            })
            result['risk_score'] += 15 if severity == 'medium' else 25
        
        # 2. IP Address Detection
        # Legitimate sites rarely use IP addresses directly
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
        if re.match(ip_pattern, domain):
            result['indicators'].append({
                'type': 'ip_address',
                'severity': 'high',
                'description': 'URL uses IP address instead of domain name'
            })
            result['risk_score'] += 30
        
        # 3. Excessive Hyphens
        # Phishers use hyphens to create look-alike domains: "paypal-secure-login.com"
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            result['indicators'].append({
                'type': 'excessive_hyphens',
                'severity': 'medium',
                'description': f'Domain contains {hyphen_count} hyphens (common in phishing)'
            })
            result['risk_score'] += 15
        
        # 4. Subdomain Analysis
        # Many subdomains can hide the real domain: "login.paypal.secure.evil.com"
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            result['indicators'].append({
                'type': 'excessive_subdomains',
                'severity': 'medium',
                'description': f'URL has {len(subdomains)-2} subdomains (may hide real domain)'
            })
            result['risk_score'] += 15
        
        # 5. URL Shortener Detection
        for shortener in self.URL_SHORTENERS:
            if shortener in domain:
                result['indicators'].append({
                    'type': 'url_shortener',
                    'severity': 'medium',
                    'description': f'URL uses shortening service ({shortener})'
                })
                result['risk_score'] += 20
                break
        
        # 6. Suspicious Keywords in URL
        found_keywords = []
        for keyword in self.SUSPICIOUS_URL_KEYWORDS:
            if keyword in full_url:
                found_keywords.append(keyword)
        
        if found_keywords:
            result['indicators'].append({
                'type': 'suspicious_keywords',
                'severity': 'medium',
                'description': f'Contains suspicious keywords: {", ".join(found_keywords[:5])}'
            })
            result['risk_score'] += min(len(found_keywords) * 5, 20)
        
        # 7. Brand Impersonation Detection
        # Check if known brand appears but domain isn't official
        for brand in self.IMPERSONATED_BRANDS:
            if brand in domain:
                # Check if this is the actual legitimate domain
                is_legitimate = any(
                    domain == trusted or domain.endswith('.' + trusted)
                    for trusted in self.TRUSTED_DOMAINS
                    if brand in trusted
                )
                
                if not is_legitimate:
                    result['indicators'].append({
                        'type': 'brand_impersonation',
                        'severity': 'high',
                        'description': f'Potential impersonation of "{brand.title()}"'
                    })
                    result['risk_score'] += 35
                    break
        
        # 8. HTTPS Check
        if parsed.scheme != 'https':
            result['indicators'].append({
                'type': 'no_https',
                'severity': 'low',
                'description': 'Site does not use HTTPS encryption'
            })
            result['risk_score'] += 10
        
        # 9. Special Characters in Domain
        # Characters like @ can be used to deceive: "paypal.com@evil.com"
        if '@' in domain:
            result['indicators'].append({
                'type': 'at_symbol',
                'severity': 'critical',
                'description': 'URL contains @ symbol (credential injection technique)'
            })
            result['risk_score'] += 50
        
        # 10. Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.click', '.link', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                result['indicators'].append({
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'description': f'Uses frequently abused TLD: {tld}'
                })
                result['risk_score'] += 15
                break
        
        # === CALCULATE FINAL RESULTS ===
        
        # Cap risk score at 100
        result['risk_score'] = min(result['risk_score'], 100)
        
        # Determine threat level
        if result['risk_score'] >= 75:
            result['threat_level'] = 'critical'
        elif result['risk_score'] >= 50:
            result['threat_level'] = 'high'
        elif result['risk_score'] >= 25:
            result['threat_level'] = 'medium'
        else:
            result['threat_level'] = 'low'
        
        # Generate recommendations
        result['recommendations'] = self._generate_url_recommendations(result)
        
        return result
    
    def analyze_email(self, email_content: str) -> dict:
        """
        Analyze email content for phishing indicators.
        
        Detection focuses on social engineering techniques:
        1. Creating urgency to bypass rational thinking
        2. Fear-inducing threats about account suspension
        3. Requests for sensitive information
        4. Too-good-to-be-true rewards
        
        Args:
            email_content: Raw email text to analyze
            
        Returns:
            Analysis results with detected patterns and risk assessment
        """
        content_lower = email_content.lower()
        
        result = {
            'content_length': len(email_content),
            'risk_score': 0,
            'threat_level': 'safe',
            'detected_patterns': [],
            'threat_categories': [],
            'recommendations': []
        }
        
        # Analyze each pattern category
        for category, patterns in self.EMAIL_PHISHING_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content_lower, re.IGNORECASE)
                matches.extend(found)
            
            if matches:
                # Remove duplicates while preserving order
                unique_matches = list(dict.fromkeys(matches))[:5]
                
                result['detected_patterns'].append({
                    'category': category.replace('_', ' ').title(),
                    'matches': unique_matches,
                    'count': len(matches)
                })
                result['threat_categories'].append(category)
                
                # Score based on severity of category
                if category == 'credential_requests':
                    result['risk_score'] += 35
                elif category == 'threats':
                    result['risk_score'] += 25
                elif category == 'security_warnings':
                    result['risk_score'] += 20
                elif category == 'urgency':
                    result['risk_score'] += 15
                elif category == 'rewards_scams':
                    result['risk_score'] += 30
        
        # Check for suspicious links in content
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, email_content)
        
        if urls:
            suspicious_url_count = 0
            for url in urls[:5]:  # Check first 5 URLs
                url_analysis = self.analyze_url(url)
                if url_analysis['risk_score'] > 25:
                    suspicious_url_count += 1
            
            if suspicious_url_count > 0:
                result['detected_patterns'].append({
                    'category': 'Suspicious Links',
                    'matches': [f'{suspicious_url_count} suspicious URL(s) detected'],
                    'count': suspicious_url_count
                })
                result['risk_score'] += suspicious_url_count * 15
        
        # Check for common phishing phrases
        phishing_phrases = [
            'click here', 'click below', 'click the link',
            'dear customer', 'dear user', 'dear valued',
            'we noticed', 'we detected', 'we have noticed'
        ]
        
        phrase_matches = [p for p in phishing_phrases if p in content_lower]
        if phrase_matches:
            result['detected_patterns'].append({
                'category': 'Phishing Phrases',
                'matches': phrase_matches,
                'count': len(phrase_matches)
            })
            result['risk_score'] += len(phrase_matches) * 5
        
        # Cap score and determine threat level
        result['risk_score'] = min(result['risk_score'], 100)
        
        if result['risk_score'] >= 70:
            result['threat_level'] = 'critical'
        elif result['risk_score'] >= 45:
            result['threat_level'] = 'high'
        elif result['risk_score'] >= 20:
            result['threat_level'] = 'medium'
        else:
            result['threat_level'] = 'low'
        
        # Generate recommendations
        result['recommendations'] = self._generate_email_recommendations(result)
        
        return result
    
    def _generate_url_recommendations(self, analysis: dict) -> list:
        """Generate actionable recommendations based on URL analysis."""
        recommendations = []
        
        if analysis['threat_level'] in ['critical', 'high']:
            recommendations.append('Do NOT click or visit this URL')
            recommendations.append('Report this URL to your IT security team')
        
        indicators = [i['type'] for i in analysis['indicators']]
        
        if 'brand_impersonation' in indicators:
            recommendations.append('Verify by going directly to the official website')
            recommendations.append('Do not enter any login credentials')
        
        if 'url_shortener' in indicators:
            recommendations.append('Use a URL expander service to reveal the full destination')
        
        if 'no_https' in indicators:
            recommendations.append('Never enter sensitive information on non-HTTPS sites')
        
        if analysis['threat_level'] == 'low' and not recommendations:
            recommendations.append('URL appears relatively safe, but always verify sender')
            recommendations.append('When in doubt, contact the organization directly')
        
        return recommendations
    
    def _generate_email_recommendations(self, analysis: dict) -> list:
        """Generate recommendations based on email analysis."""
        recommendations = []
        
        categories = analysis.get('threat_categories', [])
        
        if analysis['threat_level'] in ['critical', 'high']:
            recommendations.append('This email shows strong signs of phishing - do not click any links')
            recommendations.append('Do not reply or provide any personal information')
            recommendations.append('Report to your email provider as phishing')
        
        if 'credential_requests' in categories:
            recommendations.append('Legitimate organizations never ask for passwords via email')
            recommendations.append('Contact the organization directly using official contact information')
        
        if 'urgency' in categories or 'threats' in categories:
            recommendations.append('Scammers create urgency to prevent careful thinking')
            recommendations.append('Take time to verify - legitimate requests allow reasonable time')
        
        if 'rewards_scams' in categories:
            recommendations.append('If it sounds too good to be true, it probably is')
            recommendations.append('Never pay fees to claim "prizes" or "inheritances"')
        
        if analysis['threat_level'] == 'low' and not recommendations:
            recommendations.append('Email appears legitimate, but always verify unexpected requests')
            recommendations.append('Hover over links to verify destinations before clicking')
        
        return recommendations
