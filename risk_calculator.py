import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
from urllib.parse import urlparse
import ssl
import re
import socket

class RiskCalculator:
    def __init__(self):
        self.high_risk_keywords = [
            "guaranteed daily return", "double your investment", "passive income",
            "no risk", "get rich quick", "instant wealth", "financial freedom",
            "crypto investment", "bitcoin mining", "high returns", "risk-free",
            "guaranteed profit", "make money fast", "easy money"
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def calculate_risk(self, url):
        """Calculate risk score for a given URL"""
        risk_score = 0
        triggered_flags = []
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Fetch website content
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = soup.get_text().lower()
            
            # Flag A: High-Risk Keywords
            keyword_score = self._check_high_risk_keywords(text_content)
            if keyword_score > 0:
                risk_score += keyword_score
                triggered_flags.append(f"High-risk keywords detected (+{keyword_score})")
            
            # Flag B: Lack of Contact Info
            contact_score = self._check_contact_info(soup, text_content)
            if contact_score > 0:
                risk_score += contact_score
                triggered_flags.append(f"Lack of contact information (+{contact_score})")
            
            # Flag C: Domain Age
            domain_score = self._check_domain_age(url)
            if domain_score > 0:
                risk_score += domain_score
                triggered_flags.append(f"New domain registration (+{domain_score})")
            
            # Flag D: HTTPS/SSL Security
            ssl_score = self._check_ssl_security(url)
            if ssl_score > 0:
                risk_score += ssl_score
                triggered_flags.append(f"SSL security issues (+{ssl_score})")
            
            # Flag E: Fake Social Proof
            social_score = self._check_fake_social_proof(soup)
            if social_score > 0:
                risk_score += social_score
                triggered_flags.append(f"Potential fake social proof (+{social_score})")
            
            # Flag F: Unprofessional Design
            design_score = self._check_unprofessional_design(soup, text_content)
            if design_score > 0:
                risk_score += design_score
                triggered_flags.append(f"Unprofessional design indicators (+{design_score})")
                
        except Exception as e:
            print(f"Error analyzing {url}: {str(e)}")
            risk_score += 50  # Penalty for inaccessible sites
            triggered_flags.append("Website inaccessible (+50)")
        
        return min(risk_score, 100), triggered_flags
    
    def _check_high_risk_keywords(self, text):
        """Check for high-risk investment keywords"""
        score = 0
        for keyword in self.high_risk_keywords:
            if keyword in text:
                score += 5
        return min(score, 20)
    
    def _check_contact_info(self, soup, text):
        """Check for presence of contact information"""
        contact_indicators = [
            'contact', 'about', 'about us', 'address', 'phone', 'email',
            'location', 'support', 'help'
        ]
        
        # Check for contact page links
        contact_links = soup.find_all('a', href=True, string=lambda x: x and any(
            indicator in x.lower() for indicator in contact_indicators
        ))
        
        # Check for physical address in text
        address_patterns = [r'\d+\s+[\w\s]+,?\s*\w+,\s*\w+\s+\d+', r'p\.?o\.?\s+box']
        has_address = any(re.search(pattern, text, re.IGNORECASE) for pattern in address_patterns)
        
        # Check for phone numbers
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        has_phone = bool(re.search(phone_pattern, text))
        
        # Check for email
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        has_email = bool(re.search(email_pattern, text))
        
        if not contact_links and not has_address and not has_phone and not has_email:
            return 15
        elif (len(contact_links) == 0 and not has_address) or (not has_phone and not has_email):
            return 10
        return 0
    
    def _check_domain_age(self, url):
        """Check domain registration age"""
        try:
            domain = urlparse(url).netloc
            whois_info = whois.whois(domain)
            
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                
                if isinstance(creation_date, str):
                    creation_date = datetime.strptime(creation_date.split('T')[0], '%Y-%m-%d')
                
                domain_age = (datetime.now() - creation_date).days
                
                if domain_age <= 180:  # 6 months or less
                    return 15
                elif domain_age <= 365:  # 1 year or less
                    return 10
                    
        except Exception:
            return 10  # Default penalty if WHOIS fails
        
        return 0
    
    def _check_ssl_security(self, url):
        """Check SSL certificate validity"""
        try:
            if not url.startswith('https://'):
                return 10
            
            # Basic SSL check
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            # Check certificate expiration
            if cert:
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if (expiry_date - datetime.now()).days < 30:
                    return 5
                    
        except Exception:
            return 10
        
        return 0
    
    def _check_fake_social_proof(self, soup):
        """Check for fake testimonials and social proof"""
        testimonial_indicators = [
            'testimonial', 'review', 'success story', 'what our clients say'
        ]
        
        # Look for testimonial sections
        testimonials = soup.find_all(['div', 'section'], class_=lambda x: x and any(
            indicator in x.lower() for indicator in testimonial_indicators
        ))
        
        if testimonials:
            # Check for generic names or repetitive content
            testimonial_text = ' '.join([t.get_text() for t in testimonials]).lower()
            generic_names = ['john doe', 'jane smith', 'customer', 'client']
            
            if any(name in testimonial_text for name in generic_names):
                return 10
            elif len(testimonials) > 10:  # Excessive testimonials
                return 8
            elif 'amazing' in testimonial_text and testimonial_text.count('amazing') > 3:
                return 6
        
        return 0
    
    def _check_unprofessional_design(self, soup, text):
        """Check for unprofessional design elements"""
        score = 0
        
        # Check for excessive capitalization
        words = text.split()
        upper_count = sum(1 for word in words if word.isupper() and len(word) > 1)
        if upper_count > len(words) * 0.1:  # More than 10% uppercase
            score += 3
        
        # Check for poor grammar indicators
        grammar_issues = text.count('!!') + text.count('???')
        if grammar_issues > 5:
            score += 3
        
        # Check for low-quality images
        images = soup.find_all('img')
        low_res_images = sum(1 for img in images if 
                           img.get('width') and int(img.get('width', 0)) < 100 or
                           img.get('height') and int(img.get('height', 0)) < 100)
        
        if low_res_images > len(images) * 0.5:  # More than 50% low-res images
            score += 4
        
        return min(score, 10)