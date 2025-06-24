import re
import string
from typing import Dict, List, Tuple

class PasswordStrengthAnalyzer:
    """
    A comprehensive password strength analyzer that evaluates passwords
    based on multiple security criteria.
    """
    
    def __init__(self):
        # Common weak passwords to check against
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', '123123', 'qwerty123'
        }
        
        # Common patterns that make passwords weak
        self.weak_patterns = [
            r'123+',           # Sequential numbers
            r'abc+',           # Sequential letters
            r'(.)\1{2,}',      # Repeated characters (3+ times)
            r'password',       # Contains "password"
            r'admin',          # Contains "admin"
        ]
    
    def analyze_password(self, password: str) -> Dict:
        """
        Analyze password strength and return detailed results.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            Dict: Analysis results including score, strength, and feedback
        """
        if not password:
            return {
                'score': 0,
                'strength': 'Invalid',
                'is_valid': False,
                'feedback': ['Password cannot be empty'],
                'criteria': {}
            }
        
        # Check all criteria
        criteria = self._check_all_criteria(password)
        
        # Calculate score
        score = sum(criteria.values())
        max_score = len(criteria)
        
        # Determine strength level
        strength = self._determine_strength(score, max_score)
        
        # Check if password meets minimum requirements
        is_valid = criteria['length'] and score >= 3  # At least 3 criteria met
        
        # Generate feedback
        feedback = self._generate_feedback(criteria, password)
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 1),
            'strength': strength,
            'is_valid': is_valid,
            'feedback': feedback,
            'criteria': criteria
        }
    
    def _check_all_criteria(self, password: str) -> Dict[str, bool]:
        """Check all password criteria and return results."""
        return {
            'length': self._check_length(password),
            'uppercase': self._has_uppercase(password),
            'lowercase': self._has_lowercase(password),
            'digits': self._has_digits(password),
            'special_chars': self._has_special_chars(password),
            'no_common_password': not self._is_common_password(password),
            'no_weak_patterns': not self._has_weak_patterns(password),
            'no_personal_info': not self._contains_personal_info(password)
        }
    
    def _check_length(self, password: str) -> bool:
        """Check if password is between 8 and 64 characters long."""
        return 8 <= len(password) <= 64
    
    def _has_uppercase(self, password: str) -> bool:
        """Check if password contains uppercase letters."""
        return any(c.isupper() for c in password)
    
    def _has_lowercase(self, password: str) -> bool:
        """Check if password contains lowercase letters."""
        return any(c.islower() for c in password)
    
    def _has_digits(self, password: str) -> bool:
        """Check if password contains digits."""
        return any(c.isdigit() for c in password)
    
    def _has_special_chars(self, password: str) -> bool:
        """Check if password contains special characters."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return any(c in special_chars for c in password)
    
    def _is_common_password(self, password: str) -> bool:
        """Check if password is in the list of common weak passwords."""
        return password.lower() in self.common_passwords
    
    def _has_weak_patterns(self, password: str) -> bool:
        """Check if password contains weak patterns."""
        password_lower = password.lower()
        for pattern in self.weak_patterns:
            if re.search(pattern, password_lower):
                return True
        return False
    
    def _contains_personal_info(self, password: str) -> bool:
        """Check if password contains obvious personal information patterns."""
        # This is a basic check - in real applications, you might check against
        # user's actual personal information
        personal_patterns = [
            r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)',  # Months
            r'\b(19|20)\d{2}\b',  # Years
            r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',  # Dates
        ]
        
        password_lower = password.lower()
        for pattern in personal_patterns:
            if re.search(pattern, password_lower):
                return True
        return False
    
    def _determine_strength(self, score: int, max_score: int) -> str:
        """Determine password strength based on score."""
        percentage = (score / max_score) * 100
        
        if percentage >= 90:
            return "Very Strong"
        elif percentage >= 75:
            return "Strong"
        elif percentage >= 60:
            return "Moderate"
        elif percentage >= 40:
            return "Weak"
        else:
            return "Very Weak"
    
    def _generate_feedback(self, criteria: Dict[str, bool], password: str) -> List[str]:
        """Generate specific feedback based on failed criteria."""
        feedback = []
        
        if not criteria['length']:
            if len(password) < 8:
                feedback.append(f"Password must be at least 8 characters long (current: {len(password)})")
            elif len(password) > 64:
                feedback.append(f"Password must not exceed 64 characters (current: {len(password)})")
            else:
                feedback.append("Password length must be between 8 and 64 characters")

        if not criteria['uppercase']:
            feedback.append("Add uppercase letters (A-Z)")
            
        if not criteria['lowercase']:
            feedback.append("Add lowercase letters (a-z)")
            
        if not criteria['digits']:
            feedback.append("Add numbers (0-9)")
            
        if not criteria['special_chars']:
            feedback.append("Add special characters (!@#$%^&*)")
            
        if not criteria['no_common_password']:
            feedback.append("Avoid common passwords")
            
        if not criteria['no_weak_patterns']:
            feedback.append("Avoid predictable patterns (123, abc, repeated characters)")
            
        if not criteria['no_personal_info']:
            feedback.append("Avoid personal information (dates, names)")
        
        if not feedback:
            feedback.append("Password strong, strong like bear. Excellent work, Comrade.")
            
        return feedback

def main():
    """Main function to demonstrate the password analyzer."""
    analyzer = PasswordStrengthAnalyzer()
    
    print("Password Strength Analyzer")
    print("=" * 50)
    
    while True:
        print("\nOptions:")
        print("1. Analyze password strength")
        print("2. Test with example passwords")
        print("3. Exit PSA")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            password = input("\nEnter password to analyze: ")
            result = analyzer.analyze_password(password)
            display_results(result)
            
        elif choice == '2':
            test_passwords = [
                "123456",
                "password",
                "MyPass123",
                "StR0ng_P@ssw0rd!",
                "weakpass",
                "ComplexPassword123!@#"
                "ThisIsAVeryLongPasswordThatExceedsTheSixtyFourCharacterLimitAndShouldFail123!"
            ]
            
            print("\nHere are some examples of passwords to help inspire you to write a strong password:")
            print("-" * 50)
            
            for pwd in test_passwords:
                print(f"\nPassword: {'*' * len(pwd)}")
                result = analyzer.analyze_password(pwd)
                display_results(result, compact=True)
                
        elif choice == '3':
            print("\nbye-bye, stay safe, take care of yourself out there :)")
            break
            
        else:
            print("EHHHHH! Try again! Select 1, 2, or 3 only :)))")

def display_results(result: Dict, compact: bool = False):
    """Display password analysis results in a formatted way."""
    
    # Status indicator
    status_icon = "✅" if result['is_valid'] else "❌"
    
    print(f"\n{status_icon} Strength: {result['strength']}")
    print(f" Score: {result['score']}/{result['max_score']} ({result['percentage']}%)")
    
    if not compact:
        print(f"✓ Valid: {'Yes' if result['is_valid'] else 'No'}")
        
        print("\n Criteria Check:")
        criteria_labels = {
            'length': 'Length 8-64 characters',
            'uppercase': 'Uppercase letters',
            'lowercase': 'Lowercase letters', 
            'digits': 'Numbers',
            'special_chars': 'Special characters',
            'no_common_password': 'Not a common password',
            'no_weak_patterns': 'No weak patterns',
            'no_personal_info': 'No personal info'
        }
        
        for key, passed in result['criteria'].items():
            icon = "✅" if passed else "❌"
            print(f"  {icon} {criteria_labels[key]}")
    
    print("\n Feedback:")
    for tip in result['feedback']:
        print(f"  • {tip}")

if __name__ == "__main__":
    main()
    