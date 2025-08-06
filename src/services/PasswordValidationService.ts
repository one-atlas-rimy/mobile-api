export interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong';
}

export interface PasswordRequirements {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  forbidCommonPasswords?: boolean;
  forbidUserInfo?: boolean;
}

const DEFAULT_REQUIREMENTS: PasswordRequirements = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  forbidCommonPasswords: true,
  forbidUserInfo: true,
};

const COMMON_PASSWORDS = [
  'password', '123456', '123456789', 'qwerty', 'abc123',
  'password123', 'admin', 'letmein', 'welcome', 'monkey'
];

const SPECIAL_CHARS = /[!@#$%^&*(),.?":{}|<>]/;

export class PasswordValidator {
  private requirements: PasswordRequirements;

  constructor(requirements: Partial<PasswordRequirements> = {}) {
    this.requirements = { ...DEFAULT_REQUIREMENTS, ...requirements };
  }

  validate(password: string, userInfo?: { email?: string; username?: string; name?: string }): PasswordValidationResult {
    const errors: string[] = [];

    // Length validation
    if (this.requirements.minLength && password.length < this.requirements.minLength) {
      errors.push(`Password must be at least ${this.requirements.minLength} characters long`);
    }

    if (this.requirements.maxLength && password.length > this.requirements.maxLength) {
      errors.push(`Password must be no more than ${this.requirements.maxLength} characters long`);
    }

    // Character type validation
    if (this.requirements.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (this.requirements.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (this.requirements.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (this.requirements.requireSpecialChars && !SPECIAL_CHARS.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)');
    }

    // Common password validation
    if (this.requirements.forbidCommonPasswords && this.isCommonPassword(password)) {
      errors.push('Password is too common, please choose a different one');
    }

    // User info validation
    if (this.requirements.forbidUserInfo && userInfo && this.containsUserInfo(password, userInfo)) {
      errors.push('Password cannot contain personal information');
    }

    const strength = this.calculateStrength(password);
    const isValid = errors.length === 0;

    return {
      isValid,
      errors,
      strength,
    };
  }

  private isCommonPassword(password: string): boolean {
    const lowerPassword = password.toLowerCase();
    return COMMON_PASSWORDS.some(common => 
      lowerPassword.includes(common) || common.includes(lowerPassword)
    );
  }

  private containsUserInfo(password: string, userInfo: { email?: string; username?: string; name?: string }): boolean {
    const lowerPassword = password.toLowerCase();
    
    if (userInfo.email) {
      const emailParts = userInfo.email.toLowerCase().split('@')[0];
      if (lowerPassword.includes(emailParts) || emailParts.includes(lowerPassword)) {
        return true;
      }
    }

    if (userInfo.username && lowerPassword.includes(userInfo.username.toLowerCase())) {
      return true;
    }

    if (userInfo.name) {
      const nameParts = userInfo.name.toLowerCase().split(' ');
      if (nameParts.some(part => part.length > 2 && lowerPassword.includes(part))) {
        return true;
      }
    }

    return false;
  }

  private calculateStrength(password: string): 'weak' | 'medium' | 'strong' {
    let score = 0;

    // Length scoring
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Character variety scoring
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (SPECIAL_CHARS.test(password)) score += 1;

    // Pattern variety (not just repeated characters)
    if (!/(.)\1{2,}/.test(password)) score += 1;

    if (score >= 7) return 'strong';
    if (score >= 5) return 'medium';
    return 'weak';
  }
}

// Helper function for quick validation
export function validatePassword(
  password: string, 
  requirements?: Partial<PasswordRequirements>,
  userInfo?: { email?: string; username?: string; name?: string }
): PasswordValidationResult {
  const validator = new PasswordValidator(requirements);
  return validator.validate(password, userInfo);
}