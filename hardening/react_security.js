// React Security Utilities
// Add to your React app

// 1. Secure API calls with CSRF protection
const API_BASE = process.env.REACT_APP_API_URL;

export const secureFetch = async (url: string, options: RequestInit = {}) => {
  const token = localStorage.getItem('auth_token');
  
  const headers = {
    ...options.headers,
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCSRFToken(),
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
  
  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
    credentials: 'include',
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
};

// 2. XSS Protection
export const sanitizeInput = (input: string): string => {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

// 3. CSRF Token Generation
export const getCSRFToken = (): string => {
  const cookie = document.cookie
    .split(';')
    .find(c => c.trim().startsWith('csrf_token='));
  return cookie ? cookie.split('=')[1] : '';
};

// 4. Secure Storage
export const secureStorage = {
  set: (key: string, value: string) => {
    sessionStorage.setItem(key, value);
  },
  get: (key: string) => {
    return sessionStorage.getItem(key);
  },
  remove: (key: string) => {
    sessionStorage.removeItem(key);
  },
};

// 5. Content Security Policy
export const CSP_NONCE = process.env.REACT_APP_CSP_NONCE;
