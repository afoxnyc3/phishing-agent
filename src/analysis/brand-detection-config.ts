/**
 * Brand Detection Configuration
 * Top 20 most impersonated brands based on 2024-2025 phishing research
 */

export const BRAND_TARGETS = [
  // Tech (Top 5 - Microsoft #1 most impersonated in 2024-2025)
  { name: 'Microsoft', domain: 'microsoft.com' },
  { name: 'Apple', domain: 'apple.com' },
  { name: 'Google', domain: 'google.com' },
  { name: 'Adobe', domain: 'adobe.com' },
  { name: 'LinkedIn', domain: 'linkedin.com' },
  // Financial (Top 5)
  { name: 'PayPal', domain: 'paypal.com' },
  { name: 'Chase', domain: 'chase.com' },
  { name: 'Mastercard', domain: 'mastercard.com' },
  { name: 'American Express', domain: 'americanexpress.com' },
  { name: 'Wells Fargo', domain: 'wellsfargo.com' },
  // Retail/E-commerce (Top 5)
  { name: 'Amazon', domain: 'amazon.com' },
  { name: 'Walmart', domain: 'walmart.com' },
  { name: 'DHL', domain: 'dhl.com' },
  { name: 'FedEx', domain: 'fedex.com' },
  { name: 'Netflix', domain: 'netflix.com' },
  // Social/Communication (Top 5)
  { name: 'Facebook', domain: 'facebook.com' },
  { name: 'Meta', domain: 'meta.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'WhatsApp', domain: 'whatsapp.com' },
  { name: 'IRS', domain: 'irs.gov' },
];

/**
 * Typosquatting patterns (character substitution: 0→o, 1→l, 3→e)
 */
export const TYPOSQUAT_PATTERNS = [
  { pattern: /paypa1/, brand: 'PayPal' },          // paypal → paypa1
  { pattern: /micros0ft/, brand: 'Microsoft' },    // microsoft → micros0ft
  { pattern: /g00gle/, brand: 'Google' },          // google → g00gle
  { pattern: /appl3/, brand: 'Apple' },            // apple → appl3
  { pattern: /amaz0n/, brand: 'Amazon' },          // amazon → amaz0n
  { pattern: /netf1ix/, brand: 'Netflix' },        // netflix → netf1ix
];
