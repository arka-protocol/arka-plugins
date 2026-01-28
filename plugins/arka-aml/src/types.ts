/**
 * AML Domain Types
 *
 * Domain-specific types for the arka-aml plugin.
 * Anti-Money Laundering compliance types and constants.
 */

/**
 * KYC (Know Your Customer) verification levels
 */
export type KYCLevel =
  | 'NONE'
  | 'BASIC'
  | 'STANDARD'
  | 'ENHANCED'
  | 'FULL';

/**
 * Account risk tier
 */
export type AccountRiskTier =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'BLOCKED';

/**
 * Customer risk category
 */
export type CustomerRiskCategory =
  | 'STANDARD'
  | 'HIGH_NET_WORTH'
  | 'PEP'           // Politically Exposed Person
  | 'PEP_RELATIVE'  // Relative of PEP
  | 'SANCTIONED'
  | 'WATCHLIST'
  | 'ADVERSE_MEDIA';

/**
 * Transaction channel
 */
export type TransactionChannel =
  | 'WIRE'
  | 'ACH'
  | 'CHECK'
  | 'CASH'
  | 'CARD'
  | 'CRYPTO'
  | 'INTERNAL'
  | 'MOBILE'
  | 'ATM'
  | 'POS';

/**
 * Transaction type
 */
export type TransactionType =
  | 'DEPOSIT'
  | 'WITHDRAWAL'
  | 'TRANSFER'
  | 'PAYMENT'
  | 'EXCHANGE'
  | 'LOAN_DISBURSEMENT'
  | 'LOAN_PAYMENT';

/**
 * Alert status
 */
export type AlertStatus =
  | 'OPEN'
  | 'UNDER_REVIEW'
  | 'ESCALATED'
  | 'SAR_FILED'
  | 'CLOSED_NO_ACTION'
  | 'CLOSED_FALSE_POSITIVE';

/**
 * Country risk classification
 */
export type CountryRiskLevel =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'VERY_HIGH'
  | 'SANCTIONED';

/**
 * Account entity
 */
export interface AccountData {
  /** Account unique identifier */
  accountId: string;
  /** Owner customer ID */
  ownerId: string;
  /** Account type */
  accountType: 'CHECKING' | 'SAVINGS' | 'INVESTMENT' | 'BUSINESS' | 'TRUST';
  /** Country of account */
  country: string;
  /** Currency */
  currency: string;
  /** KYC verification level */
  kycLevel: KYCLevel;
  /** Risk tier */
  riskTier: AccountRiskTier;
  /** Account opening date */
  openedAt: string;
  /** Account status */
  status: 'ACTIVE' | 'DORMANT' | 'FROZEN' | 'CLOSED';
  /** Average monthly balance */
  avgMonthlyBalance?: number;
  /** Expected monthly activity */
  expectedMonthlyActivity?: number;
  /** Number of authorized signers */
  authorizedSigners?: number;
  /** Whether account allows international transfers */
  allowsInternational?: boolean;
}

/**
 * Customer entity
 */
export interface CustomerData {
  /** Customer unique identifier */
  customerId: string;
  /** Customer type */
  customerType: 'INDIVIDUAL' | 'BUSINESS' | 'TRUST' | 'NON_PROFIT';
  /** Full legal name */
  legalName: string;
  /** Country of residence/registration */
  country: string;
  /** Nationality (for individuals) */
  nationality?: string;
  /** Industry/occupation */
  industry: string;
  /** Is Politically Exposed Person */
  isPEP: boolean;
  /** PEP type if applicable */
  pepType?: 'DIRECT' | 'RELATIVE' | 'CLOSE_ASSOCIATE';
  /** Sanctions list matches */
  sanctionsHits: number;
  /** Watchlist matches */
  watchlistHits: number;
  /** Adverse media hits */
  adverseMediaHits: number;
  /** Risk category */
  riskCategory: CustomerRiskCategory;
  /** Overall risk score (0-100) */
  riskScore: number;
  /** Typical transaction volume */
  typicalMonthlyVolume: number;
  /** Typical transaction count */
  typicalMonthlyCount: number;
  /** Source of wealth */
  sourceOfWealth?: string;
  /** Source of funds */
  sourceOfFunds?: string;
  /** Date of birth (individuals) */
  dateOfBirth?: string;
  /** Date of incorporation (businesses) */
  incorporationDate?: string;
  /** Beneficial owners (for businesses) */
  beneficialOwners?: string[];
  /** KYC last verified date */
  kycLastVerified?: string;
  /** Customer since date */
  customerSince: string;
}

/**
 * Transaction data
 */
export interface TransactionData {
  /** Transaction unique identifier */
  transactionId: string;
  /** Transaction amount */
  amount: number;
  /** Currency code */
  currency: string;
  /** Source account ID */
  sourceAccountId: string;
  /** Destination account ID (if internal) */
  destAccountId?: string;
  /** External destination (if outgoing) */
  externalDestination?: string;
  /** Source country */
  sourceCountry: string;
  /** Destination country */
  destCountry: string;
  /** Transaction channel */
  channel: TransactionChannel;
  /** Transaction type */
  type: TransactionType;
  /** Transaction timestamp */
  timestamp: string;
  /** Reference/memo */
  reference?: string;
  /** Originator name (for wires) */
  originatorName?: string;
  /** Beneficiary name (for wires) */
  beneficiaryName?: string;
  /** Is round amount */
  isRoundAmount?: boolean;
  /** Transaction tags */
  tags?: string[];
  /** Related transaction IDs (for structuring detection) */
  relatedTransactions?: string[];
}

/**
 * Alert data
 */
export interface AlertData {
  /** Alert unique identifier */
  alertId: string;
  /** Alert type */
  alertType: string;
  /** Severity */
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Status */
  status: AlertStatus;
  /** Related transaction IDs */
  transactionIds: string[];
  /** Related customer ID */
  customerId: string;
  /** Related account IDs */
  accountIds: string[];
  /** Alert description */
  description: string;
  /** Created at */
  createdAt: string;
  /** Assigned analyst */
  assignedTo?: string;
  /** Resolution notes */
  resolutionNotes?: string;
}

/**
 * AML event payload types
 */
export interface TransactionPostedPayload {
  transaction: TransactionData;
  account: AccountData;
  customer: CustomerData;
  /** Recent transaction history for pattern detection */
  recentTransactions?: TransactionData[];
  /** Aggregated stats for the day */
  dailyStats?: {
    totalAmount: number;
    transactionCount: number;
    cashAmount: number;
    cashCount: number;
  };
  /** Aggregated stats for the period */
  periodStats?: {
    periodDays: number;
    totalAmount: number;
    transactionCount: number;
    avgTransactionAmount: number;
  };
}

export interface AccountOpenedPayload {
  account: AccountData;
  customer: CustomerData;
}

export interface AlertEscalatedPayload {
  alert: AlertData;
  customer: CustomerData;
  transactions: TransactionData[];
  escalationReason: string;
}

export type AMLEventPayload =
  | TransactionPostedPayload
  | AccountOpenedPayload
  | AlertEscalatedPayload;

/**
 * AML domain event types
 */
export type AMLEventType =
  | 'TRANSACTION_POSTED'
  | 'TRANSACTION_REVERSED'
  | 'ACCOUNT_OPENED'
  | 'ACCOUNT_CLOSED'
  | 'ACCOUNT_FROZEN'
  | 'CUSTOMER_UPDATED'
  | 'KYC_VERIFIED'
  | 'KYC_EXPIRED'
  | 'ALERT_CREATED'
  | 'ALERT_ESCALATED'
  | 'ALERT_CLOSED'
  | 'SAR_FILED'
  | 'SANCTIONS_HIT'
  | 'WATCHLIST_HIT';

/**
 * High-risk countries (FATF/sanctions)
 */
export const HIGH_RISK_COUNTRIES: Record<string, CountryRiskLevel> = {
  // FATF Black List / Call for Action
  'KP': 'SANCTIONED', // North Korea
  'IR': 'SANCTIONED', // Iran
  'MM': 'VERY_HIGH',  // Myanmar
  // FATF Grey List / Increased Monitoring (sample)
  'SY': 'VERY_HIGH',  // Syria
  'YE': 'VERY_HIGH',  // Yemen
  'AF': 'HIGH',       // Afghanistan
  'PK': 'HIGH',       // Pakistan
  'NG': 'HIGH',       // Nigeria
  'HT': 'HIGH',       // Haiti
  'JM': 'HIGH',       // Jamaica
  'PH': 'HIGH',       // Philippines
  'ZW': 'HIGH',       // Zimbabwe
  // Offshore financial centers (elevated risk)
  'KY': 'MEDIUM',     // Cayman Islands
  'VG': 'MEDIUM',     // British Virgin Islands
  'PA': 'MEDIUM',     // Panama
  'BZ': 'MEDIUM',     // Belize
};

/**
 * Currency risk levels
 */
export const CURRENCY_RISK: Record<string, 'LOW' | 'MEDIUM' | 'HIGH'> = {
  'USD': 'LOW',
  'EUR': 'LOW',
  'GBP': 'LOW',
  'JPY': 'LOW',
  'CHF': 'LOW',
  'CAD': 'LOW',
  'AUD': 'LOW',
  'RUB': 'HIGH',
  'CNY': 'MEDIUM',
  'BTC': 'HIGH',
  'ETH': 'HIGH',
  'USDT': 'HIGH',
};

/**
 * Regulatory thresholds
 */
export const AML_THRESHOLDS = {
  // BSA/AML Currency Transaction Report threshold
  CTR_THRESHOLD: 10000,
  // Suspicious Activity Report consideration threshold
  SAR_CONSIDERATION_THRESHOLD: 5000,
  // Structuring detection window (days)
  STRUCTURING_WINDOW_DAYS: 14,
  // Structuring detection threshold (just under CTR)
  STRUCTURING_AMOUNT_MIN: 8000,
  STRUCTURING_AMOUNT_MAX: 9999,
  // Velocity thresholds
  HIGH_VELOCITY_COUNT_24H: 10,
  HIGH_VELOCITY_COUNT_7D: 50,
  // PEP enhanced threshold
  PEP_ENHANCED_THRESHOLD: 5000,
  // High-risk country threshold
  HIGH_RISK_COUNTRY_THRESHOLD: 3000,
  // Cash intensive business threshold
  CASH_INTENSIVE_THRESHOLD: 15000,
  // Round amount tolerance
  ROUND_AMOUNT_TOLERANCE: 100,
};

/**
 * High-risk industries
 */
export const HIGH_RISK_INDUSTRIES = [
  'MONEY_SERVICE_BUSINESS',
  'CASINO_GAMBLING',
  'CRYPTOCURRENCY',
  'PRECIOUS_METALS',
  'ARMS_DEFENSE',
  'ADULT_ENTERTAINMENT',
  'CANNABIS',
  'CASH_INTENSIVE_RETAIL',
  'USED_CAR_DEALER',
  'REAL_ESTATE',
  'ART_ANTIQUES',
  'PRIVATE_ATM',
  'THIRD_PARTY_PAYMENT',
];

/**
 * Get country risk level
 */
export function getCountryRisk(countryCode: string): CountryRiskLevel {
  return HIGH_RISK_COUNTRIES[countryCode] ?? 'LOW';
}

/**
 * Check if amount is just under CTR threshold (structuring indicator)
 */
export function isStructuringAmount(amount: number): boolean {
  return amount >= AML_THRESHOLDS.STRUCTURING_AMOUNT_MIN &&
         amount <= AML_THRESHOLDS.STRUCTURING_AMOUNT_MAX;
}

/**
 * Check if amount is a round number (red flag for certain patterns)
 */
export function isRoundAmount(amount: number, tolerance: number = 100): boolean {
  return amount % tolerance === 0 && amount >= 1000;
}

/**
 * Calculate transaction anomaly score
 */
export function calculateAnomalyScore(
  amount: number,
  typicalAmount: number,
  stdDev: number = 0
): number {
  if (stdDev === 0) {
    // Simple ratio-based score
    const ratio = amount / typicalAmount;
    if (ratio > 10) return 100;
    if (ratio > 5) return 80;
    if (ratio > 3) return 60;
    if (ratio > 2) return 40;
    return 0;
  }
  // Z-score based
  const zScore = Math.abs((amount - typicalAmount) / stdDev);
  return Math.min(100, zScore * 20);
}
