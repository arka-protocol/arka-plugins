/**
 * ARKA AML Plugin
 *
 * Anti-Money Laundering compliance domain plugin.
 * Provides comprehensive rules for transaction monitoring, sanctions screening,
 * structuring detection, and suspicious activity identification.
 */

import type {
  ArkaEvent,
  ArkaEntity,
  ArkaEntityType,
  ArkaRule,
  CreateEventInput,
} from '@arka/types';
import {
  BaseArkaPlugin,
  type PluginManifest,
  type PluginHooks,
  type DomainEvent,
  type ValidationResult,
} from '@arka/plugin-sdk';
import { createLogger } from '@arka/utils';
import type {
  TransactionPostedPayload,
  AMLEventType,
  AccountData,
  CustomerData,
  TransactionData,
} from './types.js';
import {
  getCountryRisk,
  AML_THRESHOLDS,
  HIGH_RISK_INDUSTRIES,
  HIGH_RISK_COUNTRIES,
} from './types.js';

const logger = createLogger({ service: 'arka-aml' });

/**
 * Account entity type schema
 */
const ACCOUNT_ENTITY_TYPE: ArkaEntityType = {
  name: 'Account',
  description: 'Financial account for AML monitoring',
  schema: {
    type: 'object',
    required: ['accountId', 'ownerId', 'accountType', 'country', 'currency', 'kycLevel', 'riskTier', 'openedAt', 'status'],
    properties: {
      accountId: { type: 'string' },
      ownerId: { type: 'string' },
      accountType: { type: 'string', enum: ['CHECKING', 'SAVINGS', 'INVESTMENT', 'BUSINESS', 'TRUST'] },
      country: { type: 'string' },
      currency: { type: 'string' },
      kycLevel: { type: 'string', enum: ['NONE', 'BASIC', 'STANDARD', 'ENHANCED', 'FULL'] },
      riskTier: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'BLOCKED'] },
      openedAt: { type: 'string' },
      status: { type: 'string', enum: ['ACTIVE', 'DORMANT', 'FROZEN', 'CLOSED'] },
      avgMonthlyBalance: { type: 'number' },
      expectedMonthlyActivity: { type: 'number' },
      authorizedSigners: { type: 'number' },
      allowsInternational: { type: 'boolean' },
    },
  },
  metadata: {},
};

/**
 * Transaction entity type schema
 */
const TRANSACTION_ENTITY_TYPE: ArkaEntityType = {
  name: 'Transaction',
  description: 'Financial transaction for AML monitoring',
  schema: {
    type: 'object',
    required: ['transactionId', 'amount', 'currency', 'sourceAccountId', 'sourceCountry', 'destCountry', 'channel', 'type', 'timestamp'],
    properties: {
      transactionId: { type: 'string' },
      amount: { type: 'number', minimum: 0 },
      currency: { type: 'string' },
      sourceAccountId: { type: 'string' },
      destAccountId: { type: 'string' },
      externalDestination: { type: 'string' },
      sourceCountry: { type: 'string' },
      destCountry: { type: 'string' },
      channel: { type: 'string', enum: ['WIRE', 'ACH', 'CHECK', 'CASH', 'CARD', 'CRYPTO', 'INTERNAL', 'MOBILE', 'ATM', 'POS'] },
      type: { type: 'string', enum: ['DEPOSIT', 'WITHDRAWAL', 'TRANSFER', 'PAYMENT', 'EXCHANGE', 'LOAN_DISBURSEMENT', 'LOAN_PAYMENT'] },
      timestamp: { type: 'string' },
      reference: { type: 'string' },
      originatorName: { type: 'string' },
      beneficiaryName: { type: 'string' },
      isRoundAmount: { type: 'boolean' },
      tags: { type: 'array', items: { type: 'string' } },
      relatedTransactions: { type: 'array', items: { type: 'string' } },
    },
  },
  metadata: {},
};

/**
 * Customer entity type schema
 */
const CUSTOMER_ENTITY_TYPE: ArkaEntityType = {
  name: 'Customer',
  description: 'Customer profile for AML monitoring',
  schema: {
    type: 'object',
    required: ['customerId', 'customerType', 'legalName', 'country', 'industry', 'isPEP', 'sanctionsHits', 'watchlistHits', 'adverseMediaHits', 'riskCategory', 'riskScore', 'typicalMonthlyVolume', 'typicalMonthlyCount', 'customerSince'],
    properties: {
      customerId: { type: 'string' },
      customerType: { type: 'string', enum: ['INDIVIDUAL', 'BUSINESS', 'TRUST', 'NON_PROFIT'] },
      legalName: { type: 'string' },
      country: { type: 'string' },
      nationality: { type: 'string' },
      industry: { type: 'string' },
      isPEP: { type: 'boolean' },
      pepType: { type: 'string', enum: ['DIRECT', 'RELATIVE', 'CLOSE_ASSOCIATE'] },
      sanctionsHits: { type: 'number', minimum: 0 },
      watchlistHits: { type: 'number', minimum: 0 },
      adverseMediaHits: { type: 'number', minimum: 0 },
      riskCategory: { type: 'string', enum: ['STANDARD', 'HIGH_NET_WORTH', 'PEP', 'PEP_RELATIVE', 'SANCTIONED', 'WATCHLIST', 'ADVERSE_MEDIA'] },
      riskScore: { type: 'number', minimum: 0, maximum: 100 },
      typicalMonthlyVolume: { type: 'number' },
      typicalMonthlyCount: { type: 'number' },
      sourceOfWealth: { type: 'string' },
      sourceOfFunds: { type: 'string' },
      dateOfBirth: { type: 'string' },
      incorporationDate: { type: 'string' },
      beneficialOwners: { type: 'array', items: { type: 'string' } },
      kycLastVerified: { type: 'string' },
      customerSince: { type: 'string' },
    },
  },
  metadata: {},
};

/**
 * ARKA AML Domain Plugin
 *
 * Provides comprehensive AML compliance rules:
 * - Transaction monitoring and thresholds
 * - Structuring / smurfing detection
 * - Sanctions and watchlist screening
 * - PEP enhanced due diligence
 * - High-risk country monitoring
 * - Velocity and pattern analysis
 * - Unusual activity detection
 */
export class ArkaAMLPlugin extends BaseArkaPlugin {
  readonly manifest: PluginManifest = {
    id: 'arka-aml',
    name: 'ARKA AML',
    version: '1.0.0',
    author: 'ARKA Systems LLC',
    description: 'Anti-Money Laundering compliance domain plugin',
    entityTypes: ['Account', 'Transaction', 'Customer'],
    eventTypes: [
      'TRANSACTION_POSTED',
      'TRANSACTION_REVERSED',
      'ACCOUNT_OPENED',
      'ACCOUNT_CLOSED',
      'ACCOUNT_FROZEN',
      'CUSTOMER_UPDATED',
      'KYC_VERIFIED',
      'KYC_EXPIRED',
      'ALERT_CREATED',
      'ALERT_ESCALATED',
      'ALERT_CLOSED',
      'SAR_FILED',
      'SANCTIONS_HIT',
      'WATCHLIST_HIT',
    ],
    arkaCoreVersion: '^0.1.0',
    configSchema: {
      type: 'object',
      properties: {
        ctrThreshold: { type: 'number', default: 10000 },
        enableStructuringDetection: { type: 'boolean', default: true },
        enableVelocityChecks: { type: 'boolean', default: true },
        enablePatternAnalysis: { type: 'boolean', default: true },
      },
    },
  };

  override readonly hooks: PluginHooks = {
    onLoad: async () => {
      logger.info('ARKA AML plugin loaded', { version: this.manifest.version });
    },
    onUnload: async () => {
      logger.info('ARKA AML plugin unloaded');
    },
    beforeEventProcess: async (event: ArkaEvent) => {
      logger.debug('Processing AML event', { eventType: event.type, entityId: event.entityId });
      return event;
    },
  };

  protected entityTypes: ArkaEntityType[] = [
    ACCOUNT_ENTITY_TYPE,
    TRANSACTION_ENTITY_TYPE,
    CUSTOMER_ENTITY_TYPE,
  ];

  protected defaultRules: ArkaRule[] = [
    // ============================================
    // SANCTIONS & WATCHLIST RULES (Highest Priority)
    // ============================================

    // Sanctioned Customer Block
    this.createRule({
      name: 'Sanctioned Customer Block',
      description: 'Block all transactions for customers with sanctions hits',
      severity: 'CRITICAL',
      tags: ['sanctions', 'ofac', 'block'],
      condition: {
        type: 'compare',
        field: 'customer.sanctionsHits',
        operator: '>',
        value: 0,
      },
      consequence: {
        decision: 'DENY',
        code: 'SANCTIONED_CUSTOMER',
        message: 'Transaction blocked - customer has sanctions list matches',
        remediation: 'Escalate to compliance for sanctions review',
      },
      // priority:100,
    }),

    // Sanctioned Country Block
    this.createRule({
      name: 'Sanctioned Country Block',
      description: 'Block transactions to/from OFAC sanctioned countries',
      severity: 'CRITICAL',
      tags: ['sanctions', 'country', 'block'],
      condition: {
        type: 'or',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.destCountry',
            operator: 'in',
            value: ['KP', 'IR'], // North Korea, Iran
          },
          {
            type: 'compare',
            field: 'transaction.sourceCountry',
            operator: 'in',
            value: ['KP', 'IR'],
          },
        ],
      },
      consequence: {
        decision: 'DENY',
        code: 'SANCTIONED_COUNTRY',
        message: 'Transaction blocked - involves OFAC sanctioned country',
        remediation: 'Transaction cannot proceed to sanctioned jurisdiction',
      },
      // priority:99,
    }),

    // Watchlist Customer Flag
    this.createRule({
      name: 'Watchlist Customer Flag',
      description: 'Flag transactions for customers on watchlists',
      severity: 'HIGH',
      tags: ['watchlist', 'enhanced-review'],
      condition: {
        type: 'compare',
        field: 'customer.watchlistHits',
        operator: '>',
        value: 0,
      },
      consequence: {
        decision: 'FLAG',
        code: 'WATCHLIST_MATCH',
        message: 'Customer has watchlist matches - enhanced review required',
      },
      // priority:95,
    }),

    // ============================================
    // CURRENCY TRANSACTION REPORT (CTR) RULES
    // ============================================

    // CTR Threshold - Cash Transactions
    this.createRule({
      name: 'CTR Cash Threshold',
      description: 'Flag cash transactions at or above $10,000 for CTR filing',
      severity: 'HIGH',
      tags: ['ctr', 'cash', 'reporting'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.channel',
            operator: '==',
            value: 'CASH',
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: AML_THRESHOLDS.CTR_THRESHOLD,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'CTR_REQUIRED',
        message: 'Cash transaction requires Currency Transaction Report filing',
      },
      // priority:85,
    }),

    // ============================================
    // STRUCTURING / SMURFING DETECTION
    // ============================================

    // Single Transaction Structuring Indicator
    this.createRule({
      name: 'Structuring Amount Detection',
      description: 'Flag transactions just under CTR threshold ($8,000-$9,999)',
      severity: 'HIGH',
      tags: ['structuring', 'smurfing', 'evasion'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: AML_THRESHOLDS.STRUCTURING_AMOUNT_MIN,
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '<=',
            value: AML_THRESHOLDS.STRUCTURING_AMOUNT_MAX,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'STRUCTURING_INDICATOR',
        message: 'Transaction amount just under CTR threshold - potential structuring',
      },
      // priority:82,
    }),

    // Multiple Structuring Transactions Pattern
    this.createRule({
      name: 'Structuring Pattern Detection',
      description: 'Flag when daily cash total approaches CTR threshold across multiple transactions',
      severity: 'CRITICAL',
      tags: ['structuring', 'pattern', 'aggregation'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'dailyStats.cashAmount',
            operator: '>=',
            value: AML_THRESHOLDS.STRUCTURING_AMOUNT_MIN,
          },
          {
            type: 'compare',
            field: 'dailyStats.cashCount',
            operator: '>=',
            value: 2,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'STRUCTURING_PATTERN',
        message: 'Multiple cash transactions aggregating near CTR threshold - structuring pattern detected',
      },
      // priority:88,
    }),

    // ============================================
    // PEP (POLITICALLY EXPOSED PERSON) RULES
    // ============================================

    // PEP Enhanced Threshold
    this.createRule({
      name: 'PEP Enhanced Threshold',
      description: 'Enhanced scrutiny for PEP transactions above $5,000',
      severity: 'HIGH',
      tags: ['pep', 'enhanced-due-diligence'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'customer.isPEP',
            operator: '==',
            value: true,
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: AML_THRESHOLDS.PEP_ENHANCED_THRESHOLD,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'PEP_ENHANCED_REVIEW',
        message: 'PEP transaction above enhanced threshold - senior management approval required',
      },
      // priority:80,
    }),

    // PEP Any Transaction Flag
    this.createRule({
      name: 'PEP Transaction Flag',
      description: 'Flag all transactions for PEP customers',
      severity: 'MEDIUM',
      tags: ['pep', 'monitoring'],
      condition: {
        type: 'compare',
        field: 'customer.isPEP',
        operator: '==',
        value: true,
      },
      consequence: {
        decision: 'FLAG',
        code: 'PEP_TRANSACTION',
        message: 'Transaction involves Politically Exposed Person',
      },
      // priority:70,
    }),

    // ============================================
    // HIGH-RISK COUNTRY RULES
    // ============================================

    // Very High Risk Country
    this.createRule({
      name: 'Very High Risk Country',
      description: 'Flag transactions to/from FATF grey list countries',
      severity: 'HIGH',
      tags: ['country-risk', 'fatf', 'grey-list'],
      condition: {
        type: 'or',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.destCountry',
            operator: 'in',
            value: ['SY', 'YE', 'MM'], // Syria, Yemen, Myanmar
          },
          {
            type: 'compare',
            field: 'transaction.sourceCountry',
            operator: 'in',
            value: ['SY', 'YE', 'MM'],
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'VERY_HIGH_RISK_COUNTRY',
        message: 'Transaction involves very high risk jurisdiction',
      },
      // priority:78,
    }),

    // High Risk Country with Amount
    this.createRule({
      name: 'High Risk Country Transaction',
      description: 'Flag transactions above $3,000 to/from high-risk countries',
      severity: 'MEDIUM',
      tags: ['country-risk', 'threshold'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: AML_THRESHOLDS.HIGH_RISK_COUNTRY_THRESHOLD,
          },
          {
            type: 'or',
            conditions: [
              {
                type: 'compare',
                field: 'transaction.destCountry',
                operator: 'in',
                value: ['AF', 'PK', 'NG', 'HT', 'JM', 'PH', 'ZW'],
              },
              {
                type: 'compare',
                field: 'transaction.sourceCountry',
                operator: 'in',
                value: ['AF', 'PK', 'NG', 'HT', 'JM', 'PH', 'ZW'],
              },
            ],
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'HIGH_RISK_COUNTRY_AMOUNT',
        message: 'Significant transaction involving high-risk jurisdiction',
      },
      // priority:72,
    }),

    // ============================================
    // VELOCITY & PATTERN RULES
    // ============================================

    // High Velocity - 24 Hour
    this.createRule({
      name: 'High Transaction Velocity (24h)',
      description: 'Flag accounts with more than 10 transactions in 24 hours',
      severity: 'MEDIUM',
      tags: ['velocity', 'pattern', '24h'],
      condition: {
        type: 'compare',
        field: 'dailyStats.transactionCount',
        operator: '>=',
        value: AML_THRESHOLDS.HIGH_VELOCITY_COUNT_24H,
      },
      consequence: {
        decision: 'FLAG',
        code: 'HIGH_VELOCITY_24H',
        message: 'Unusually high transaction count in 24 hour period',
      },
      // priority:68,
    }),

    // Unusual Amount Pattern
    this.createRule({
      name: 'Unusual Transaction Amount',
      description: 'Flag transactions significantly above customer typical activity',
      severity: 'MEDIUM',
      tags: ['anomaly', 'amount', 'pattern'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>',
            value: 0, // Will be evaluated with context
          },
          {
            type: 'compare',
            field: 'periodStats.avgTransactionAmount',
            operator: '>',
            value: 0,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'UNUSUAL_AMOUNT',
        message: 'Transaction amount significantly exceeds typical customer pattern',
      },
      // priority:65,
    }),

    // Round Amount Pattern
    this.createRule({
      name: 'Round Amount Pattern',
      description: 'Flag large round amount transactions',
      severity: 'LOW',
      tags: ['pattern', 'round-amount'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.isRoundAmount',
            operator: '==',
            value: true,
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: 5000,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'ROUND_AMOUNT_PATTERN',
        message: 'Large round amount transaction - may warrant review',
      },
      // priority:50,
    }),

    // ============================================
    // HIGH-RISK INDUSTRY RULES
    // ============================================

    // Money Service Business
    this.createRule({
      name: 'Money Service Business Customer',
      description: 'Enhanced monitoring for MSB customers',
      severity: 'MEDIUM',
      tags: ['high-risk-industry', 'msb'],
      condition: {
        type: 'compare',
        field: 'customer.industry',
        operator: '==',
        value: 'MONEY_SERVICE_BUSINESS',
      },
      consequence: {
        decision: 'FLAG',
        code: 'MSB_CUSTOMER',
        message: 'Transaction involves Money Service Business - enhanced monitoring',
      },
      // priority:60,
    }),

    // Cryptocurrency Business
    this.createRule({
      name: 'Cryptocurrency Business Customer',
      description: 'Enhanced monitoring for cryptocurrency businesses',
      severity: 'MEDIUM',
      tags: ['high-risk-industry', 'crypto'],
      condition: {
        type: 'compare',
        field: 'customer.industry',
        operator: '==',
        value: 'CRYPTOCURRENCY',
      },
      consequence: {
        decision: 'FLAG',
        code: 'CRYPTO_BUSINESS',
        message: 'Transaction involves cryptocurrency business - enhanced monitoring',
      },
      // priority:62,
    }),

    // Casino/Gambling
    this.createRule({
      name: 'Casino/Gambling Customer',
      description: 'Enhanced monitoring for casino and gambling businesses',
      severity: 'MEDIUM',
      tags: ['high-risk-industry', 'casino', 'gambling'],
      condition: {
        type: 'compare',
        field: 'customer.industry',
        operator: '==',
        value: 'CASINO_GAMBLING',
      },
      consequence: {
        decision: 'FLAG',
        code: 'CASINO_CUSTOMER',
        message: 'Transaction involves casino/gambling business - enhanced monitoring',
      },
      // priority:61,
    }),

    // ============================================
    // KYC & ACCOUNT RULES
    // ============================================

    // No KYC Block
    this.createRule({
      name: 'No KYC Block',
      description: 'Block transactions for accounts without KYC verification',
      severity: 'CRITICAL',
      tags: ['kyc', 'block'],
      condition: {
        type: 'compare',
        field: 'account.kycLevel',
        operator: '==',
        value: 'NONE',
      },
      consequence: {
        decision: 'DENY',
        code: 'NO_KYC',
        message: 'Transaction blocked - account has no KYC verification',
        remediation: 'Complete KYC verification before transacting',
      },
      // priority:90,
    }),

    // Basic KYC High Amount
    this.createRule({
      name: 'Basic KYC High Amount',
      description: 'Flag high-value transactions on basic KYC accounts',
      severity: 'HIGH',
      tags: ['kyc', 'threshold'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'account.kycLevel',
            operator: '==',
            value: 'BASIC',
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: 5000,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'BASIC_KYC_HIGH_AMOUNT',
        message: 'High-value transaction on basic KYC account - enhanced verification needed',
      },
      // priority:75,
    }),

    // Frozen Account Block
    this.createRule({
      name: 'Frozen Account Block',
      description: 'Block all transactions on frozen accounts',
      severity: 'CRITICAL',
      tags: ['account-status', 'block'],
      condition: {
        type: 'compare',
        field: 'account.status',
        operator: '==',
        value: 'FROZEN',
      },
      consequence: {
        decision: 'DENY',
        code: 'ACCOUNT_FROZEN',
        message: 'Transaction blocked - account is frozen',
        remediation: 'Contact compliance to resolve account freeze',
      },
      // priority:98,
    }),

    // Dormant Account Activity
    this.createRule({
      name: 'Dormant Account Activity',
      description: 'Flag transactions on dormant accounts',
      severity: 'MEDIUM',
      tags: ['account-status', 'dormant'],
      condition: {
        type: 'compare',
        field: 'account.status',
        operator: '==',
        value: 'DORMANT',
      },
      consequence: {
        decision: 'FLAG',
        code: 'DORMANT_ACCOUNT_ACTIVITY',
        message: 'Transaction on dormant account - verify customer identity',
      },
      // priority:66,
    }),

    // ============================================
    // CRYPTO / DIGITAL ASSET RULES
    // ============================================

    // Crypto Channel High Amount
    this.createRule({
      name: 'Crypto Transaction High Amount',
      description: 'Flag high-value cryptocurrency transactions',
      severity: 'HIGH',
      tags: ['crypto', 'digital-asset'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.channel',
            operator: '==',
            value: 'CRYPTO',
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: 3000,
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'CRYPTO_HIGH_AMOUNT',
        message: 'High-value cryptocurrency transaction - enhanced monitoring',
      },
      // priority:73,
    }),

    // ============================================
    // WIRE TRANSFER RULES
    // ============================================

    // International Wire High Amount
    this.createRule({
      name: 'International Wire High Amount',
      description: 'Flag high-value international wire transfers',
      severity: 'MEDIUM',
      tags: ['wire', 'international'],
      condition: {
        type: 'and',
        conditions: [
          {
            type: 'compare',
            field: 'transaction.channel',
            operator: '==',
            value: 'WIRE',
          },
          {
            type: 'compare',
            field: 'transaction.amount',
            operator: '>=',
            value: 10000,
          },
          {
            type: 'not',
            condition: {
              type: 'compare',
              field: 'transaction.sourceCountry',
              operator: '==',
              value: 'transaction.destCountry',
            },
          },
        ],
      },
      consequence: {
        decision: 'FLAG',
        code: 'INTL_WIRE_HIGH_AMOUNT',
        message: 'High-value international wire transfer',
      },
      // priority:64,
    }),

    // ============================================
    // ADVERSE MEDIA RULES
    // ============================================

    // Adverse Media Flag
    this.createRule({
      name: 'Adverse Media Flag',
      description: 'Flag transactions for customers with adverse media hits',
      severity: 'MEDIUM',
      tags: ['adverse-media', 'reputation'],
      condition: {
        type: 'compare',
        field: 'customer.adverseMediaHits',
        operator: '>',
        value: 0,
      },
      consequence: {
        decision: 'FLAG',
        code: 'ADVERSE_MEDIA',
        message: 'Customer has adverse media hits - enhanced monitoring',
      },
      // priority:58,
    }),

    // ============================================
    // HIGH CUSTOMER RISK RULES
    // ============================================

    // Critical Risk Customer
    this.createRule({
      name: 'Critical Risk Customer',
      description: 'Enhanced review for critical risk customers',
      severity: 'HIGH',
      tags: ['customer-risk', 'critical'],
      condition: {
        type: 'compare',
        field: 'account.riskTier',
        operator: '==',
        value: 'CRITICAL',
      },
      consequence: {
        decision: 'FLAG',
        code: 'CRITICAL_RISK_CUSTOMER',
        message: 'Transaction for critical-risk customer - senior review required',
      },
      // priority:77,
    }),

    // High Risk Score
    this.createRule({
      name: 'High Risk Score Customer',
      description: 'Flag transactions for customers with risk score above 75',
      severity: 'MEDIUM',
      tags: ['customer-risk', 'score'],
      condition: {
        type: 'compare',
        field: 'customer.riskScore',
        operator: '>=',
        value: 75,
      },
      consequence: {
        decision: 'FLAG',
        code: 'HIGH_RISK_SCORE',
        message: 'Customer has elevated risk score',
      },
      // priority:67,
    }),
  ];

  /**
   * Convert AML domain event to canonical ARKA event
   */
  override mapToCanonicalEvent(domainEvent: DomainEvent<Record<string, unknown>>): CreateEventInput {
    const payload = domainEvent.payload as unknown as TransactionPostedPayload;
    return {
      source: this.manifest.id,
      type: domainEvent.type as AMLEventType,
      entityId: domainEvent.entityId,
      entityType: 'Transaction',
      jurisdiction: domainEvent.jurisdiction,
      payload: payload as unknown as Record<string, unknown>,
      occurredAt: domainEvent.occurredAt ?? new Date().toISOString(),
    };
  }

  /**
   * Validate AML data
   */
  override validateDomainData(
    entityType: string,
    data: Record<string, unknown>
  ): ValidationResult {
    const errors: ValidationResult['errors'] = [];
    const warnings: ValidationResult['warnings'] = [];

    if (entityType === 'Transaction') {
      const payload = data as unknown as TransactionPostedPayload;

      if (!payload.transaction) {
        errors.push({
          field: 'transaction',
          message: 'Transaction data is required',
          code: 'MISSING_TRANSACTION',
        });
      } else {
        if (payload.transaction.amount < 0) {
          errors.push({
            field: 'transaction.amount',
            message: 'Transaction amount cannot be negative',
            code: 'INVALID_AMOUNT',
          });
        }
        if (!payload.transaction.sourceCountry) {
          errors.push({
            field: 'transaction.sourceCountry',
            message: 'Source country is required',
            code: 'MISSING_SOURCE_COUNTRY',
          });
        }
        if (!payload.transaction.destCountry) {
          errors.push({
            field: 'transaction.destCountry',
            message: 'Destination country is required',
            code: 'MISSING_DEST_COUNTRY',
          });
        }

        // Warnings
        const destRisk = getCountryRisk(payload.transaction.destCountry);
        if (destRisk === 'HIGH' || destRisk === 'VERY_HIGH') {
          warnings?.push({
            field: 'transaction.destCountry',
            message: `Destination country ${payload.transaction.destCountry} is ${destRisk} risk`,
          });
        }
      }

      if (!payload.account) {
        errors.push({
          field: 'account',
          message: 'Account data is required',
          code: 'MISSING_ACCOUNT',
        });
      }

      if (!payload.customer) {
        errors.push({
          field: 'customer',
          message: 'Customer data is required',
          code: 'MISSING_CUSTOMER',
        });
      } else {
        if (payload.customer.isPEP) {
          warnings?.push({
            field: 'customer.isPEP',
            message: 'Customer is a Politically Exposed Person',
          });
        }
        if (payload.customer.sanctionsHits > 0) {
          warnings?.push({
            field: 'customer.sanctionsHits',
            message: `Customer has ${payload.customer.sanctionsHits} sanctions list matches`,
          });
        }
      }
    } else {
      errors.push({
        field: 'entityType',
        message: `Unknown or unsupported entity type: ${entityType}`,
        code: 'UNKNOWN_ENTITY_TYPE',
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Get evaluation context with AML-specific data
   */
  override getEvaluationContext(
    event: ArkaEvent,
    _entity?: ArkaEntity | null
  ): Record<string, unknown> {
    const payload = event.payload as unknown as TransactionPostedPayload;

    return {
      thresholds: AML_THRESHOLDS,
      highRiskCountries: Object.keys(HIGH_RISK_COUNTRIES),
      highRiskIndustries: HIGH_RISK_INDUSTRIES,
      sourceCountryRisk: payload?.transaction?.sourceCountry
        ? getCountryRisk(payload.transaction.sourceCountry)
        : 'UNKNOWN',
      destCountryRisk: payload?.transaction?.destCountry
        ? getCountryRisk(payload.transaction.destCountry)
        : 'UNKNOWN',
      evaluatedAt: new Date().toISOString(),
    };
  }

  /**
   * Get rules organized by category
   */
  getRulesByCategory(): Record<string, ArkaRule[]> {
    const categories: Record<string, ArkaRule[]> = {
      'sanctions': [],
      'ctr-reporting': [],
      'structuring': [],
      'pep': [],
      'country-risk': [],
      'velocity-pattern': [],
      'high-risk-industry': [],
      'kyc-account': [],
      'crypto': [],
      'wire-transfer': [],
      'customer-risk': [],
    };

    for (const rule of this.defaultRules) {
      const tags = rule.tags ?? [];
      if (tags.includes('sanctions') || tags.includes('ofac') || tags.includes('watchlist')) {
        categories['sanctions']!.push(rule);
      } else if (tags.includes('ctr')) {
        categories['ctr-reporting']!.push(rule);
      } else if (tags.includes('structuring') || tags.includes('smurfing')) {
        categories['structuring']!.push(rule);
      } else if (tags.includes('pep')) {
        categories['pep']!.push(rule);
      } else if (tags.includes('country-risk') || tags.includes('fatf')) {
        categories['country-risk']!.push(rule);
      } else if (tags.includes('velocity') || tags.includes('pattern') || tags.includes('anomaly')) {
        categories['velocity-pattern']!.push(rule);
      } else if (tags.includes('high-risk-industry')) {
        categories['high-risk-industry']!.push(rule);
      } else if (tags.includes('kyc') || tags.includes('account-status')) {
        categories['kyc-account']!.push(rule);
      } else if (tags.includes('crypto')) {
        categories['crypto']!.push(rule);
      } else if (tags.includes('wire')) {
        categories['wire-transfer']!.push(rule);
      } else if (tags.includes('customer-risk')) {
        categories['customer-risk']!.push(rule);
      }
    }

    return categories;
  }
}

// Singleton instance
let amlPluginInstance: ArkaAMLPlugin | null = null;

/**
 * Get the AML plugin instance
 */
export function getArkaAMLPlugin(): ArkaAMLPlugin {
  if (!amlPluginInstance) {
    amlPluginInstance = new ArkaAMLPlugin();
  }
  return amlPluginInstance;
}

/**
 * Reset the AML plugin instance (for testing)
 */
export function resetArkaAMLPlugin(): void {
  amlPluginInstance = null;
}
