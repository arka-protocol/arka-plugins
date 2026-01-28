/**
 * @arka/aml Plugin Tests
 *
 * Tests for the Anti-Money Laundering compliance plugin.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  PactAMLPlugin,
  getPactAMLPlugin,
  HIGH_RISK_COUNTRIES,
  AML_THRESHOLDS,
  HIGH_RISK_INDUSTRIES,
  getCountryRisk,
  isStructuringAmount,
  isRoundAmount,
  calculateAnomalyScore,
} from '../src/index.js';
import type {
  TransactionData,
  AccountData,
  CustomerData,
  KYCLevel,
  AccountRiskTier,
  CustomerRiskCategory,
} from '../src/types.js';

describe('PactAMLPlugin', () => {
  let plugin: PactAMLPlugin;

  beforeEach(() => {
    plugin = getPactAMLPlugin();
  });

  describe('Plugin Configuration', () => {
    it('should have correct plugin metadata', () => {
      expect(plugin.manifest.name).toBe('ARKA AML');
      expect(plugin.manifest.version).toBe('1.0.0');
      expect(plugin.manifest.id).toBe('arka-aml');
    });

    it('should define entity types', () => {
      const entityTypes = plugin.getEntityTypes();
      expect(entityTypes.length).toBe(3);

      const entityNames = entityTypes.map(e => e.name);
      expect(entityNames).toContain('Account');
      expect(entityNames).toContain('Transaction');
      expect(entityNames).toContain('Customer');
    });

    it('should define rules', () => {
      const rules = plugin.getDefaultRules();
      expect(rules.length).toBeGreaterThan(20);
    });

    it('should have rules with proper structure', () => {
      const rules = plugin.getDefaultRules();
      for (const rule of rules) {
        expect(rule.id).toBeDefined();
        expect(rule.name).toBeDefined();
        expect(rule.description).toBeDefined();
        expect(rule.condition).toBeDefined();
        expect(rule.consequence).toBeDefined();
        expect(['ALLOW', 'DENY', 'FLAG']).toContain(rule.consequence.decision);
      }
    });
  });

  describe('Helper Functions', () => {
    describe('getCountryRisk', () => {
      it('should return SANCTIONED for North Korea', () => {
        expect(getCountryRisk('KP')).toBe('SANCTIONED');
      });

      it('should return SANCTIONED for Iran', () => {
        expect(getCountryRisk('IR')).toBe('SANCTIONED');
      });

      it('should return VERY_HIGH for Syria', () => {
        expect(getCountryRisk('SY')).toBe('VERY_HIGH');
      });

      it('should return HIGH for Pakistan', () => {
        expect(getCountryRisk('PK')).toBe('HIGH');
      });

      it('should return MEDIUM for Cayman Islands', () => {
        expect(getCountryRisk('KY')).toBe('MEDIUM');
      });

      it('should return LOW for unknown countries', () => {
        expect(getCountryRisk('US')).toBe('LOW');
        expect(getCountryRisk('GB')).toBe('LOW');
        expect(getCountryRisk('DE')).toBe('LOW');
      });
    });

    describe('isStructuringAmount', () => {
      it('should return true for amounts in structuring range', () => {
        expect(isStructuringAmount(8000)).toBe(true);
        expect(isStructuringAmount(9000)).toBe(true);
        expect(isStructuringAmount(9500)).toBe(true);
        expect(isStructuringAmount(9999)).toBe(true);
      });

      it('should return false for amounts outside structuring range', () => {
        expect(isStructuringAmount(7999)).toBe(false);
        expect(isStructuringAmount(10000)).toBe(false);
        expect(isStructuringAmount(5000)).toBe(false);
        expect(isStructuringAmount(15000)).toBe(false);
      });
    });

    describe('isRoundAmount', () => {
      it('should return true for round amounts >= 1000', () => {
        expect(isRoundAmount(1000)).toBe(true);
        expect(isRoundAmount(5000)).toBe(true);
        expect(isRoundAmount(10000)).toBe(true);
        expect(isRoundAmount(100000)).toBe(true);
      });

      it('should return false for non-round amounts', () => {
        expect(isRoundAmount(1001)).toBe(false);
        expect(isRoundAmount(5123)).toBe(false);
        expect(isRoundAmount(9999)).toBe(false);
      });

      it('should return false for small round amounts', () => {
        expect(isRoundAmount(100)).toBe(false);
        expect(isRoundAmount(500)).toBe(false);
      });
    });

    describe('calculateAnomalyScore', () => {
      it('should return 0 for amounts at or below typical', () => {
        expect(calculateAnomalyScore(1000, 2000)).toBe(0);
        expect(calculateAnomalyScore(2000, 2000)).toBe(0);
      });

      it('should return scores based on ratio when no stdDev', () => {
        // ratio > 2 = 40, ratio > 3 = 60, ratio > 5 = 80, ratio > 10 = 100
        expect(calculateAnomalyScore(4000, 2000)).toBe(0); // 2x (not > 2)
        expect(calculateAnomalyScore(4001, 2000)).toBe(40); // > 2x
        expect(calculateAnomalyScore(6001, 2000)).toBe(60); // > 3x
        expect(calculateAnomalyScore(10001, 2000)).toBe(80); // > 5x
        expect(calculateAnomalyScore(20001, 2000)).toBe(100); // > 10x
      });

      it('should use z-score when stdDev is provided', () => {
        const score = calculateAnomalyScore(3000, 1000, 500);
        // z-score = (3000 - 1000) / 500 = 4
        // score = 4 * 20 = 80
        expect(score).toBe(80);
      });
    });
  });

  describe('Constants', () => {
    describe('HIGH_RISK_COUNTRIES', () => {
      it('should have sanctioned countries', () => {
        expect(HIGH_RISK_COUNTRIES['KP']).toBe('SANCTIONED');
        expect(HIGH_RISK_COUNTRIES['IR']).toBe('SANCTIONED');
      });

      it('should have very high risk countries', () => {
        expect(HIGH_RISK_COUNTRIES['SY']).toBe('VERY_HIGH');
        expect(HIGH_RISK_COUNTRIES['MM']).toBe('VERY_HIGH');
        expect(HIGH_RISK_COUNTRIES['YE']).toBe('VERY_HIGH');
      });

      it('should have high risk countries', () => {
        expect(HIGH_RISK_COUNTRIES['AF']).toBe('HIGH');
        expect(HIGH_RISK_COUNTRIES['PK']).toBe('HIGH');
        expect(HIGH_RISK_COUNTRIES['NG']).toBe('HIGH');
      });

      it('should have medium risk offshore centers', () => {
        expect(HIGH_RISK_COUNTRIES['KY']).toBe('MEDIUM');
        expect(HIGH_RISK_COUNTRIES['VG']).toBe('MEDIUM');
        expect(HIGH_RISK_COUNTRIES['PA']).toBe('MEDIUM');
      });
    });

    describe('AML_THRESHOLDS', () => {
      it('should have correct CTR threshold', () => {
        expect(AML_THRESHOLDS.CTR_THRESHOLD).toBe(10000);
      });

      it('should have correct structuring range', () => {
        expect(AML_THRESHOLDS.STRUCTURING_AMOUNT_MIN).toBe(8000);
        expect(AML_THRESHOLDS.STRUCTURING_AMOUNT_MAX).toBe(9999);
      });

      it('should have correct PEP threshold', () => {
        expect(AML_THRESHOLDS.PEP_ENHANCED_THRESHOLD).toBe(5000);
      });

      it('should have correct velocity thresholds', () => {
        expect(AML_THRESHOLDS.HIGH_VELOCITY_COUNT_24H).toBe(10);
        expect(AML_THRESHOLDS.HIGH_VELOCITY_COUNT_7D).toBe(50);
      });
    });

    describe('HIGH_RISK_INDUSTRIES', () => {
      it('should include key high-risk industries', () => {
        expect(HIGH_RISK_INDUSTRIES).toContain('MONEY_SERVICE_BUSINESS');
        expect(HIGH_RISK_INDUSTRIES).toContain('CASINO_GAMBLING');
        expect(HIGH_RISK_INDUSTRIES).toContain('CRYPTOCURRENCY');
        expect(HIGH_RISK_INDUSTRIES).toContain('PRECIOUS_METALS');
        expect(HIGH_RISK_INDUSTRIES).toContain('REAL_ESTATE');
        expect(HIGH_RISK_INDUSTRIES).toContain('CANNABIS');
      });
    });
  });

  describe('Rule Categories', () => {
    it('should have sanctions rules', () => {
      const rules = plugin.getDefaultRules();
      const sanctionsRules = rules.filter(r =>
        r.tags?.includes('sanctions') || r.name.toLowerCase().includes('sanction')
      );
      expect(sanctionsRules.length).toBeGreaterThan(0);
    });

    it('should have structuring detection rules', () => {
      const rules = plugin.getDefaultRules();
      const structuringRules = rules.filter(r =>
        r.tags?.includes('structuring') || r.name.toLowerCase().includes('structuring')
      );
      expect(structuringRules.length).toBeGreaterThan(0);
    });

    it('should have PEP rules', () => {
      const rules = plugin.getDefaultRules();
      const pepRules = rules.filter(r =>
        r.tags?.includes('pep') || r.name.toLowerCase().includes('pep')
      );
      expect(pepRules.length).toBeGreaterThan(0);
    });

    it('should have velocity rules', () => {
      const rules = plugin.getDefaultRules();
      const velocityRules = rules.filter(r =>
        r.tags?.includes('velocity') || r.name.toLowerCase().includes('velocity')
      );
      expect(velocityRules.length).toBeGreaterThan(0);
    });

    it('should have KYC rules', () => {
      const rules = plugin.getDefaultRules();
      const kycRules = rules.filter(r =>
        r.tags?.includes('kyc') || r.name.toLowerCase().includes('kyc')
      );
      expect(kycRules.length).toBeGreaterThan(0);
    });
  });

  describe('Rule Decisions', () => {
    it('should have DENY rules for hard blocks', () => {
      const rules = plugin.getDefaultRules();
      const denyRules = rules.filter(r => r.consequence.decision === 'DENY');

      // Should include sanctions, frozen account, no KYC
      expect(denyRules.length).toBeGreaterThan(3);

      const denyRuleNames = denyRules.map(r => r.name.toLowerCase());
      expect(denyRuleNames.some(name => name.includes('sanction'))).toBe(true);
      expect(denyRuleNames.some(name => name.includes('frozen'))).toBe(true);
    });

    it('should have FLAG rules for suspicious activity', () => {
      const rules = plugin.getDefaultRules();
      const flagRules = rules.filter(r => r.consequence.decision === 'FLAG');

      // Should have many flag rules for various patterns
      expect(flagRules.length).toBeGreaterThan(10);

      const flagRuleNames = flagRules.map(r => r.name.toLowerCase());
      expect(flagRuleNames.some(name => name.includes('pep'))).toBe(true);
      expect(flagRuleNames.some(name => name.includes('structuring'))).toBe(true);
      expect(flagRuleNames.some(name => name.includes('velocity'))).toBe(true);
    });
  });

  describe('Validation', () => {
    it('should validate transaction data', () => {
      const validTransaction: TransactionData = {
        transactionId: 'txn-001',
        amount: 5000,
        currency: 'USD',
        sourceAccountId: 'acct-001',
        sourceCountry: 'US',
        destCountry: 'US',
        channel: 'WIRE',
        type: 'TRANSFER',
        timestamp: new Date().toISOString(),
      };

      const validAccount: AccountData = {
        accountId: 'acct-001',
        ownerId: 'cust-001',
        accountType: 'CHECKING',
        country: 'US',
        currency: 'USD',
        kycLevel: 'STANDARD',
        riskTier: 'LOW',
        openedAt: '2020-01-01',
        status: 'ACTIVE',
      };

      const validCustomer: CustomerData = {
        customerId: 'cust-001',
        customerType: 'INDIVIDUAL',
        legalName: 'John Doe',
        country: 'US',
        industry: 'TECHNOLOGY',
        isPEP: false,
        sanctionsHits: 0,
        watchlistHits: 0,
        adverseMediaHits: 0,
        riskCategory: 'STANDARD',
        riskScore: 20,
        typicalMonthlyVolume: 10000,
        typicalMonthlyCount: 15,
        customerSince: '2020-01-01',
      };

      // Should validate successfully for valid data
      const result = plugin.validateDomainData('Transaction', {
        transaction: validTransaction,
        account: validAccount,
        customer: validCustomer,
      });
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    it('should validate and catch missing transaction data', () => {
      const result = plugin.validateDomainData('Transaction', {});
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.code === 'MISSING_TRANSACTION')).toBe(true);
    });

    it('should return error for unknown entity type', () => {
      const result = plugin.validateDomainData('UnknownType', {});
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.code === 'UNKNOWN_ENTITY_TYPE')).toBe(true);
    });
  });

  describe('Event Context', () => {
    it('should build evaluation context for transaction events', () => {
      const event = {
        id: 'evt-001',
        source: 'arka-aml',
        type: 'TRANSACTION_POSTED',
        entityType: 'Transaction',
        entityId: 'txn-001',
        payload: {
          transaction: {
            transactionId: 'txn-001',
            amount: 9500,
            currency: 'USD',
            sourceAccountId: 'acct-001',
            sourceCountry: 'US',
            destCountry: 'PK', // High-risk country for testing
            channel: 'CASH',
            type: 'DEPOSIT',
            timestamp: new Date().toISOString(),
          },
          account: {
            accountId: 'acct-001',
            ownerId: 'cust-001',
            accountType: 'CHECKING',
            country: 'US',
            currency: 'USD',
            kycLevel: 'STANDARD',
            riskTier: 'LOW',
            openedAt: '2020-01-01',
            status: 'ACTIVE',
          },
          customer: {
            customerId: 'cust-001',
            customerType: 'INDIVIDUAL',
            legalName: 'John Doe',
            country: 'US',
            industry: 'RETAIL',
            isPEP: false,
            sanctionsHits: 0,
            watchlistHits: 0,
            adverseMediaHits: 0,
            riskCategory: 'STANDARD',
            riskScore: 20,
            typicalMonthlyVolume: 5000,
            typicalMonthlyCount: 10,
            customerSince: '2020-01-01',
          },
        },
        createdAt: new Date().toISOString(),
      };

      const context = plugin.getEvaluationContext(event as any);

      // getEvaluationContext returns AML-specific context, not raw data
      expect(context.thresholds).toBeDefined();
      expect(context.highRiskCountries).toBeDefined();
      expect(context.highRiskIndustries).toBeDefined();
      expect(context.sourceCountryRisk).toBe('LOW');
      expect(context.destCountryRisk).toBe('HIGH');
      expect(context.evaluatedAt).toBeDefined();
    });
  });

  describe('getRulesByCategory', () => {
    it('should return rules organized by category', () => {
      const categories = plugin.getRulesByCategory();

      // Should have sanctions rules
      expect(categories['sanctions']).toBeDefined();
      expect(categories['sanctions'].length).toBeGreaterThan(0);

      // Should have PEP rules
      expect(categories['pep']).toBeDefined();
      expect(categories['pep'].length).toBeGreaterThan(0);

      // Should have structuring rules
      expect(categories['structuring']).toBeDefined();
      expect(categories['structuring'].length).toBeGreaterThan(0);
    });

    it('should categorize all defined categories', () => {
      const categories = plugin.getRulesByCategory();

      // Check that expected categories exist
      expect(Object.keys(categories)).toContain('sanctions');
      expect(Object.keys(categories)).toContain('pep');
      expect(Object.keys(categories)).toContain('structuring');
      expect(Object.keys(categories)).toContain('country-risk');
      expect(Object.keys(categories)).toContain('kyc-account');
    });
  });

  describe('Singleton Pattern', () => {
    it('should return same instance from getPactAMLPlugin', () => {
      const instance1 = getPactAMLPlugin();
      const instance2 = getPactAMLPlugin();
      expect(instance1).toBe(instance2);
    });
  });
});

describe('AML Compliance Scenarios', () => {
  let plugin: PactAMLPlugin;

  beforeEach(() => {
    plugin = getPactAMLPlugin();
  });

  describe('Sanctions Screening', () => {
    it('should have rule to block sanctioned customers', () => {
      const rules = plugin.getDefaultRules();
      const sanctionedCustomerRule = rules.find(r => r.name === 'Sanctioned Customer Block');

      expect(sanctionedCustomerRule).toBeDefined();
      expect(sanctionedCustomerRule?.consequence.decision).toBe('DENY');
    });

    it('should have rule to block sanctioned countries', () => {
      const rules = plugin.getDefaultRules();
      const sanctionedCountryRule = rules.find(r => r.name === 'Sanctioned Country Block');

      expect(sanctionedCountryRule).toBeDefined();
      expect(sanctionedCountryRule?.consequence.decision).toBe('DENY');
    });
  });

  describe('CTR and Structuring', () => {
    it('should have CTR threshold rule at $10,000', () => {
      const rules = plugin.getDefaultRules();
      const ctrRule = rules.find(r => r.name === 'CTR Cash Threshold');

      expect(ctrRule).toBeDefined();
      expect(ctrRule?.consequence.decision).toBe('FLAG');
    });

    it('should have structuring detection rule', () => {
      const rules = plugin.getDefaultRules();
      const structuringRule = rules.find(r => r.name === 'Structuring Amount Detection');

      expect(structuringRule).toBeDefined();
      expect(structuringRule?.consequence.decision).toBe('FLAG');
    });
  });

  describe('PEP Monitoring', () => {
    it('should have PEP enhanced threshold rule', () => {
      const rules = plugin.getDefaultRules();
      const pepEnhancedRule = rules.find(r => r.name === 'PEP Enhanced Threshold');

      expect(pepEnhancedRule).toBeDefined();
      expect(pepEnhancedRule?.consequence.decision).toBe('FLAG');
    });

    it('should have PEP any transaction rule', () => {
      const rules = plugin.getDefaultRules();
      const pepAnyRule = rules.find(r => r.name === 'PEP Transaction Flag');

      expect(pepAnyRule).toBeDefined();
      expect(pepAnyRule?.consequence.decision).toBe('FLAG');
    });
  });

  describe('High-Risk Industries', () => {
    it('should have MSB transaction rule', () => {
      const rules = plugin.getDefaultRules();
      const msbRule = rules.find(r => r.name === 'Money Service Business Customer');

      expect(msbRule).toBeDefined();
      expect(msbRule?.consequence.decision).toBe('FLAG');
    });

    it('should have crypto business rule', () => {
      const rules = plugin.getDefaultRules();
      const cryptoRule = rules.find(r => r.name === 'Cryptocurrency Business Customer');

      expect(cryptoRule).toBeDefined();
    });

    it('should have casino/gambling rule', () => {
      const rules = plugin.getDefaultRules();
      const casinoRule = rules.find(r => r.name === 'Casino/Gambling Customer');

      expect(casinoRule).toBeDefined();
    });
  });

  describe('Account Status Rules', () => {
    it('should have frozen account block rule', () => {
      const rules = plugin.getDefaultRules();
      const frozenRule = rules.find(r => r.name === 'Frozen Account Block');

      expect(frozenRule).toBeDefined();
      expect(frozenRule?.consequence.decision).toBe('DENY');
    });

    it('should have dormant account reactivation rule', () => {
      const rules = plugin.getDefaultRules();
      const dormantRule = rules.find(r => r.name === 'Dormant Account Activity');

      expect(dormantRule).toBeDefined();
      expect(dormantRule?.consequence.decision).toBe('FLAG');
    });
  });

  describe('KYC Rules', () => {
    it('should have no KYC block rule', () => {
      const rules = plugin.getDefaultRules();
      const noKycRule = rules.find(r => r.name === 'No KYC Block');

      expect(noKycRule).toBeDefined();
      expect(noKycRule?.consequence.decision).toBe('DENY');
    });

    it('should have basic KYC high amount rule', () => {
      const rules = plugin.getDefaultRules();
      const basicKycRule = rules.find(r => r.name === 'Basic KYC High Amount');

      expect(basicKycRule).toBeDefined();
      expect(basicKycRule?.consequence.decision).toBe('FLAG');
    });
  });

  describe('Velocity Rules', () => {
    it('should have high velocity 24H rule', () => {
      const rules = plugin.getDefaultRules();
      const velocityRule = rules.find(r => r.name === 'High Transaction Velocity (24h)');

      expect(velocityRule).toBeDefined();
      expect(velocityRule?.consequence.decision).toBe('FLAG');
    });

    it('should have unusual amount rule', () => {
      const rules = plugin.getDefaultRules();
      const unusualRule = rules.find(r => r.name === 'Unusual Transaction Amount');

      expect(unusualRule).toBeDefined();
    });
  });
});
