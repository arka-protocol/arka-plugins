# @arka/aml - Anti-Money Laundering Compliance Plugin

Enterprise-ready domain plugin for AML compliance monitoring. Provides comprehensive rules for transaction monitoring, sanctions screening, structuring detection, PEP handling, velocity analysis, and cross-entity risk correlation.

## Features

- **Sanctions Screening**: Real-time blocking of sanctioned customers and countries
- **Structuring Detection**: Identify transactions structured to avoid CTR thresholds ($10K)
- **PEP Monitoring**: Enhanced due diligence for Politically Exposed Persons
- **Velocity Analysis**: Detect unusual transaction patterns (count, amount, frequency)
- **High-Risk Country Rules**: FATF blacklist/greylist enforcement
- **High-Risk Industry Rules**: MSB, crypto, casino, and other elevated-risk sectors
- **KYC Compliance**: Block transactions for unverified accounts
- **Cross-Entity Correlation**: Link customer, account, and transaction data for pattern detection
- **Round Amount Detection**: Flag suspiciously round transaction amounts
- **Dormant Account Reactivation**: Alert on sudden activity in dormant accounts

## Installation

```bash
pnpm add @arka/aml
```

## Quick Start

```typescript
import { getPactAMLPlugin } from '@arka/aml';
import { ArkaEngine } from '@arka/core';

// Get plugin instance
const amlPlugin = getPactAMLPlugin();

// Register with engine
const engine = new ArkaEngine();
engine.registerPlugin(amlPlugin);

// Process a transaction
const decision = await engine.evaluateEvent({
  type: 'TRANSACTION_POSTED',
  entityId: 'txn-001',
  entityType: 'Transaction',
  jurisdiction: 'US',
  payload: {
    transaction: {
      transactionId: 'txn-001',
      amount: 9500,
      currency: 'USD',
      sourceAccountId: 'acct-001',
      sourceCountry: 'US',
      destCountry: 'US',
      channel: 'WIRE',
      type: 'TRANSFER',
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
      openedAt: '2020-01-15',
      status: 'ACTIVE',
    },
    customer: {
      customerId: 'cust-001',
      customerType: 'INDIVIDUAL',
      legalName: 'John Smith',
      country: 'US',
      industry: 'TECHNOLOGY',
      isPEP: false,
      sanctionsHits: 0,
      watchlistHits: 0,
      adverseMediaHits: 0,
      riskCategory: 'STANDARD',
      riskScore: 15,
      typicalMonthlyVolume: 50000,
      typicalMonthlyCount: 20,
      customerSince: '2019-06-01',
    },
    dailyStats: {
      totalAmount: 15000,
      transactionCount: 3,
      cashAmount: 0,
      cashCount: 0,
    },
  },
});

console.log(decision.status); // 'ALLOW' | 'DENY' | 'ALLOW_WITH_FLAGS'
```

## Entity Schema

### Transaction Entity

```typescript
interface TransactionData {
  transactionId: string;        // Unique transaction identifier
  amount: number;               // Transaction amount
  currency: string;             // Currency code (USD, EUR, etc.)
  sourceAccountId: string;      // Source account ID
  destAccountId?: string;       // Destination account ID (internal)
  externalDestination?: string; // External destination (outgoing)
  sourceCountry: string;        // Source country code
  destCountry: string;          // Destination country code
  channel: TransactionChannel;  // WIRE | ACH | CASH | CRYPTO | etc.
  type: TransactionType;        // DEPOSIT | WITHDRAWAL | TRANSFER | etc.
  timestamp: string;            // ISO timestamp
  reference?: string;           // Reference/memo
  originatorName?: string;      // Wire originator name
  beneficiaryName?: string;     // Wire beneficiary name
  isRoundAmount?: boolean;      // Is suspiciously round amount
  tags?: string[];              // Transaction tags
  relatedTransactions?: string[]; // Related transaction IDs
}
```

### Account Entity

```typescript
interface AccountData {
  accountId: string;            // Account unique identifier
  ownerId: string;              // Owner customer ID
  accountType: 'CHECKING' | 'SAVINGS' | 'INVESTMENT' | 'BUSINESS' | 'TRUST';
  country: string;              // Country of account
  currency: string;             // Currency
  kycLevel: KYCLevel;           // NONE | BASIC | STANDARD | ENHANCED | FULL
  riskTier: AccountRiskTier;    // LOW | MEDIUM | HIGH | CRITICAL | BLOCKED
  openedAt: string;             // Account opening date
  status: 'ACTIVE' | 'DORMANT' | 'FROZEN' | 'CLOSED';
  avgMonthlyBalance?: number;   // Average monthly balance
  expectedMonthlyActivity?: number; // Expected monthly activity
  authorizedSigners?: number;   // Number of authorized signers
  allowsInternational?: boolean; // Whether account allows international
}
```

### Customer Entity

```typescript
interface CustomerData {
  customerId: string;           // Customer unique identifier
  customerType: 'INDIVIDUAL' | 'BUSINESS' | 'TRUST' | 'NON_PROFIT';
  legalName: string;            // Full legal name
  country: string;              // Country of residence/registration
  nationality?: string;         // Nationality (individuals)
  industry: string;             // Industry/occupation
  isPEP: boolean;               // Is Politically Exposed Person
  pepType?: 'DIRECT' | 'RELATIVE' | 'CLOSE_ASSOCIATE';
  sanctionsHits: number;        // Sanctions list matches
  watchlistHits: number;        // Watchlist matches
  adverseMediaHits: number;     // Adverse media hits
  riskCategory: CustomerRiskCategory;
  riskScore: number;            // Overall risk score (0-100)
  typicalMonthlyVolume: number; // Typical transaction volume
  typicalMonthlyCount: number;  // Typical transaction count
  sourceOfWealth?: string;      // Source of wealth
  sourceOfFunds?: string;       // Source of funds
  customerSince: string;        // Customer since date
}
```

### Transaction Channels

| Channel | Description |
|---------|-------------|
| `WIRE` | Wire transfers |
| `ACH` | ACH/direct deposit |
| `CHECK` | Check deposits/payments |
| `CASH` | Cash transactions |
| `CARD` | Card payments |
| `CRYPTO` | Cryptocurrency |
| `INTERNAL` | Internal transfers |
| `MOBILE` | Mobile payments |
| `ATM` | ATM transactions |
| `POS` | Point of sale |

### Risk Categories

| Category | Description |
|----------|-------------|
| `STANDARD` | Normal risk customer |
| `HIGH_NET_WORTH` | High net worth individual |
| `PEP` | Politically Exposed Person |
| `PEP_RELATIVE` | Relative of PEP |
| `SANCTIONED` | On sanctions list |
| `WATCHLIST` | On watchlist |
| `ADVERSE_MEDIA` | Adverse media findings |

## Events

| Event Type | Description |
|------------|-------------|
| `TRANSACTION_POSTED` | Transaction completed |
| `TRANSACTION_REVERSED` | Transaction reversed |
| `ACCOUNT_OPENED` | New account opened |
| `ACCOUNT_CLOSED` | Account closed |
| `ACCOUNT_FROZEN` | Account frozen |
| `CUSTOMER_UPDATED` | Customer profile updated |
| `KYC_VERIFIED` | KYC verification completed |
| `KYC_EXPIRED` | KYC verification expired |
| `ALERT_CREATED` | AML alert created |
| `ALERT_ESCALATED` | Alert escalated |
| `ALERT_CLOSED` | Alert resolved |
| `SAR_FILED` | SAR filed |
| `SANCTIONS_HIT` | Sanctions match found |
| `WATCHLIST_HIT` | Watchlist match found |

## Rules

### Sanctions & Watchlist Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| Sanctioned Customer Block | sanctionsHits > 0 | DENY |
| Sanctioned Country Block | Dest = KP, IR, etc. | DENY |
| Watchlist Flag | watchlistHits > 0 | FLAG |

### CTR & Structuring Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| CTR Threshold | Cash ≥ $10,000 | FLAG (file CTR) |
| Structuring Amount | $8,000-$9,999 | FLAG |
| Structuring Pattern | 3+ transactions 8K-10K in 14 days | FLAG |

### PEP Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| PEP Enhanced Threshold | PEP + amount ≥ $5,000 | FLAG |
| PEP Any Transaction | PEP + any transaction | FLAG |

### Country Risk Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| FATF Grey List | Dest in grey list countries | FLAG |
| High-Risk Country Threshold | High-risk + amount ≥ $3,000 | FLAG |

### Velocity & Pattern Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| High Velocity 24H | > 10 transactions/day | FLAG |
| Unusual Amount | Amount > 5x typical | FLAG |
| Round Amount Pattern | Round amount ≥ $5,000 | FLAG |

### High-Risk Industry Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| MSB Transaction | Money Service Business | FLAG |
| Crypto Business | Cryptocurrency business | FLAG |
| Casino/Gambling | Gaming industry | FLAG |

### KYC & Account Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| No KYC Block | kycLevel = NONE + amount > $1,000 | DENY |
| Basic KYC High Amount | kycLevel = BASIC + amount > $10,000 | FLAG |
| Frozen Account Block | status = FROZEN | DENY |
| Dormant Account Activity | status = DORMANT | FLAG |

### Risk Correlation Rules

| Rule | Condition | Decision |
|------|-----------|----------|
| Critical Risk Customer | riskScore > 80 | FLAG |
| Adverse Media Alert | adverseMediaHits > 0 | FLAG |

## High-Risk Countries

### FATF Blacklist (Sanctioned)
- North Korea (KP)
- Iran (IR)

### FATF Greylist / Very High Risk
- Myanmar (MM)
- Syria (SY)
- Yemen (YE)

### High Risk
- Afghanistan (AF)
- Pakistan (PK)
- Nigeria (NG)
- Haiti (HT)
- Jamaica (JM)
- Philippines (PH)
- Zimbabwe (ZW)

### Medium Risk (Offshore Centers)
- Cayman Islands (KY)
- British Virgin Islands (VG)
- Panama (PA)
- Belize (BZ)

## Regulatory Thresholds

```typescript
const AML_THRESHOLDS = {
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
};
```

## API Examples

### Using arka-core-service REST API

```bash
# Process a transaction
curl -X POST http://localhost:3001/v1/events/process \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "source": "arka-aml",
      "type": "TRANSACTION_POSTED",
      "entityId": "txn-001",
      "entityType": "Transaction",
      "jurisdiction": "US",
      "payload": {
        "transaction": {
          "transactionId": "txn-001",
          "amount": 9500,
          "currency": "USD",
          "sourceAccountId": "acct-001",
          "sourceCountry": "US",
          "destCountry": "US",
          "channel": "CASH",
          "type": "DEPOSIT",
          "timestamp": "2024-01-15T10:30:00Z"
        },
        "account": {
          "accountId": "acct-001",
          "ownerId": "cust-001",
          "accountType": "CHECKING",
          "country": "US",
          "currency": "USD",
          "kycLevel": "STANDARD",
          "riskTier": "LOW",
          "openedAt": "2020-01-15",
          "status": "ACTIVE"
        },
        "customer": {
          "customerId": "cust-001",
          "customerType": "INDIVIDUAL",
          "legalName": "John Smith",
          "country": "US",
          "industry": "RETAIL",
          "isPEP": false,
          "sanctionsHits": 0,
          "watchlistHits": 0,
          "adverseMediaHits": 0,
          "riskCategory": "STANDARD",
          "riskScore": 20,
          "typicalMonthlyVolume": 5000,
          "typicalMonthlyCount": 10,
          "customerSince": "2019-01-01"
        }
      }
    }
  }'
```

### Using pactctl CLI

```bash
# List all AML rules
pactctl rule list --tags aml

# Verify a specific rule on blockchain
pactctl rule verify aml-ctr-threshold

# Run audit verification
pactctl audit verify audit-123 --proof
```

## Running Simulations

The plugin includes sample datasets and simulation scripts:

```bash
# Navigate to examples
cd examples/aml-domain

# Run simulation on all datasets
npx ts-node scripts/run-aml-simulations.ts

# Run on specific dataset
npx ts-node scripts/run-aml-simulations.ts --dataset structuring

# Generate verbose output
npx ts-node scripts/run-aml-simulations.ts --verbose

# Output to custom directory
npx ts-node scripts/run-aml-simulations.ts --output ./my-reports
```

### Sample Datasets

| Dataset | Description |
|---------|-------------|
| `transactions_clean.json` | 10 transactions that should pass compliance |
| `transactions_suspicious.json` | 10 transactions flagged for review |
| `transactions_blocked.json` | 10 transactions that should be blocked |
| `transactions_patterns.json` | 15 transactions with hidden patterns |

## Testing

```bash
# Run tests
cd plugi../arka-aml
pnpm test

# Run with coverage
pnpm test --coverage
```

## Configuration

```typescript
const plugin = getPactAMLPlugin();

// Plugin configuration options
{
  defaultJurisdiction: 'US',             // Default jurisdiction
  strictMode: false,                      // Enable strict validation
  enablePatternDetection: true,           // Enable pattern-based rules
  enableVelocityChecks: true,             // Enable velocity analysis
  enableCrossEntityCorrelation: true,     // Enable cross-entity rules
}
```

## Regulatory References

- **Bank Secrecy Act (BSA)**: $10,000 CTR threshold
- **FinCEN Guidance**: SAR filing requirements
- **OFAC Sanctions**: Sanctioned countries/entities
- **FATF Recommendations**: Risk-based approach to AML
- **USA PATRIOT Act**: Enhanced due diligence requirements
- **EU 6AMLD**: Sixth Anti-Money Laundering Directive
- **PEP Screening**: FATF PEP guidelines

## Cross-Entity Correlation

PACT's unique strength is correlating data across entities:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Customer   │────▶│   Account   │────▶│ Transaction │
│  Risk Data  │     │  KYC Level  │     │   Amount    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                    ┌──────▼──────┐
                    │  ARKA Rule  │
                    │  Evaluation │
                    └─────────────┘
```

Example cross-entity rule:
- Customer is PEP (Customer entity)
- Account has only BASIC KYC (Account entity)
- Transaction amount > $5,000 (Transaction entity)
- **Result**: FLAG for enhanced review

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for development guidelines.

## License

MIT License - see [LICENSE](../../LICENSE) for details.
