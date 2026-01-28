# @arka/plugin-audit-log

Audit trail and evidence logging plugin for the ARKA Protocol. Provides immutable, tamper-evident audit logging for compliance and regulatory requirements.

## Features

- **Immutable Audit Records**: Append-only audit log with hash chaining
- **Hash Chain Integrity**: SHA-256/384/512 hash chaining for tamper detection
- **Evidence Storage**: Capture and store supporting evidence
- **Multiple Backends**: In-memory (dev) and PostgreSQL (production)
- **Query & Export**: Flexible querying and export in JSON/CSV formats
- **Retention Management**: Configurable retention periods
- **Automatic Hooks**: Captures transactions, rule evaluations, alerts, and risk scores

## Installation

```bash
pnpm add @arka/plugin-audit-log
```

For PostgreSQL support:
```bash
pnpm add pg
```

## Usage

### Basic Setup

```typescript
import { createAuditLogPlugin } from '@arka/plugin-audit-log';

const plugin = createAuditLogPlugin({
  storageType: 'memory', // or 'postgres'
  enableHashChaining: true,
  hashAlgorithm: 'sha256',
  enableEvidenceStorage: true,
  retentionDays: 365,
});

// Initialize with ARKA core
await plugin.init(arkaCore);
```

### PostgreSQL Configuration

```typescript
const plugin = createAuditLogPlugin({
  storageType: 'postgres',
  postgresConnectionString: 'postgresql://user:pass@localhost:5432/pact_audit',
  enableHashChaining: true,
  batchInsertSize: 100,
  flushIntervalMs: 5000,
});
```

### Recording Custom Events

```typescript
const record = await plugin.recordEvent({
  eventType: 'manual_override',
  actor: {
    type: 'user',
    id: 'user-123',
    name: 'John Doe',
    ipAddress: '192.168.1.1',
  },
  correlationIds: {
    transactionId: 'tx-456',
    alertId: 'alert-789',
  },
  category: 'compliance',
  severity: 'warn',
  description: 'Manual override of alert disposition',
  data: {
    previousStatus: 'open',
    newStatus: 'false_positive',
    reason: 'Verified with customer',
  },
});
```

### Querying Audit Records

```typescript
const service = plugin.getService();

// Query by time range
const records = await service.queryEvents({
  fromTimestamp: '2024-01-01T00:00:00Z',
  toTimestamp: '2024-01-31T23:59:59Z',
  categories: ['compliance', 'risk'],
  orderBy: 'timestamp_desc',
  limit: 100,
});

// Get transaction audit trail
const txTrail = await plugin.getTransactionAuditTrail('tx-123');

// Get entity audit trail
const entityTrail = await plugin.getEntityAuditTrail('entity-456');
```

### Storing Evidence

```typescript
const evidence = await plugin.storeEvidence({
  type: 'document',
  mimeType: 'application/pdf',
  filename: 'verification-document.pdf',
  content: Buffer.from(pdfContent),
  description: 'Customer identity verification document',
});

// Retrieve evidence
const retrieved = await plugin.getEvidence(evidence.id);
```

### Verifying Integrity

```typescript
const result = await plugin.verifyIntegrity();

if (!result.valid) {
  console.error(`Integrity violation at record: ${result.firstInvalidId}`);
}
```

### Exporting Audit Data

```typescript
// Export as JSON Lines
for await (const line of plugin.exportAsJsonLines({
  fromTimestamp: '2024-01-01T00:00:00Z'
})) {
  await fs.appendFile('audit-export.jsonl', line);
}

// Export as CSV
for await (const line of plugin.exportAsCsv({
  categories: ['compliance']
})) {
  await fs.appendFile('audit-export.csv', line);
}
```

## Audit Event Types

| Type | Description |
|------|-------------|
| `transaction_received` | New transaction processed |
| `transaction_processed` | Transaction monitoring complete |
| `rule_evaluated` | Rule evaluated (passed) |
| `rule_fired` | Rule triggered (violation) |
| `alert_generated` | Alert created |
| `risk_score_computed` | Risk score calculated |
| `decision_made` | Decision rendered |
| `manual_override` | Manual action taken |
| `entity_created` | Entity created |
| `entity_updated` | Entity modified |
| `config_changed` | Configuration changed |
| `plugin_loaded` | Plugin initialized |
| `plugin_unloaded` | Plugin shutdown |
| `report_generated` | Report created |
| `external_query` | External system query |
| `custom` | Custom event type |

## Audit Categories

- `transaction` - Transaction events
- `compliance` - Compliance and rule events
- `risk` - Risk assessment events
- `security` - Security events
- `configuration` - Config changes
- `system` - System events
- `reporting` - Report events

## Severity Levels

- `debug` - Diagnostic information
- `info` - Normal operations
- `warn` - Warning conditions
- `error` - Error conditions
- `critical` - Critical issues

## Configuration

### Environment Variables

- `AUDIT_STORAGE_TYPE` - Storage backend (`memory` or `postgres`)
- `AUDIT_POSTGRES_URL` - PostgreSQL connection string
- `AUDIT_RETENTION_DAYS` - Record retention period
- `AUDIT_HASH_ALGORITHM` - Hash algorithm (`sha256`, `sha384`, `sha512`)

### Config File

Place configuration in `config/pact/plugins/audit-log.yaml`:

```yaml
storageType: postgres
postgresConnectionString: ${AUDIT_POSTGRES_URL}
enableHashChaining: true
hashAlgorithm: sha256
enableEvidenceStorage: true
evidenceStoragePath: /data/evidence
maxEvidenceSize: 10485760  # 10MB
retentionDays: 2555  # 7 years
compressEvidence: true
batchInsertSize: 100
flushIntervalMs: 5000
```

## API Reference

### AuditLogPlugin

Main plugin class.

#### Methods

- `init(core: ArkaCoreContext): Promise<void>` - Initialize
- `shutdown(): Promise<void>` - Shutdown
- `getService(): AuditLogService` - Get service instance
- `recordEvent(input): Promise<AuditRecord>` - Record event
- `queryEvents(query): Promise<AuditRecord[]>` - Query records
- `exportEvents(query): AsyncIterable<AuditRecord>` - Export iterator
- `getTransactionAuditTrail(id): Promise<AuditRecord[]>` - Get tx trail
- `getEntityAuditTrail(id): Promise<AuditRecord[]>` - Get entity trail
- `verifyIntegrity(from?, to?): Promise<IntegrityCheckResult>` - Verify chain
- `storeEvidence(input): Promise<EvidenceAttachment>` - Store evidence
- `getEvidence(id): Promise<EvidenceData | null>` - Retrieve evidence
- `getStats(): Promise<AuditStats>` - Get statistics

## Extension Points

1. **Custom Storage Backend**: Implement `AuditStorageBackend` interface
2. **Custom Evidence Storage**: Implement `EvidenceStorageBackend` interface
3. **Event Hooks**: Subscribe to audit events for custom processing

## License

MIT
