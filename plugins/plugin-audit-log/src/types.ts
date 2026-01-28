/**
 * Audit Log Plugin Types
 *
 * Types specific to the audit trail and evidence logging plugin.
 */

import type {
  AuditRecord,
  AuditQuery,
  EvidenceAttachment,
  AuditEventType,
  AuditCategory,
  AuditSeverity,
  AuditActor,
  AuditCorrelationIds,
} from '@arka/types';

// Re-export types used by storage backends
export type {
  AuditRecord,
  AuditQuery,
  EvidenceAttachment,
  AuditEventType,
  AuditCategory,
  AuditSeverity,
  AuditActor,
  AuditCorrelationIds,
} from '@arka/types';

/**
 * Audit log plugin configuration
 */
export interface AuditLogConfig {
  /** Storage backend type */
  storageType: 'memory' | 'postgres' | 'custom';
  /** PostgreSQL connection string */
  postgresConnectionString?: string;
  /** Enable hash chaining for tamper detection */
  enableHashChaining?: boolean;
  /** Hash algorithm */
  hashAlgorithm?: 'sha256' | 'sha384' | 'sha512';
  /** Enable evidence storage */
  enableEvidenceStorage?: boolean;
  /** Evidence storage path */
  evidenceStoragePath?: string;
  /** Maximum evidence size in bytes */
  maxEvidenceSize?: number;
  /** Retention period in days (0 = forever) */
  retentionDays?: number;
  /** Enable compression for evidence */
  compressEvidence?: boolean;
  /** Batch insert size */
  batchInsertSize?: number;
  /** Flush interval in ms */
  flushIntervalMs?: number;
}

/**
 * Audit log service interface
 */
export interface AuditLogService {
  /** Record a new audit event */
  recordEvent(
    record: Omit<AuditRecord, 'id' | 'timestamp' | 'recordHash' | 'previousHash'>
  ): Promise<AuditRecord>;

  /** Query audit records */
  queryEvents(query: AuditQuery): Promise<AuditRecord[]>;

  /** Export events as async iterable */
  exportEvents(query: AuditQuery): AsyncIterable<AuditRecord>;

  /** Get a single record by ID */
  getRecord(id: string): Promise<AuditRecord | null>;

  /** Get records by transaction ID */
  getByTransactionId(transactionId: string): Promise<AuditRecord[]>;

  /** Get records by entity ID */
  getByEntityId(entityId: string): Promise<AuditRecord[]>;

  /** Verify hash chain integrity */
  verifyIntegrity(fromId?: string, toId?: string): Promise<IntegrityCheckResult>;

  /** Store evidence attachment */
  storeEvidence(evidence: EvidenceInput): Promise<EvidenceAttachment>;

  /** Retrieve evidence */
  getEvidence(id: string): Promise<EvidenceData | null>;

  /** Get statistics */
  getStats(): Promise<AuditStats>;
}

/**
 * Input for storing evidence
 */
export interface EvidenceInput {
  /** Type of evidence */
  type: EvidenceAttachment['type'];
  /** MIME type */
  mimeType: string;
  /** Optional filename */
  filename?: string;
  /** Evidence content */
  content: Buffer;
  /** Description */
  description?: string;
}

/**
 * Evidence data with content
 */
export interface EvidenceData extends EvidenceAttachment {
  content: Buffer;
}

/**
 * Result of integrity check
 */
export interface IntegrityCheckResult {
  /** Whether the chain is valid */
  valid: boolean;
  /** Number of records checked */
  recordsChecked: number;
  /** First invalid record ID (if any) */
  firstInvalidId?: string;
  /** Error message (if any) */
  error?: string;
  /** Checked from */
  fromId?: string;
  /** Checked to */
  toId?: string;
  /** Check timestamp */
  checkedAt: string;
}

/**
 * Audit statistics
 */
export interface AuditStats {
  /** Total record count */
  totalRecords: number;
  /** Records by type */
  byEventType: Record<string, number>;
  /** Records by category */
  byCategory: Record<string, number>;
  /** Records by severity */
  bySeverity: Record<string, number>;
  /** Evidence count */
  evidenceCount: number;
  /** Total evidence size in bytes */
  totalEvidenceSize: number;
  /** Oldest record timestamp */
  oldestRecord?: string;
  /** Newest record timestamp */
  newestRecord?: string;
}

/**
 * Audit record input for creation
 */
export interface AuditRecordInput {
  eventType: AuditEventType;
  actor?: AuditActor | null;
  correlationIds: AuditCorrelationIds;
  category: AuditCategory;
  severity: AuditSeverity;
  description: string;
  data: Record<string, unknown>;
  evidence?: EvidenceInput[];
}

/**
 * Export format
 */
export type ExportFormat = 'json' | 'csv' | 'jsonl';

/**
 * Export options
 */
export interface ExportOptions {
  format: ExportFormat;
  includeEvidence?: boolean;
  compress?: boolean;
}

/**
 * Storage backend interface
 */
export interface AuditStorageBackend {
  /** Initialize storage */
  init(): Promise<void>;

  /** Insert a record */
  insert(record: AuditRecord): Promise<void>;

  /** Insert batch of records */
  insertBatch(records: AuditRecord[]): Promise<void>;

  /** Query records */
  query(query: AuditQuery): Promise<AuditRecord[]>;

  /** Get single record */
  get(id: string): Promise<AuditRecord | null>;

  /** Get last record (for hash chaining) */
  getLastRecord(): Promise<AuditRecord | null>;

  /** Get records in range for integrity check */
  getRange(fromId: string, toId: string): Promise<AuditRecord[]>;

  /** Count records */
  count(query?: Partial<AuditQuery>): Promise<number>;

  /** Delete old records */
  deleteOlderThan(timestamp: string): Promise<number>;

  /** Close connection */
  close(): Promise<void>;
}

/**
 * Evidence storage backend interface
 */
export interface EvidenceStorageBackend {
  /** Store evidence */
  store(id: string, content: Buffer, metadata: Omit<EvidenceAttachment, 'storageRef'>): Promise<string>;

  /** Retrieve evidence */
  retrieve(storageRef: string): Promise<Buffer | null>;

  /** Delete evidence */
  delete(storageRef: string): Promise<boolean>;

  /** Get total size */
  getTotalSize(): Promise<number>;

  /** Count items */
  count(): Promise<number>;
}
