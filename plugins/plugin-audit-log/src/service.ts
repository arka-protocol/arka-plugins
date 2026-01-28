/**
 * Audit Log Service
 *
 * Core service implementation for audit logging.
 */

import { createLogger, type Logger, generateId } from '@arka/utils';
import { createHash } from 'crypto';
import type { AuditRecord, AuditQuery, EvidenceAttachment } from '@arka/types';
import type {
  AuditLogService,
  AuditLogConfig,
  AuditRecordInput,
  EvidenceInput,
  EvidenceData,
  IntegrityCheckResult,
  AuditStats,
  AuditStorageBackend,
  EvidenceStorageBackend,
} from './types.js';
import { InMemoryAuditStorage, InMemoryEvidenceStorage } from './storage/memory.js';
import { PostgresAuditStorage } from './storage/postgres.js';

/**
 * Default audit log configuration
 */
const DEFAULT_CONFIG: AuditLogConfig = {
  storageType: 'memory',
  enableHashChaining: true,
  hashAlgorithm: 'sha256',
  enableEvidenceStorage: true,
  maxEvidenceSize: 10 * 1024 * 1024, // 10MB
  retentionDays: 0,
  batchInsertSize: 100,
  flushIntervalMs: 5000,
};

/**
 * Audit Log Service implementation
 */
export class AuditLogServiceImpl implements AuditLogService {
  private readonly logger: Logger;
  private readonly config: AuditLogConfig;
  private storage: AuditStorageBackend;
  private evidenceStorage: EvidenceStorageBackend;
  private lastHash: string | null = null;
  private batchQueue: AuditRecord[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private initialized = false;

  constructor(config: Partial<AuditLogConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = createLogger({ service: 'audit-log-service' });

    // Initialize storage backends
    this.storage = this.createStorageBackend();
    this.evidenceStorage = new InMemoryEvidenceStorage();
  }

  private createStorageBackend(): AuditStorageBackend {
    switch (this.config.storageType) {
      case 'postgres':
        if (!this.config.postgresConnectionString) {
          throw new Error('PostgreSQL connection string required');
        }
        return new PostgresAuditStorage(this.config.postgresConnectionString);
      case 'memory':
      default:
        return new InMemoryAuditStorage();
    }
  }

  /**
   * Initialize the service
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    this.logger.info('Initializing audit log service', {
      storageType: this.config.storageType,
      hashChaining: this.config.enableHashChaining,
    });

    await this.storage.init();

    // Get last record hash for chaining
    if (this.config.enableHashChaining) {
      const lastRecord = await this.storage.getLastRecord();
      if (lastRecord) {
        this.lastHash = lastRecord.recordHash;
      }
    }

    // Start batch flush timer
    if (this.config.flushIntervalMs && this.config.flushIntervalMs > 0) {
      this.flushTimer = setInterval(() => {
        this.flushBatch();
      }, this.config.flushIntervalMs);
    }

    this.initialized = true;
    this.logger.info('Audit log service initialized');
  }

  /**
   * Shutdown the service
   */
  async shutdown(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    // Flush remaining batch
    await this.flushBatch();

    await this.storage.close();
    this.initialized = false;
  }

  async recordEvent(
    input: Omit<AuditRecord, 'id' | 'timestamp' | 'recordHash' | 'previousHash'>
  ): Promise<AuditRecord> {
    const now = new Date().toISOString();
    const id = generateId();

    // Compute record hash
    const hashContent = JSON.stringify({
      id,
      timestamp: now,
      eventType: input.eventType,
      actor: input.actor,
      correlationIds: input.correlationIds,
      category: input.category,
      severity: input.severity,
      description: input.description,
      data: input.data,
      previousHash: this.lastHash,
    });

    const recordHash = this.computeHash(hashContent);

    const record: AuditRecord = {
      id,
      timestamp: now,
      eventType: input.eventType,
      actor: input.actor,
      correlationIds: input.correlationIds,
      category: input.category,
      severity: input.severity,
      description: input.description,
      data: input.data,
      evidence: input.evidence,
      previousHash: this.config.enableHashChaining ? this.lastHash : null,
      recordHash,
    };

    // Update last hash
    if (this.config.enableHashChaining) {
      this.lastHash = recordHash;
    }

    // Add to batch queue
    this.batchQueue.push(record);

    // Flush if batch is full
    if (this.batchQueue.length >= (this.config.batchInsertSize || 100)) {
      await this.flushBatch();
    }

    this.logger.debug('Audit event recorded', {
      id,
      eventType: input.eventType,
      category: input.category,
    });

    return record;
  }

  async queryEvents(query: AuditQuery): Promise<AuditRecord[]> {
    // Flush batch before querying
    await this.flushBatch();
    return this.storage.query(query);
  }

  async *exportEvents(query: AuditQuery): AsyncIterable<AuditRecord> {
    await this.flushBatch();

    const pageSize = 100;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const records = await this.storage.query({
        ...query,
        limit: pageSize,
        offset,
      });

      for (const record of records) {
        yield record;
      }

      hasMore = records.length === pageSize;
      offset += pageSize;
    }
  }

  async getRecord(id: string): Promise<AuditRecord | null> {
    // Check batch queue first
    const queued = this.batchQueue.find(r => r.id === id);
    if (queued) return queued;

    return this.storage.get(id);
  }

  async getByTransactionId(transactionId: string): Promise<AuditRecord[]> {
    await this.flushBatch();
    return this.storage.query({
      correlationIds: { transactionId },
      orderBy: 'timestamp_asc',
    });
  }

  async getByEntityId(entityId: string): Promise<AuditRecord[]> {
    await this.flushBatch();
    return this.storage.query({
      correlationIds: { entityId },
      orderBy: 'timestamp_asc',
    });
  }

  async verifyIntegrity(fromId?: string, toId?: string): Promise<IntegrityCheckResult> {
    if (!this.config.enableHashChaining) {
      return {
        valid: true,
        recordsChecked: 0,
        error: 'Hash chaining is disabled',
        checkedAt: new Date().toISOString(),
      };
    }

    await this.flushBatch();

    let records: AuditRecord[];
    if (fromId && toId) {
      records = await this.storage.getRange(fromId, toId);
    } else {
      records = await this.storage.query({
        orderBy: 'timestamp_asc',
        limit: 10000,
      });
    }

    let previousHash: string | null = null;
    let firstInvalidId: string | undefined;

    for (const record of records) {
      // Verify previous hash matches
      if (previousHash !== null && record.previousHash !== previousHash) {
        firstInvalidId = record.id;
        break;
      }

      // Verify record hash
      const hashContent = JSON.stringify({
        id: record.id,
        timestamp: record.timestamp,
        eventType: record.eventType,
        actor: record.actor,
        correlationIds: record.correlationIds,
        category: record.category,
        severity: record.severity,
        description: record.description,
        data: record.data,
        previousHash: record.previousHash,
      });

      const expectedHash = this.computeHash(hashContent);
      if (expectedHash !== record.recordHash) {
        firstInvalidId = record.id;
        break;
      }

      previousHash = record.recordHash;
    }

    return {
      valid: !firstInvalidId,
      recordsChecked: records.length,
      firstInvalidId,
      fromId,
      toId,
      checkedAt: new Date().toISOString(),
    };
  }

  async storeEvidence(input: EvidenceInput): Promise<EvidenceAttachment> {
    if (!this.config.enableEvidenceStorage) {
      throw new Error('Evidence storage is disabled');
    }

    if (input.content.length > (this.config.maxEvidenceSize || 10 * 1024 * 1024)) {
      throw new Error(`Evidence size exceeds maximum of ${this.config.maxEvidenceSize} bytes`);
    }

    const id = generateId();
    const contentHash = this.computeHash(input.content.toString('base64'));
    const now = new Date().toISOString();

    const metadata: Omit<EvidenceAttachment, 'storageRef'> = {
      id,
      type: input.type,
      mimeType: input.mimeType,
      filename: input.filename,
      size: input.content.length,
      contentHash,
      capturedAt: now,
      description: input.description,
    };

    const storageRef = await this.evidenceStorage.store(id, input.content, metadata);

    this.logger.debug('Evidence stored', { id, type: input.type, size: input.content.length });

    return { ...metadata, storageRef };
  }

  async getEvidence(id: string): Promise<EvidenceData | null> {
    // This would need the full attachment metadata stored somewhere
    const content = await this.evidenceStorage.retrieve(`memory://${id}`);
    if (!content) return null;

    // In a real implementation, we'd store and retrieve the full metadata
    return {
      id,
      type: 'other',
      mimeType: 'application/octet-stream',
      size: content.length,
      contentHash: this.computeHash(content.toString('base64')),
      storageRef: `memory://${id}`,
      capturedAt: new Date().toISOString(),
      content,
    };
  }

  async getStats(): Promise<AuditStats> {
    await this.flushBatch();

    const totalRecords = await this.storage.count();
    const evidenceCount = await this.evidenceStorage.count();
    const totalEvidenceSize = await this.evidenceStorage.getTotalSize();

    // Get breakdown by type
    const allRecords = await this.storage.query({ limit: 10000 });

    const byEventType: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    let oldestRecord: string | undefined;
    let newestRecord: string | undefined;

    for (const record of allRecords) {
      byEventType[record.eventType] = (byEventType[record.eventType] || 0) + 1;
      byCategory[record.category] = (byCategory[record.category] || 0) + 1;
      bySeverity[record.severity] = (bySeverity[record.severity] || 0) + 1;

      if (!oldestRecord || record.timestamp < oldestRecord) {
        oldestRecord = record.timestamp;
      }
      if (!newestRecord || record.timestamp > newestRecord) {
        newestRecord = record.timestamp;
      }
    }

    return {
      totalRecords,
      byEventType,
      byCategory,
      bySeverity,
      evidenceCount,
      totalEvidenceSize,
      oldestRecord,
      newestRecord,
    };
  }

  private async flushBatch(): Promise<void> {
    if (this.batchQueue.length === 0) return;

    const batch = this.batchQueue.splice(0);
    try {
      await this.storage.insertBatch(batch);
      this.logger.debug('Flushed audit batch', { count: batch.length });
    } catch (error) {
      // Put records back in queue on failure
      this.batchQueue.unshift(...batch);
      this.logger.error('Failed to flush audit batch', error as Error);
      throw error;
    }
  }

  private computeHash(content: string): string {
    const algorithm = this.config.hashAlgorithm || 'sha256';
    return createHash(algorithm).update(content).digest('hex');
  }
}

/**
 * Factory function to create the audit log service
 */
export function createAuditLogService(
  config?: Partial<AuditLogConfig>
): AuditLogServiceImpl {
  return new AuditLogServiceImpl(config);
}
