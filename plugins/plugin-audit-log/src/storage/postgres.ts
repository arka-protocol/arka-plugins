/**
 * PostgreSQL Storage Backend
 *
 * Production-ready PostgreSQL storage for audit records.
 */

import { createLogger, type Logger } from '@arka/utils';
import type { AuditRecord, AuditQuery, AuditEventType, AuditCategory, AuditSeverity, EvidenceAttachment } from '@arka/types';
import type { AuditStorageBackend } from '../types.js';

/**
 * PostgreSQL audit storage backend
 */
export class PostgresAuditStorage implements AuditStorageBackend {
  private readonly logger: Logger;
  private client: PostgresClient | null = null;
  private connectionString: string;

  constructor(connectionString: string) {
    this.connectionString = connectionString;
    this.logger = createLogger({ service: 'postgres-audit-storage' });
  }

  async init(): Promise<void> {
    this.logger.info('Initializing PostgreSQL audit storage');

    try {
      // Dynamic import of pg to make it optional
      const { Pool } = await import('pg');
      this.client = new Pool({
        connectionString: this.connectionString,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      }) as unknown as PostgresClient;

      // Create tables if they don't exist
      await this.createTables();

      this.logger.info('PostgreSQL audit storage initialized');
    } catch (error) {
      this.logger.error('Failed to initialize PostgreSQL', error as Error);
      throw error;
    }
  }

  private async createTables(): Promise<void> {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS pact_audit_records (
        id VARCHAR(64) PRIMARY KEY,
        event_type VARCHAR(64) NOT NULL,
        timestamp TIMESTAMPTZ NOT NULL,
        actor_type VARCHAR(32),
        actor_id VARCHAR(128),
        actor_name VARCHAR(256),
        actor_ip VARCHAR(45),
        correlation_transaction_id VARCHAR(64),
        correlation_entity_id VARCHAR(64),
        correlation_rule_id VARCHAR(64),
        correlation_alert_id VARCHAR(64),
        correlation_request_id VARCHAR(64),
        correlation_session_id VARCHAR(64),
        correlation_external_id VARCHAR(256),
        category VARCHAR(32) NOT NULL,
        severity VARCHAR(16) NOT NULL,
        description TEXT NOT NULL,
        data JSONB NOT NULL DEFAULT '{}',
        evidence JSONB,
        previous_hash VARCHAR(128),
        record_hash VARCHAR(128) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON pact_audit_records(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_event_type ON pact_audit_records(event_type);
      CREATE INDEX IF NOT EXISTS idx_audit_category ON pact_audit_records(category);
      CREATE INDEX IF NOT EXISTS idx_audit_severity ON pact_audit_records(severity);
      CREATE INDEX IF NOT EXISTS idx_audit_transaction_id ON pact_audit_records(correlation_transaction_id);
      CREATE INDEX IF NOT EXISTS idx_audit_entity_id ON pact_audit_records(correlation_entity_id);
      CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON pact_audit_records(actor_id);
    `;

    await this.client!.query(createTableSQL);
  }

  async insert(record: AuditRecord): Promise<void> {
    const sql = `
      INSERT INTO pact_audit_records (
        id, event_type, timestamp, actor_type, actor_id, actor_name, actor_ip,
        correlation_transaction_id, correlation_entity_id, correlation_rule_id,
        correlation_alert_id, correlation_request_id, correlation_session_id,
        correlation_external_id, category, severity, description, data,
        evidence, previous_hash, record_hash
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
    `;

    const values = [
      record.id,
      record.eventType,
      record.timestamp,
      record.actor?.type || null,
      record.actor?.id || null,
      record.actor?.name || null,
      record.actor?.ipAddress || null,
      record.correlationIds.transactionId || null,
      record.correlationIds.entityId || null,
      record.correlationIds.ruleId || null,
      record.correlationIds.alertId || null,
      record.correlationIds.requestId || null,
      record.correlationIds.sessionId || null,
      record.correlationIds.externalId || null,
      record.category,
      record.severity,
      record.description,
      JSON.stringify(record.data),
      record.evidence ? JSON.stringify(record.evidence) : null,
      record.previousHash || null,
      record.recordHash,
    ];

    await this.client!.query(sql, values);
  }

  async insertBatch(records: AuditRecord[]): Promise<void> {
    // Use transaction for batch insert
    const client = await this.client!.connect();
    try {
      await client.query('BEGIN');
      for (const record of records) {
        await this.insert(record);
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async query(query: AuditQuery): Promise<AuditRecord[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (query.eventTypes?.length) {
      conditions.push(`event_type = ANY($${paramIndex})`);
      values.push(query.eventTypes);
      paramIndex++;
    }

    if (query.categories?.length) {
      conditions.push(`category = ANY($${paramIndex})`);
      values.push(query.categories);
      paramIndex++;
    }

    if (query.severities?.length) {
      conditions.push(`severity = ANY($${paramIndex})`);
      values.push(query.severities);
      paramIndex++;
    }

    if (query.actorId) {
      conditions.push(`actor_id = $${paramIndex}`);
      values.push(query.actorId);
      paramIndex++;
    }

    if (query.correlationIds?.transactionId) {
      conditions.push(`correlation_transaction_id = $${paramIndex}`);
      values.push(query.correlationIds.transactionId);
      paramIndex++;
    }

    if (query.correlationIds?.entityId) {
      conditions.push(`correlation_entity_id = $${paramIndex}`);
      values.push(query.correlationIds.entityId);
      paramIndex++;
    }

    if (query.correlationIds?.ruleId) {
      conditions.push(`correlation_rule_id = $${paramIndex}`);
      values.push(query.correlationIds.ruleId);
      paramIndex++;
    }

    if (query.fromTimestamp) {
      conditions.push(`timestamp >= $${paramIndex}`);
      values.push(query.fromTimestamp);
      paramIndex++;
    }

    if (query.toTimestamp) {
      conditions.push(`timestamp < $${paramIndex}`);
      values.push(query.toTimestamp);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderBy = query.orderBy === 'timestamp_asc' ? 'timestamp ASC' : 'timestamp DESC';
    const limit = query.limit || 100;
    const offset = query.offset || 0;

    const sql = `
      SELECT * FROM pact_audit_records
      ${whereClause}
      ORDER BY ${orderBy}
      LIMIT ${limit} OFFSET ${offset}
    `;

    const result = await this.client!.query(sql, values);
    return result.rows.map(this.rowToRecord);
  }

  async get(id: string): Promise<AuditRecord | null> {
    const sql = 'SELECT * FROM pact_audit_records WHERE id = $1';
    const result = await this.client!.query(sql, [id]);
    const row = result.rows[0];
    return row ? this.rowToRecord(row) : null;
  }

  async getLastRecord(): Promise<AuditRecord | null> {
    const sql = 'SELECT * FROM pact_audit_records ORDER BY created_at DESC LIMIT 1';
    const result = await this.client!.query(sql, []);
    const row = result.rows[0];
    return row ? this.rowToRecord(row) : null;
  }

  async getRange(fromId: string, toId: string): Promise<AuditRecord[]> {
    const sql = `
      SELECT * FROM pact_audit_records
      WHERE created_at >= (SELECT created_at FROM pact_audit_records WHERE id = $1)
        AND created_at <= (SELECT created_at FROM pact_audit_records WHERE id = $2)
      ORDER BY created_at ASC
    `;
    const result = await this.client!.query(sql, [fromId, toId]);
    return result.rows.map(this.rowToRecord);
  }

  async count(query?: Partial<AuditQuery>): Promise<number> {
    if (!query) {
      const sql = 'SELECT COUNT(*) as count FROM pact_audit_records';
      const result = await this.client!.query(sql, []);
      const row = result.rows[0] as { count: string } | undefined;
      return row ? parseInt(row.count, 10) : 0;
    }

    // Build conditions for count
    const conditions: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (query.eventTypes?.length) {
      conditions.push(`event_type = ANY($${paramIndex})`);
      values.push(query.eventTypes);
      paramIndex++;
    }

    if (query.categories?.length) {
      conditions.push(`category = ANY($${paramIndex})`);
      values.push(query.categories);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `SELECT COUNT(*) as count FROM pact_audit_records ${whereClause}`;
    const result = await this.client!.query(sql, values);
    const row = result.rows[0] as { count: string } | undefined;
    return row ? parseInt(row.count, 10) : 0;
  }

  async deleteOlderThan(timestamp: string): Promise<number> {
    const sql = 'DELETE FROM pact_audit_records WHERE timestamp < $1';
    const result = await this.client!.query(sql, [timestamp]);
    return result.rowCount || 0;
  }

  async close(): Promise<void> {
    if (this.client) {
      await this.client.end();
      this.client = null;
    }
  }

  private rowToRecord(row: PostgresRow): AuditRecord {
    return {
      id: row.id,
      eventType: row.event_type as AuditEventType,
      timestamp: row.timestamp.toISOString(),
      actor: row.actor_id
        ? {
            type: row.actor_type as 'user' | 'system' | 'api' | 'plugin',
            id: row.actor_id,
            name: row.actor_name,
            ipAddress: row.actor_ip,
          }
        : null,
      correlationIds: {
        transactionId: row.correlation_transaction_id,
        entityId: row.correlation_entity_id,
        ruleId: row.correlation_rule_id,
        alertId: row.correlation_alert_id,
        requestId: row.correlation_request_id,
        sessionId: row.correlation_session_id,
        externalId: row.correlation_external_id,
      },
      category: row.category as AuditCategory,
      severity: row.severity as AuditSeverity,
      description: row.description,
      data: row.data,
      evidence: row.evidence as EvidenceAttachment[] | undefined,
      previousHash: row.previous_hash,
      recordHash: row.record_hash,
    };
  }
}

// Type definitions for pg module
interface PostgresClient {
  query(sql: string, values?: unknown[]): Promise<{ rows: PostgresRow[]; rowCount: number | null }>;
  connect(): Promise<{
    query(sql: string, values?: unknown[]): Promise<{ rows: PostgresRow[] }>;
    release(): void;
  }>;
  end(): Promise<void>;
}

interface PostgresRow {
  id: string;
  event_type: string;
  timestamp: Date;
  actor_type: string | null;
  actor_id: string | null;
  actor_name: string | null;
  actor_ip: string | null;
  correlation_transaction_id: string | null;
  correlation_entity_id: string | null;
  correlation_rule_id: string | null;
  correlation_alert_id: string | null;
  correlation_request_id: string | null;
  correlation_session_id: string | null;
  correlation_external_id: string | null;
  category: string;
  severity: string;
  description: string;
  data: Record<string, unknown>;
  evidence: unknown[] | null;
  previous_hash: string | null;
  record_hash: string;
}
