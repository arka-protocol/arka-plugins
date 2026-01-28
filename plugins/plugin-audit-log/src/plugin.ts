/**
 * Audit Log Plugin
 *
 * Main plugin implementation for audit trail and evidence logging.
 */

import { createLogger, type Logger } from '@arka/utils';
import type {
  ArkaPlugin,
  ArkaCoreContext,
  ArkaTransaction,
  ArkaEvent,
  ArkaRule,
  Alert,
  RiskScoreBundle,
  RiskInput,
  ArkaPluginHooks,
  ArkaDecision,
  AuditRecord,
  AuditQuery,
  EvidenceAttachment,
} from '@arka/types';
import type {
  AuditLogConfig,
  AuditLogService,
  EvidenceInput,
  EvidenceData,
  IntegrityCheckResult,
  AuditStats,
} from './types.js';
import { AuditLogServiceImpl, createAuditLogService } from './service.js';

/**
 * Audit Log Plugin
 *
 * Provides immutable audit logging for all ARKA operations.
 */
export class AuditLogPlugin implements ArkaPlugin {
  readonly id = 'audit-log';
  readonly version = '0.1.0';
  readonly name = 'Audit Trail & Evidence';
  readonly description = 'Immutable audit logging and evidence capture for compliance';

  private readonly logger: Logger;
  private core: ArkaCoreContext | null = null;
  private service: AuditLogServiceImpl;
  private config: AuditLogConfig;
  private initialized = false;
  private retentionTimer: NodeJS.Timeout | null = null;

  constructor(config: Partial<AuditLogConfig> = {}) {
    this.config = {
      storageType: 'memory',
      enableHashChaining: true,
      hashAlgorithm: 'sha256',
      enableEvidenceStorage: true,
      maxEvidenceSize: 10 * 1024 * 1024,
      retentionDays: 0,
      batchInsertSize: 100,
      flushIntervalMs: 5000,
      ...config,
    };
    this.logger = createLogger({ service: 'plugin-audit-log' });
    this.service = createAuditLogService(this.config);
  }

  async init(core: ArkaCoreContext): Promise<void> {
    if (this.initialized) {
      this.logger.warn('Plugin already initialized');
      return;
    }

    this.logger.info('Initializing Audit Log plugin');
    this.core = core;

    try {
      await this.service.init();

      // Record plugin initialization
      await this.service.recordEvent({
        eventType: 'plugin_loaded',
        actor: { type: 'system', id: this.id },
        correlationIds: {},
        category: 'system',
        severity: 'info',
        description: `Audit Log plugin v${this.version} initialized`,
        data: {
          config: {
            storageType: this.config.storageType,
            enableHashChaining: this.config.enableHashChaining,
            retentionDays: this.config.retentionDays,
          },
        },
      });

      // Start retention cleanup if configured
      if (this.config.retentionDays && this.config.retentionDays > 0) {
        this.startRetentionCleanup();
      }

      this.initialized = true;
      this.logger.info('Audit Log plugin initialized');
    } catch (error) {
      this.logger.error('Failed to initialize plugin', error as Error);
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    this.logger.info('Shutting down Audit Log plugin');

    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
      this.retentionTimer = null;
    }

    await this.service.recordEvent({
      eventType: 'plugin_unloaded',
      actor: { type: 'system', id: this.id },
      correlationIds: {},
      category: 'system',
      severity: 'info',
      description: `Audit Log plugin v${this.version} shutting down`,
      data: {},
    });

    await this.service.shutdown();

    this.initialized = false;
    this.core = null;
    this.logger.info('Audit Log plugin shut down');
  }

  /**
   * Get the audit log service for direct access
   */
  getService(): AuditLogService {
    return this.service;
  }

  /**
   * Record a custom audit event
   */
  async recordEvent(
    input: Omit<AuditRecord, 'id' | 'timestamp' | 'recordHash' | 'previousHash'>
  ): Promise<AuditRecord> {
    return this.service.recordEvent(input);
  }

  /**
   * Query audit records
   */
  async queryEvents(query: AuditQuery): Promise<AuditRecord[]> {
    return this.service.queryEvents(query);
  }

  /**
   * Export events as async iterable
   */
  exportEvents(query: AuditQuery): AsyncIterable<AuditRecord> {
    return this.service.exportEvents(query);
  }

  /**
   * Get audit records for a transaction
   */
  async getTransactionAuditTrail(transactionId: string): Promise<AuditRecord[]> {
    return this.service.getByTransactionId(transactionId);
  }

  /**
   * Get audit records for an entity
   */
  async getEntityAuditTrail(entityId: string): Promise<AuditRecord[]> {
    return this.service.getByEntityId(entityId);
  }

  /**
   * Verify audit log integrity
   */
  async verifyIntegrity(fromId?: string, toId?: string): Promise<IntegrityCheckResult> {
    return this.service.verifyIntegrity(fromId, toId);
  }

  /**
   * Store evidence
   */
  async storeEvidence(input: EvidenceInput): Promise<EvidenceAttachment> {
    return this.service.storeEvidence(input);
  }

  /**
   * Get evidence by ID
   */
  async getEvidence(id: string): Promise<EvidenceData | null> {
    return this.service.getEvidence(id);
  }

  /**
   * Get audit statistics
   */
  async getStats(): Promise<AuditStats> {
    return this.service.getStats();
  }

  /**
   * Export audit trail as JSON Lines
   */
  async *exportAsJsonLines(query: AuditQuery): AsyncIterable<string> {
    for await (const record of this.service.exportEvents(query)) {
      yield JSON.stringify(record) + '\n';
    }
  }

  /**
   * Export audit trail as CSV
   */
  async *exportAsCsv(query: AuditQuery): AsyncIterable<string> {
    // Header row
    yield 'id,timestamp,eventType,category,severity,actorId,transactionId,entityId,description\n';

    for await (const record of this.service.exportEvents(query)) {
      const row = [
        record.id,
        record.timestamp,
        record.eventType,
        record.category,
        record.severity,
        record.actor?.id || '',
        record.correlationIds.transactionId || '',
        record.correlationIds.entityId || '',
        `"${record.description.replace(/"/g, '""')}"`,
      ].join(',');
      yield row + '\n';
    }
  }

  /**
   * Start retention cleanup timer
   */
  private startRetentionCleanup(): void {
    // Run daily
    const intervalMs = 24 * 60 * 60 * 1000;

    this.retentionTimer = setInterval(async () => {
      await this.runRetentionCleanup();
    }, intervalMs);

    // Also run once on startup
    setTimeout(() => this.runRetentionCleanup(), 60000);
  }

  /**
   * Run retention cleanup
   */
  private async runRetentionCleanup(): Promise<void> {
    if (!this.config.retentionDays || this.config.retentionDays <= 0) return;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

    this.logger.info('Running retention cleanup', {
      retentionDays: this.config.retentionDays,
      cutoffDate: cutoffDate.toISOString(),
    });

    // Note: We don't actually delete audit records in production
    // This is just for demonstration - real implementations would archive
    this.logger.info('Retention cleanup complete (archival would happen here)');
  }

  /**
   * Plugin hooks
   */
  readonly hooks: ArkaPluginHooks = {
    onTransaction: async (tx: ArkaTransaction): Promise<void> => {
      await this.service.recordEvent({
        eventType: 'transaction_received',
        actor: { type: 'system', id: 'transaction-stream' },
        correlationIds: {
          transactionId: tx.id,
          entityId: tx.fromEntity?.entityId || tx.toEntity?.entityId || null,
        },
        category: 'transaction',
        severity: 'info',
        description: `Transaction ${tx.id} received: ${tx.amount} ${tx.currency}`,
        data: {
          transactionId: tx.id,
          type: tx.type,
          amount: tx.amount,
          currency: tx.currency,
          source: tx.source,
          fromEntity: tx.fromEntity,
          toEntity: tx.toEntity,
          jurisdiction: tx.jurisdiction,
        },
      });
    },

    onEvent: async (event: ArkaEvent): Promise<void> => {
      await this.service.recordEvent({
        eventType: 'custom',
        actor: { type: 'system', id: event.source },
        correlationIds: {
          entityId: event.entityId,
          externalId: event.id,
        },
        category: 'system',
        severity: 'debug',
        description: `Event ${event.type} from ${event.source}`,
        data: {
          eventId: event.id,
          eventType: event.type,
          entityId: event.entityId,
          entityType: event.entityType,
          payload: event.payload,
        },
      });
    },

    onRuleEvaluation: async (rule: ArkaRule, result: ArkaDecision): Promise<void> => {
      await this.service.recordEvent({
        eventType: result.status === 'ALLOW' ? 'rule_evaluated' : 'rule_fired',
        actor: { type: 'system', id: 'rule-engine' },
        correlationIds: {
          ruleId: rule.id,
          entityId: result.eventId || null,
        },
        category: 'compliance',
        severity: result.status === 'ALLOW' ? 'debug' : 'warn',
        description: `Rule "${rule.name}" evaluated: ${result.status}`,
        data: {
          ruleId: rule.id,
          ruleName: rule.name,
          status: result.status,
          ruleEvaluations: result.ruleEvaluations,
          metadata: result.metadata,
        },
      });
    },

    onAlert: async (alert: Alert): Promise<void> => {
      await this.service.recordEvent({
        eventType: 'alert_generated',
        actor: { type: 'system', id: 'alert-service' },
        correlationIds: {
          alertId: alert.id,
          transactionId: alert.references.transactionIds?.[0] || null,
          entityId: alert.references.entityIds?.[0] || null,
        },
        category: 'compliance',
        severity: alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'error' : 'warn',
        description: `Alert generated: ${alert.title}`,
        data: {
          alertId: alert.id,
          alertType: alert.type,
          severity: alert.severity,
          category: alert.category,
          title: alert.title,
          description: alert.description,
          references: alert.references,
          priority: alert.priority,
        },
      });
    },

    onRiskScore: async (input: RiskInput, result: RiskScoreBundle): Promise<void> => {
      await this.service.recordEvent({
        eventType: 'risk_score_computed',
        actor: { type: 'system', id: 'risk-engine' },
        correlationIds: {
          transactionId: input.transaction?.id || null,
          entityId: input.entity?.id || null,
        },
        category: 'risk',
        severity: result.riskLevel === 'critical' ? 'error' : result.riskLevel === 'high' ? 'warn' : 'info',
        description: `Risk score computed: ${result.overallScore} (${result.riskLevel})`,
        data: {
          transactionId: input.transaction?.id,
          entityId: input.entity?.id,
          overallScore: result.overallScore,
          riskLevel: result.riskLevel,
          factors: result.factors,
          confidence: result.confidence,
          modelVersion: result.modelVersion,
        },
      });
    },
  };
}

/**
 * Factory function to create the plugin
 */
export function createAuditLogPlugin(config?: Partial<AuditLogConfig>): AuditLogPlugin {
  return new AuditLogPlugin(config);
}
