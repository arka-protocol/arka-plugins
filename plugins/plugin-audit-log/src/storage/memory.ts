/**
 * In-Memory Storage Backend
 *
 * Simple in-memory storage for development and testing.
 */

import type { AuditRecord, AuditQuery } from '@arka/types';
import type { AuditStorageBackend, EvidenceStorageBackend, EvidenceAttachment } from '../types.js';

/**
 * In-memory audit storage backend
 */
export class InMemoryAuditStorage implements AuditStorageBackend {
  private records: Map<string, AuditRecord> = new Map();
  private orderedIds: string[] = [];

  async init(): Promise<void> {
    // No initialization needed
  }

  async insert(record: AuditRecord): Promise<void> {
    this.records.set(record.id, record);
    this.orderedIds.push(record.id);
  }

  async insertBatch(records: AuditRecord[]): Promise<void> {
    for (const record of records) {
      await this.insert(record);
    }
  }

  async query(query: AuditQuery): Promise<AuditRecord[]> {
    let results = Array.from(this.records.values());

    // Filter by event types
    if (query.eventTypes?.length) {
      results = results.filter(r => query.eventTypes!.includes(r.eventType));
    }

    // Filter by categories
    if (query.categories?.length) {
      results = results.filter(r => query.categories!.includes(r.category));
    }

    // Filter by severities
    if (query.severities?.length) {
      results = results.filter(r => query.severities!.includes(r.severity));
    }

    // Filter by actor ID
    if (query.actorId) {
      results = results.filter(r => r.actor?.id === query.actorId);
    }

    // Filter by correlation IDs
    if (query.correlationIds) {
      results = results.filter(r => {
        if (query.correlationIds!.transactionId && r.correlationIds.transactionId !== query.correlationIds!.transactionId) {
          return false;
        }
        if (query.correlationIds!.entityId && r.correlationIds.entityId !== query.correlationIds!.entityId) {
          return false;
        }
        if (query.correlationIds!.ruleId && r.correlationIds.ruleId !== query.correlationIds!.ruleId) {
          return false;
        }
        if (query.correlationIds!.alertId && r.correlationIds.alertId !== query.correlationIds!.alertId) {
          return false;
        }
        if (query.correlationIds!.requestId && r.correlationIds.requestId !== query.correlationIds!.requestId) {
          return false;
        }
        return true;
      });
    }

    // Filter by timestamp range
    if (query.fromTimestamp) {
      results = results.filter(r => r.timestamp >= query.fromTimestamp!);
    }
    if (query.toTimestamp) {
      results = results.filter(r => r.timestamp < query.toTimestamp!);
    }

    // Sort
    if (query.orderBy === 'timestamp_asc') {
      results.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    } else {
      results.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    }

    // Pagination
    const offset = query.offset || 0;
    const limit = query.limit || 100;
    results = results.slice(offset, offset + limit);

    return results;
  }

  async get(id: string): Promise<AuditRecord | null> {
    return this.records.get(id) || null;
  }

  async getLastRecord(): Promise<AuditRecord | null> {
    if (this.orderedIds.length === 0) return null;
    const lastId = this.orderedIds[this.orderedIds.length - 1];
    if (!lastId) return null;
    return this.records.get(lastId) ?? null;
  }

  async getRange(fromId: string, toId: string): Promise<AuditRecord[]> {
    const fromIndex = this.orderedIds.indexOf(fromId);
    const toIndex = this.orderedIds.indexOf(toId);

    if (fromIndex === -1 || toIndex === -1) {
      return [];
    }

    const ids = this.orderedIds.slice(fromIndex, toIndex + 1);
    return ids.map(id => this.records.get(id)!).filter(Boolean);
  }

  async count(query?: Partial<AuditQuery>): Promise<number> {
    if (!query) {
      return this.records.size;
    }

    const results = await this.query(query as AuditQuery);
    return results.length;
  }

  async deleteOlderThan(timestamp: string): Promise<number> {
    let deleted = 0;
    const toDelete: string[] = [];

    for (const [id, record] of this.records) {
      if (record.timestamp < timestamp) {
        toDelete.push(id);
      }
    }

    for (const id of toDelete) {
      this.records.delete(id);
      const index = this.orderedIds.indexOf(id);
      if (index >= 0) {
        this.orderedIds.splice(index, 1);
      }
      deleted++;
    }

    return deleted;
  }

  async close(): Promise<void> {
    this.records.clear();
    this.orderedIds = [];
  }
}

/**
 * In-memory evidence storage backend
 */
export class InMemoryEvidenceStorage implements EvidenceStorageBackend {
  private evidence: Map<string, { content: Buffer; metadata: Omit<EvidenceAttachment, 'storageRef'> }> = new Map();

  async store(
    id: string,
    content: Buffer,
    metadata: Omit<EvidenceAttachment, 'storageRef'>
  ): Promise<string> {
    const storageRef = `memory://${id}`;
    this.evidence.set(storageRef, { content, metadata });
    return storageRef;
  }

  async retrieve(storageRef: string): Promise<Buffer | null> {
    const data = this.evidence.get(storageRef);
    return data?.content || null;
  }

  async delete(storageRef: string): Promise<boolean> {
    return this.evidence.delete(storageRef);
  }

  async getTotalSize(): Promise<number> {
    let total = 0;
    for (const { content } of this.evidence.values()) {
      total += content.length;
    }
    return total;
  }

  async count(): Promise<number> {
    return this.evidence.size;
  }
}
