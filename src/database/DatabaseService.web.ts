/**
 * Web stub for DatabaseService.
 *
 * expo-sqlite is not available on web, so we implement a full in-memory
 * store that correctly handles the SQL patterns used by VaultService,
 * ThreatStore, NetworkStore, and SecurityScoreService.
 *
 * Data is NOT persisted across page refreshes — web is for development/testing only.
 */

import { CryptoKey } from '../services/CryptoService';
import { QueryResult } from '../types/index';
import { IDatabaseService } from './DatabaseService';

// ---------------------------------------------------------------------------
// Tiny in-memory row store keyed by table name
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>;

class InMemoryStore {
  private tables: Map<string, Row[]> = new Map();
  private autoIncrements: Map<string, number> = new Map();

  private getTable(name: string): Row[] {
    if (!this.tables.has(name)) this.tables.set(name, []);
    return this.tables.get(name)!;
  }

  insert(table: string, row: Row): number {
    const rows = this.getTable(table);
    // Handle AUTOINCREMENT integer primary keys
    if (row.id === undefined || row.id === null) {
      const next = (this.autoIncrements.get(table) ?? 0) + 1;
      this.autoIncrements.set(table, next);
      row = { ...row, id: next };
    }
    rows.push(row);
    return typeof row.id === 'number' ? row.id : rows.length;
  }

  selectAll(table: string): Row[] {
    return this.getTable(table).slice();
  }

  selectWhere(table: string, col: string, val: unknown): Row[] {
    return this.getTable(table).filter((r) => r[col] === val);
  }

  updateWhere(table: string, col: string, val: unknown, changes: Row): number {
    const rows = this.getTable(table);
    let affected = 0;
    for (const row of rows) {
      if (row[col] === val) {
        Object.assign(row, changes);
        affected++;
      }
    }
    return affected;
  }

  deleteWhere(table: string, col: string, val: unknown): number {
    const rows = this.getTable(table);
    const before = rows.length;
    const remaining = rows.filter((r) => r[col] !== val);
    this.tables.set(table, remaining);
    return before - remaining.length;
  }

  clear(): void {
    this.tables.clear();
    this.autoIncrements.clear();
  }
}

// ---------------------------------------------------------------------------
// SQL mini-parser
// Handles the exact patterns emitted by VaultService / DatabaseService:
//   INSERT INTO <table> (<cols>) VALUES (?, ?, ...)
//   SELECT * FROM <table> [WHERE id = ?] [ORDER BY ...]
//   UPDATE <table> SET col=?, col=? WHERE id = ?
//   DELETE FROM <table> WHERE id = ?
// ---------------------------------------------------------------------------

const store = new InMemoryStore();

function parseTableName(sql: string): string {
  const m = sql.match(/(?:INTO|FROM|UPDATE)\s+(\w+)/i);
  return m ? m[1] : '';
}

function parseInsertColumns(sql: string): string[] {
  const m = sql.match(/\(([^)]+)\)\s+VALUES/i);
  if (!m) return [];
  return m[1].split(',').map((c) => c.trim());
}

function parseSetColumns(sql: string): string[] {
  const m = sql.match(/SET\s+(.+?)\s+WHERE/i);
  if (!m) return [];
  return m[1].split(',').map((part) => part.split('=')[0].trim());
}

function parseWhereIdColumn(sql: string): string {
  // Matches "WHERE id = ?" or "WHERE last_used = ?" etc.
  const m = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
  return m ? m[1] : 'id';
}

function parseOrderBy(sql: string): { col: string; desc: boolean } | null {
  const m = sql.match(/ORDER\s+BY\s+(\w+)(?:\s+(ASC|DESC))?/i);
  if (!m) return null;
  return { col: m[1], desc: (m[2] ?? '').toUpperCase() === 'DESC' };
}

// ---------------------------------------------------------------------------
// WebDatabaseService
// ---------------------------------------------------------------------------

class WebDatabaseService implements IDatabaseService {
  async initialize(_masterKey: CryptoKey): Promise<void> {
    // No-op: in-memory store is always ready
    console.info('[WebDB] Using in-memory database (web — data not persisted)');
  }

  async execute(query: string, params: unknown[] = []): Promise<QueryResult> {
    const q = query.trim();
    const upper = q.toUpperCase();
    const table = parseTableName(q);

    // ── INSERT ──────────────────────────────────────────────────────────────
    if (upper.startsWith('INSERT INTO')) {
      const cols = parseInsertColumns(q);
      const row: Row = {};
      cols.forEach((col, i) => { row[col] = params[i] ?? null; });
      const insertId = store.insert(table, row);
      return { rowsAffected: 1, insertId };
    }

    // ── UPDATE ──────────────────────────────────────────────────────────────
    if (upper.startsWith('UPDATE')) {
      const setCols = parseSetColumns(q);
      const whereCol = parseWhereIdColumn(q);
      // params: [val1, val2, ..., whereVal]
      const whereVal = params[setCols.length];
      const changes: Row = {};
      setCols.forEach((col, i) => { changes[col] = params[i] ?? null; });
      const affected = store.updateWhere(table, whereCol, whereVal, changes);
      return { rowsAffected: affected };
    }

    // ── DELETE ──────────────────────────────────────────────────────────────
    if (upper.startsWith('DELETE FROM')) {
      const whereCol = parseWhereIdColumn(q);
      const affected = store.deleteWhere(table, whereCol, params[0]);
      return { rowsAffected: affected };
    }

    // ── PRAGMA / DDL — ignore ────────────────────────────────────────────────
    return { rowsAffected: 0 };
  }

  async insert(table: string, data: Record<string, unknown>): Promise<number> {
    return store.insert(table, { ...data });
  }

  async update(table: string, id: number, data: Record<string, unknown>): Promise<void> {
    store.updateWhere(table, 'id', id, data);
  }

  async delete(table: string, id: number): Promise<void> {
    store.deleteWhere(table, 'id', id);
  }

  async select<T>(query: string, params: unknown[] = []): Promise<T[]> {
    const q = query.trim();
    const upper = q.toUpperCase();
    const table = parseTableName(q);
    const hasWhere = upper.includes('WHERE');
    const orderBy = parseOrderBy(q);

    let rows: Row[];

    if (hasWhere) {
      const whereCol = parseWhereIdColumn(q);
      rows = store.selectWhere(table, whereCol, params[0]);
    } else {
      rows = store.selectAll(table);
    }

    // Apply ORDER BY
    if (orderBy) {
      const { col, desc } = orderBy;
      rows = rows.slice().sort((a, b) => {
        const av = a[col] as number ?? 0;
        const bv = b[col] as number ?? 0;
        return desc ? bv - av : av - bv;
      });
    }

    return rows as T[];
  }

  async beginTransaction(): Promise<void> {}
  async commit(): Promise<void> {}
  async rollback(): Promise<void> {}
  async close(): Promise<void> { store.clear(); }
}

export const databaseService: IDatabaseService = new WebDatabaseService();
export default databaseService;
