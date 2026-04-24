/**
 * Web stub for DatabaseService.
 * Uses in-memory storage since expo-sqlite is not available on web.
 * All data is lost on page refresh — web is for testing UI only.
 */
import { CryptoKey } from '../services/CryptoService';
import { QueryResult } from '../types/index';
import { IDatabaseService } from './DatabaseService';

class WebDatabaseService implements IDatabaseService {
  private store: Map<string, Record<string, unknown>[]> = new Map();

  async initialize(_masterKey: CryptoKey): Promise<void> {
    console.info('[WebDB] Using in-memory database (web — data not persisted)');
  }

  async execute(_query: string, _params?: unknown[]): Promise<QueryResult> {
    return { rowsAffected: 0 };
  }

  async insert(table: string, data: Record<string, unknown>): Promise<number> {
    if (!this.store.has(table)) this.store.set(table, []);
    this.store.get(table)!.push(data);
    return this.store.get(table)!.length;
  }

  async update(table: string, id: number, data: Record<string, unknown>): Promise<void> {
    const rows = this.store.get(table) ?? [];
    if (rows[id - 1]) Object.assign(rows[id - 1], data);
  }

  async delete(table: string, id: number): Promise<void> {
    const rows = this.store.get(table) ?? [];
    rows.splice(id - 1, 1);
  }

  async select<T>(query: string, _params?: unknown[]): Promise<T[]> {
    const match = query.match(/FROM\s+(\w+)/i);
    if (match) return (this.store.get(match[1]) ?? []) as T[];
    return [];
  }

  async beginTransaction(): Promise<void> {}
  async commit(): Promise<void> {}
  async rollback(): Promise<void> {}
  async close(): Promise<void> {}
}

export const databaseService: IDatabaseService = new WebDatabaseService();
export default databaseService;
