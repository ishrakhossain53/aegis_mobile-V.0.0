/**
 * DoHResolver — re-export shim (src/api)
 *
 * The canonical implementation lives in src/services/api/DoHResolver.ts.
 * This file re-exports everything from there so that Phase 2 modules that
 * import from src/api/ continue to work.
 */
export {
  dohResolver,
  DoHResolver,
  type IDoHResolver,
  type DoHResult,
} from '../services/api/DoHResolver';
export { dohResolver as default } from '../services/api/DoHResolver';
