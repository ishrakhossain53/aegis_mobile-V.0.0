/**
 * ThreatIntelAPI — re-export shim (src/api)
 *
 * The canonical implementation lives in src/services/api/ThreatIntelAPI.ts.
 * This file re-exports everything from there so that Phase 2 modules that
 * import from src/api/ continue to work.
 */
export {
  threatIntelAPI,
  ThreatIntelAPIService,
  type IThreatIntelAPI,
  type ReputationResult,
} from '../services/api/ThreatIntelAPI';
export { threatIntelAPI as default } from '../services/api/ThreatIntelAPI';
