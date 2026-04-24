/**
 * RASPGuard — re-export shim
 *
 * All RASP functionality has been consolidated into src/rasp/RASPGuard.ts
 * (Phase 2 enhanced implementation with vault/crypto op gating and tamper
 * detection). This file re-exports everything from there so that Phase 1
 * imports continue to work without any changes.
 */
export { raspGuard, type IRASPGuard } from '../rasp/RASPGuard';
export { raspGuard as default } from '../rasp/RASPGuard';
