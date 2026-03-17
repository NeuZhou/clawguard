// ClawGuard — Plugin System Type Definitions

import { SecurityRule, Severity } from '../types';

/** Standard plugin interface — implement this to create a ClawGuard plugin */
export interface ClawGuardPlugin {
  /** Unique plugin name (e.g., "clawguard-rules-hipaa") */
  name: string;
  /** Semver version string */
  version: string;
  /** Security rules provided by this plugin */
  rules: SecurityRule[];
  /** Optional metadata */
  meta?: PluginMeta;
}

export interface PluginMeta {
  author?: string;
  description?: string;
  homepage?: string;
  license?: string;
  tags?: string[];
}

/** Rule severity override from config */
export type RuleSeverityOverride = Severity | 'off';

/** Configuration file schema (.clawguardrc.json or clawguard.config.js) */
export interface ClawGuardConfig {
  /** Plugin names to load (npm packages or local paths) */
  plugins?: string[];
  /** Per-rule severity overrides: rule-id → severity or "off" */
  rules?: Record<string, RuleSeverityOverride>;
  /** Minimum severity threshold to report */
  'severity-threshold'?: Severity;
  /** Builtin rule categories to disable */
  'disable-builtin'?: string[];
}

/** Resolved plugin with load source info */
export interface ResolvedPlugin {
  plugin: ClawGuardPlugin;
  source: 'builtin' | 'npm' | 'local-dir' | 'local-file';
  path?: string;
}

/** Plugin load error */
export interface PluginLoadError {
  name: string;
  error: string;
}

/** Helper to create a plugin (for plugin authors) */
export function definePlugin(plugin: ClawGuardPlugin): ClawGuardPlugin {
  return plugin;
}
