// ClawGuard — Plugin System Barrel Export

export {
  ClawGuardPlugin,
  PluginMeta,
  ClawGuardConfig,
  RuleSeverityOverride,
  ResolvedPlugin,
  PluginLoadError,
  definePlugin,
} from './plugin-types';

export {
  loadPlugin,
  loadPlugins,
  discoverPlugins,
  loadConfig,
  getBuiltinPlugin,
  generatePluginTemplate,
} from './plugin-loader';

/** Semgrep YAML rule adapter */
export {
  loadSemgrepRules,
  loadSemgrepRulesFromFile,
  parseSemgrepYaml,
  convertSemgrepRule,
  semgrepPlugin,
} from './semgrep-adapter';
export type { SemgrepRule, SemgrepRuleFile, SemgrepPattern } from './semgrep-adapter';

/** YARA rule adapter */
export {
  loadYaraRules,
  loadYaraRulesFromFile,
  parseYaraContent,
  parseYaraFile,
  convertYaraRule,
  yaraPlugin,
} from './yara-adapter';
export type { YaraRule, YaraString } from './yara-adapter';
