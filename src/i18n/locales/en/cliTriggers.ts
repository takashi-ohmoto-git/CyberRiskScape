import type { TranslationKey } from '../ja';

/** English translation for the CLI `triggers` subcommand (trigger checklist). */
export const enCliTriggers: Partial<Record<TranslationKey, string>> = {
  'cliTriggers.heading': '# Threat modeling trigger checklist',
  'cliTriggers.intro':
    'Check whether this PR needs a threat model update. Tick the items that apply and update the threat model if needed.',

  'cliTriggers.section.auto': '## Auto-detected from the model diff',
  'cliTriggers.section.manual': '## Needs human (or AI reviewer) review (cannot be auto-judged from the model diff)',
};
