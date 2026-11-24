/**
 * Rule-based prompt injection and jailbreak detector (Prompt Checks, v2).
 *
 * Runs in microseconds with no model call, so it can sit on the synchronous
 * Prompt Checks path. v1 matched 4 exact English phrases and missed every
 * paraphrase, obfuscation and non-English attack in the Langfuse eval suite.
 * v2:
 *   1. normalises the text (case, accents, leetspeak, "i.g.n.o.r.e" spacing)
 *      while keeping a map back to the original characters;
 *   2. matches verb + target patterns ("disregard ... prior instructions",
 *      "reveal ... hidden prompt") instead of fixed phrases, in English,
 *      Spanish, French, German and Portuguese;
 *   3. treats "developer mode" as a jailbreak only when it is aimed at the AI,
 *      not at a phone, browser or OS.
 * Spans point at the original text so the UI can highlight flagged tokens.
 * For prompts the rules call benign, prompt-classifier-model.ts offers an
 * optional, slower model-based second opinion.
 */

export type DetectorCategory = "prompt_injection" | "jailbreak";
export type DetectorSpan = { start: number; end: number; phrase: string; category: DetectorCategory; rule: string };

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i" };
// Latin (with accents), Greek and Cyrillic letters; the repo targets ES5, so no \p{L}.
const LETTER = /[A-Za-z\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]/;
const COMBINING_MARKS = /[\u0300-\u036f]/g;
const SEPARATORS = new Set([".", "-", "_", "*", "​", "‌", "‍", "⁠"]);

/** Lowercase, strip accents, undo leetspeak inside words and drop separators between single letters. */
export function normalize(text: string): { normalized: string; map: number[] } {
  let normalized = "";
  const map: number[] = [];
  const chars = Array.from(text);
  let offset = 0;
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const prev = chars[i - 1] ?? " ";
    const next = chars[i + 1] ?? " ";
    const isLetter = (c: string) => LETTER.test(c);
    // "i.g.n.o.r.e": drop a separator that sits between two letters (or a letter and an escaped letter).
    if (SEPARATORS.has(ch) && isLetter(prev) && isLetter(next) && (!isLetter(chars[i - 2] ?? " ") || !isLetter(chars[i + 2] ?? " "))) {
      offset += ch.length;
      continue;
    }
    let out = ch.normalize("NFD").replace(COMBINING_MARKS, "").toLowerCase();
    // Leetspeak only inside a word, so "order 1042" and "$20" keep their digits.
    if (LEET[ch] && (isLetter(prev) || isLetter(next)) && !/\d/.test(prev) && !/\d/.test(next)) out = LEET[ch];
    for (let k = 0; k < out.length; k++) {
      normalized += out[k];
      map.push(offset);
    }
    offset += ch.length;
  }
  map.push(offset);
  return { normalized, map };
}

const GAP = "[^.!?\\n]{0,40}?";
const SHORT = "[^.!?\\n]{0,25}?";

type Rule = { name: string; category: DetectorCategory; pattern: RegExp };

const OVERRIDE_VERBS = "ignore|disregard|forget|override|bypass|skip|drop|discard|neglect|abandon";
const INSTRUCTION_NOUNS = "instructions?|rules|directions|guidelines|prompts?|context|directives|programming|constraints|system message";
const REVEAL_VERBS = "reveal|print|show|display|output|repeat|leak|dump|list|tell me|give me|share|expose|echo";
const SECRET_QUALIFIERS = "system|hidden|secret|initial|original|internal|confidential|your|developer|pre-?prompt";
const SECRET_NOUNS = "prompt|instructions|rules|configuration|config|guidelines|directives|system message";
const NO_LIMITS =
  "dan|do anything now|no (?:rules|restrictions|limits|limitations|filters|guidelines|content policy|morals|ethics|boundaries)|" +
  "without (?:any )?(?:rules|restrictions|limits|limitations|filters|content filters|content policy|censorship|safety|guardrails)|" +
  "unfiltered|uncensored|unrestricted|jailbroken|jailbreak|evil (?:twin|ai|version|mode)|" +
  "ignores? (?:all |any )?(?:safety|ethical|content) (?:guidelines|rules|policies|filters)";
const PERSONA = "pretend|act|roleplay|role-play|behave|respond|answer|play a game|imagine|you are now|from now on|simulate|become|you're now";
const SAFETY_TARGETS = "(?:safety|content|ethical|moderation|usage) (?:policy|policies|filters?|guidelines|rules|restrictions|guardrails)|guardrails";
const DEVICE_CONTEXT = /\b(android|iphone|ios|phone|tablet|chrome|browser|extensions?|windows|macos|mac|linux|settings|xbox|playstation|tv|router|app store|firmware)\b/;

const RULES: Rule[] = [
  { name: "override_instructions", category: "prompt_injection", pattern: new RegExp(`\\b(?:${OVERRIDE_VERBS})\\b${GAP}\\b(?:previous|prior|above|earlier|preceding|initial|original|all|any|your|the|system|those|these)\\b${SHORT}\\b(?:${INSTRUCTION_NOUNS})\\b`, "g") },
  { name: "ignore_the_above", category: "prompt_injection", pattern: /\b(?:ignore|disregard|forget)\s+(?:the |everything |all )?(?:above|before|prior|preceding)\b/g },
  { name: "forget_what_you_were_told", category: "prompt_injection", pattern: new RegExp(`\\b(?:forget|disregard|ignore)\\s+(?:everything|all|what)\\b${SHORT}\\b(?:told|said|instructed|given|before this|above|previous|prior)\\b`, "g") },
  { name: "reveal_hidden_prompt", category: "prompt_injection", pattern: new RegExp(`\\b(?:${REVEAL_VERBS})\\b${SHORT}\\b(?:${SECRET_QUALIFIERS})\\b${SHORT}\\b(?:${SECRET_NOUNS})\\b`, "g") },
  { name: "reveal_credentials", category: "prompt_injection", pattern: new RegExp(`\\b(?:${REVEAL_VERBS})\\b${SHORT}\\b(?:admin|root|system|api|database|master|service)\\s+(?:password|api key|key|secret|token|credentials)\\b`, "g") },
  { name: "new_instructions", category: "prompt_injection", pattern: /\bnew (?:instructions|rules|system prompt|directives)\s*:|\byou are no longer\b|\bupdated system prompt\b/g },
  { name: "fake_role_tag", category: "prompt_injection", pattern: /<\/?(?:user|system|assistant|instructions?)>|\[\/?(?:system|inst)\]|(?:^|[\n>])\s*(?:system|assistant)\s*:/g },
  { name: "override_es", category: "prompt_injection", pattern: new RegExp(`\\b(?:ignora|olvida|omite|descarta)\\b${GAP}\\binstrucciones\\b|\\b(?:muestra|revela|imprime)\\b${SHORT}\\b(?:prompt|instrucciones)\\b${SHORT}\\bsistema\\b`, "g") },
  { name: "override_fr", category: "prompt_injection", pattern: new RegExp(`\\b(?:ignore[zs]?|oublie[zs]?)\\b${GAP}\\b(?:instructions|consignes)\\b|\\b(?:affiche|montre|revele)\\b${SHORT}\\b(?:prompt|instructions)\\b`, "g") },
  { name: "override_de", category: "prompt_injection", pattern: new RegExp(`\\b(?:ignoriere|ignorieren sie|vergiss|vergessen sie)\\b${GAP}\\b(?:anweisungen|regeln|instruktionen)\\b|\\b(?:zeig|zeige|gib)\\b${SHORT}\\b(?:systemanweisungs?|systemprompt|prompt)\\w*`, "g") },
  { name: "override_pt", category: "prompt_injection", pattern: new RegExp(`\\b(?:ignore|ignora|esqueca|esqueça|desconsidere)\\b${GAP}\\b(?:instrucoes|regras)\\b`, "g") },
  { name: "no_limits_persona", category: "jailbreak", pattern: new RegExp(`\\b(?:${PERSONA})\\b[^.!?\\n]{0,60}?\\b(?:${NO_LIMITS})\\b`, "g") },
  { name: "bypass_safety", category: "jailbreak", pattern: new RegExp(`\\b(?:bypass|disable|ignore|turn off|override|circumvent|get around|switch off|remove)\\b${SHORT}\\b(?:${SAFETY_TARGETS})\\b`, "g") },
];

const DEVELOPER_MODE = /\b(?:developer mode|dev mode|god mode|jailbreak mode|debug mode)\b/g;
const AI_DIRECTED = /\b(you|your|ai|model|assistant|chatbot|policy|restrictions|rules|filters|answer anything)\b/;

/** Spans of injection and jailbreak patterns, in original-text offsets. */
export function detect(text: string): DetectorSpan[] {
  const { normalized, map } = normalize(text);
  const spans: DetectorSpan[] = [];
  const push = (start: number, end: number, category: DetectorCategory, rule: string) => {
    const s = map[start];
    const e = map[end] ?? text.length;
    spans.push({ start: s, end: e, phrase: text.slice(s, e), category, rule });
  };
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(normalized))) {
      const lead = match[0].length - match[0].trimStart().length;
      push(match.index + lead, match.index + match[0].length, rule.category, rule.name);
      if (match[0].length === 0) rule.pattern.lastIndex++;
    }
  }
  // "developer mode" is a jailbreak only when aimed at the assistant, not at a device.
  if (!DEVICE_CONTEXT.test(normalized) && AI_DIRECTED.test(normalized)) {
    DEVELOPER_MODE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = DEVELOPER_MODE.exec(normalized))) push(match.index, match.index + match[0].length, "jailbreak", "developer_mode");
  }
  return spans.sort((a, b) => a.start - b.start);
}

export function labelFromSpans(spans: { category: DetectorCategory }[]): "benign" | DetectorCategory {
  const injection = spans.filter((s) => s.category === "prompt_injection").length;
  const jailbreak = spans.filter((s) => s.category === "jailbreak").length;
  if (!injection && !jailbreak) return "benign";
  return jailbreak > injection ? "jailbreak" : "prompt_injection";
}
