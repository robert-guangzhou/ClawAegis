import { sanitizeEncodedSecretVariants } from "./encoding-guard.js";

const EMAIL_ADDRESS_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const GENERIC_PHONE_RE = /(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4,6}(?!\w)/g;
const CN_MOBILE_PHONE_RE = /(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)/g;
const LABELED_API_KEY_RE =
  /((?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?)([A-Za-z0-9\-_.~+/]{12,}=*)(["']?)/gi;
const LABELED_SECRET_RE =
  /((?:bearer|token|password|passwd|secret)\s*[:=]\s*["']?)([A-Za-z0-9\-_.~+/]{12,}=*)(["']?)/gi;
const PREFIXED_API_KEY_PATTERNS = [
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bsk-[A-Za-z0-9]{16,}\b/g },
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bpk_[A-Za-z0-9]{16,}\b/g },
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bghp_[A-Za-z0-9]{20,}\b/g },
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bAKIA[A-Z0-9]{16}\b/g },
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bAIza[0-9A-Za-z\-_]{20,}\b/g },
  { category: "api_key", placeholder: "<API_KEY>", regex: /\bhf_[A-Za-z0-9]{16,}\b/g },
  { category: "secret_token", placeholder: "<SECRET>", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { category: "secret_token", placeholder: "<SECRET>", regex: /\bSG\.[A-Za-z0-9_\-.]{16,}\b/g },
];
const HIGH_ENTROPY_TOKEN_RE = /(?<![A-Za-z0-9\-_.~+/=])[A-Za-z0-9\-_.~+/]{20,}={0,3}(?![A-Za-z0-9\-_.~+/=])/g;

const HIGH_ENTROPY_PLACEHOLDER = "<SECRET>";
const PLACEHOLDER_TOKENS = new Set([
  "<EMAIL_ADDRESS>",
  "<PHONE_NUMBER>",
  "<API_KEY>",
  "<SECRET>",
  "***",
]);

function incrementCount(map, key, amount = 1) {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function appendUnique(values, nextValues) {
  const seen = new Set(values);
  const merged = [...values];
  for (const value of nextValues) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    merged.push(trimmed);
  }
  return merged;
}

function shannonEntropy(value) {
  if (!value) {
    return 0;
  }
  const frequencies = new Map();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function looksLikeHighEntropySecret(token) {
  if (
    token.length < 20 ||
    token.length > 256 ||
    PLACEHOLDER_TOKENS.has(token) ||
    /^[a-z]+$/i.test(token) ||
    /^[0-9]+$/.test(token) ||
    /^[a-f0-9]{32,}$/i.test(token)
  ) {
    return false;
  }
  const hasLetter = /[A-Za-z]/.test(token);
  const hasDigit = /\d/.test(token);
  const hasSpecial = /[-_.~+/=]/.test(token);
  if (!hasLetter || !hasDigit || (!hasSpecial && token.length < 28)) {
    return false;
  }
  return shannonEntropy(token) >= 4.0;
}

function uniqueSortedSecretCandidates(values) {
  return [...new Set(values.map((value) => value.trim()).filter((value) => value.length >= 8))]
    .filter((value) => !PLACEHOLDER_TOKENS.has(value))
    .sort((left, right) => right.length - left.length || left.localeCompare(right));
}

export function sanitizeLlmPromptText(
  text,
  options = {},
) {
  const categoryCounts = new Map();
  const riskFlags = new Set();
  let secretCandidates = appendUnique([], options.observedSecrets ?? []);
  let next = text;

  next = next.replace(EMAIL_ADDRESS_RE, () => {
    incrementCount(categoryCounts, "email_address");
    riskFlags.add("llm-prompt-email-address");
    return "<EMAIL_ADDRESS>";
  });

  next = next.replace(GENERIC_PHONE_RE, () => {
    incrementCount(categoryCounts, "phone_number");
    riskFlags.add("llm-prompt-phone-number");
    return "<PHONE_NUMBER>";
  });

  next = next.replace(CN_MOBILE_PHONE_RE, () => {
    incrementCount(categoryCounts, "phone_number");
    riskFlags.add("llm-prompt-phone-number");
    return "<PHONE_NUMBER>";
  });

  next = next.replace(LABELED_API_KEY_RE, (_match, prefix, value, suffix) => {
    incrementCount(categoryCounts, "api_key");
    riskFlags.add("llm-prompt-api-key");
    secretCandidates = appendUnique(secretCandidates, [value]);
    return `${prefix}<API_KEY>${suffix}`;
  });

  next = next.replace(LABELED_SECRET_RE, (_match, prefix, value, suffix) => {
    incrementCount(categoryCounts, "secret_token");
    riskFlags.add("llm-prompt-secret-token");
    secretCandidates = appendUnique(secretCandidates, [value]);
    return `${prefix}<SECRET>${suffix}`;
  });

  for (const pattern of PREFIXED_API_KEY_PATTERNS) {
    next = next.replace(pattern.regex, (match) => {
      incrementCount(categoryCounts, pattern.category);
      riskFlags.add(
        pattern.category === "api_key" ? "llm-prompt-api-key" : "llm-prompt-secret-token",
      );
      secretCandidates = appendUnique(secretCandidates, [match]);
      return pattern.placeholder;
    });
  }

  const encodedSecretCandidates = uniqueSortedSecretCandidates(secretCandidates);
  const encodedRedactions = sanitizeEncodedSecretVariants(
    next,
    encodedSecretCandidates,
    HIGH_ENTROPY_PLACEHOLDER,
  );
  if (encodedRedactions.changed) {
    next = encodedRedactions.value;
    incrementCount(categoryCounts, "encoded_secret", encodedRedactions.redactionCount);
    riskFlags.add("llm-prompt-encoded-secret");
  }

  next = next.replace(HIGH_ENTROPY_TOKEN_RE, (match) => {
    if (!looksLikeHighEntropySecret(match)) {
      return match;
    }
    incrementCount(categoryCounts, "secret_token");
    riskFlags.add("llm-prompt-secret-token");
    secretCandidates = appendUnique(secretCandidates, [match]);
    return HIGH_ENTROPY_PLACEHOLDER;
  });

  const finalSecretCandidates = uniqueSortedSecretCandidates(secretCandidates);
  const categoryCountsObject = Object.fromEntries(categoryCounts.entries());
  const redactionCount = [...categoryCounts.values()].reduce((total, count) => total + count, 0);

  return {
    value: next,
    changed: next !== text,
    redactionCount,
    matchedCategories: [...categoryCounts.keys()].sort(),
    categoryCounts: categoryCountsObject,
    riskFlags: [...riskFlags].sort(),
    secretCandidates: finalSecretCandidates,
  };
}
