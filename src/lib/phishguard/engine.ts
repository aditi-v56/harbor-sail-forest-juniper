export type Severity = "critical" | "high" | "medium" | "low";

export type RedFlag = {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  category:
    | "sender"
    | "auth"
    | "url"
    | "language"
    | "credential"
    | "injection"
    | "pii";
};

export type FeatureVector = {
  urgencyScore: number;
  numUrls: number;
  hasUrl: number;
  suspiciousUrl: number;
  lookalikeDomain: number;
  senderMismatch: number;
  spfFail: number;
  dkimFail: number;
  dmarcFail: number;
  genericGreeting: number;
  asksCredentials: number;
  injectionAttempt: number;
  piiDetected: number;
};

export type EngineResult = {
  features: FeatureVector;
  redFlags: RedFlag[];
  urls: string[];
  masked: {
    subject: string;
    body: string;
    sender: string;
    headers: string;
  };
  piiHits: string[];
  injectionHits: string[];
};

const URGENCY = [
  "urgent",
  "immediately",
  "act now",
  "within 24 hours",
  "account suspended",
  "verify your account",
  "confirm your identity",
  "password expired",
  "security alert",
  "unusual activity",
  "click here",
  "login now",
  "limited time",
  "final notice",
  "action required",
  "suspended",
  "locked",
  "compromised",
  "verify now",
  "update payment",
];

const SUSPICIOUS_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".xyz",
  ".top",
  ".club",
  ".info",
  ".online",
  ".buzz",
  ".click",
];

const BRANDS = [
  "microsoft",
  "google",
  "apple",
  "amazon",
  "paypal",
  "bankofamerica",
  "chase",
  "wellsfargo",
  "citibank",
  "hsbc",
  "icici",
  "hdfc",
  "sbi",
  "axisbank",
  "kotak",
  "outlook",
  "office365",
  "linkedin",
  "dropbox",
];

const INJECTION_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /ignore (all |any )?(previous|prior|above) instructions/i, label: "instruction override" },
  { re: /you are now (a |an )?(unrestricted|dan|jailbreak)/i, label: "persona hijack" },
  { re: /system\s*prompt|reveal (the )?system (message|prompt)/i, label: "system prompt exfil" },
  { re: /disregard (your )?(safety|content|policy)/i, label: "safety override" },
  { re: /<\|?(im_start|system)\|?>/i, label: "token delimiter injection" },
  { re: /\[INST\]|<<SYS>>/i, label: "template token hijack" },
];

function extractUrls(text: string): string[] {
  const re = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;
  return text.match(re) ?? [];
}

function lookalike(domain: string): string | null {
  const host = domain.toLowerCase().replace(/^www\./, "");
  const base = host.split(".")[0] ?? host;
  for (const brand of BRANDS) {
    if (base.includes(brand) && base !== brand) {
      if (/\d/.test(base) || base.includes("-") || base.length > brand.length + 3) {
        return `Lookalike of ${brand}: ${host}`;
      }
    }
    if (Math.abs(base.length - brand.length) <= 2 && base !== brand) {
      let diffs = 0;
      const n = Math.min(base.length, brand.length);
      for (let i = 0; i < n; i++) if (base[i] !== brand[i]) diffs++;
      diffs += Math.abs(base.length - brand.length);
      if (diffs <= 2) return `Possible lookalike of ${brand}: ${host}`;
    }
  }
  return null;
}

export function maskPii(input: string): { text: string; hits: string[] } {
  const hits: string[] = [];
  let text = input;
  const rules: { re: RegExp; label: string; repl: string }[] = [
    {
      re: /\b\d{3}-\d{2}-\d{4}\b/g,
      label: "SSN-like identifier",
      repl: "[REDACTED_SSN]",
    },
    {
      re: /\b(?:\d[ -]*?){13,19}\b/g,
      label: "card-like number",
      repl: "[REDACTED_PAN]",
    },
    {
      re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
      label: "email address",
      repl: "[REDACTED_EMAIL]",
    },
    {
      re: /\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g,
      label: "phone",
      repl: "[REDACTED_PHONE]",
    },
    {
      re: /\b(?:acct|account|a\/c)[\s#:.-]*\d{6,}\b/gi,
      label: "account number",
      repl: "[REDACTED_ACCT]",
    },
  ];
  for (const r of rules) {
    if (r.re.test(text)) {
      hits.push(r.label);
      r.re.lastIndex = 0;
      text = text.replace(r.re, r.repl);
    }
  }
  return { text, hits: [...new Set(hits)] };
}

export function runEngine(input: {
  subject: string;
  body: string;
  sender: string;
  headers: string;
}): EngineResult {
  const subject = input.subject ?? "";
  const body = input.body ?? "";
  const sender = input.sender ?? "";
  const headers = input.headers ?? "";

  const combined = `${subject}\n${body}\n${sender}\n${headers}`;
  const text = `${subject} ${body}`.toLowerCase();
  const flags: RedFlag[] = [];

  const subjMask = maskPii(subject);
  const bodyMask = maskPii(body);
  const sendMask = maskPii(sender);
  const headMask = maskPii(headers);
  const piiHits = [...new Set([...subjMask.hits, ...bodyMask.hits, ...sendMask.hits, ...headMask.hits])];

  const injectionHits: string[] = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(combined)) injectionHits.push(p.label);
  }

  let urgencyCount = 0;
  for (const kw of URGENCY) if (text.includes(kw)) urgencyCount++;
  const urgencyScore = Math.min(urgencyCount / 3, 1);
  if (urgencyCount >= 2) {
    flags.push({
      id: "urgency",
      title: "Urgency / pressure language",
      detail: `${urgencyCount} urgency indicators (account lock, act now, verify immediately).`,
      severity: urgencyCount >= 4 ? "critical" : "high",
      category: "language",
    });
  }

  const urls = extractUrls(combined);
  let suspiciousUrl = 0;
  let lookalikeDomain = 0;
  for (const url of urls) {
    try {
      const href = url.startsWith("http") ? url : `http://${url}`;
      const host = new URL(href).hostname.toLowerCase();
      const tld = host.includes(".") ? `.${host.split(".").pop()}` : "";
      if (SUSPICIOUS_TLDS.includes(tld)) {
        suspiciousUrl = 1;
        flags.push({
          id: `tld-${host}`,
          title: "Suspicious URL TLD",
          detail: `${host} uses a high-abuse TLD (${tld}).`,
          severity: "high",
          category: "url",
        });
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        suspiciousUrl = 1;
        flags.push({
          id: `ip-${host}`,
          title: "IP-literal URL",
          detail: `Link uses a raw IP (${host}) instead of a branded hostname.`,
          severity: "critical",
          category: "url",
        });
      }
      const like = lookalike(host);
      if (like) {
        lookalikeDomain = 1;
        flags.push({
          id: `look-${host}`,
          title: "Lookalike / typosquat domain",
          detail: like,
          severity: "critical",
          category: "url",
        });
      }
    } catch {
      /* ignore parse */
    }
  }

  let senderMismatch = 0;
  const display = sender.includes("<") ? sender.split("<")[0].toLowerCase() : "";
  const actual = sender.includes("<")
    ? sender.split("<").pop()!.replace(">", "").toLowerCase()
    : sender.toLowerCase();
  const domain = actual.includes("@") ? actual.split("@")[1] : "";
  if (display && domain && BRANDS.some((b) => display.includes(b)) && !BRANDS.some((b) => domain.includes(b))) {
    senderMismatch = 1;
    flags.push({
      id: "display-spoof",
      title: "Display-name spoof",
      detail: `Display name claims a trusted brand but the mailbox is ${domain || actual}.`,
      severity: "critical",
      category: "sender",
    });
  }

  const h = headers.toLowerCase();
  const spfFail = /spf=(fail|softfail)/.test(h) ? 1 : 0;
  const dkimFail = /dkim=(fail|none)/.test(h) ? 1 : 0;
  const dmarcFail = /dmarc=fail/.test(h) ? 1 : 0;
  if (spfFail || dkimFail || dmarcFail) {
    flags.push({
      id: "auth",
      title: "Authentication failure",
      detail: `SPF ${spfFail ? "fail" : "ok"} · DKIM ${dkimFail ? "fail/none" : "ok"} · DMARC ${dmarcFail ? "fail" : "ok"}.`,
      severity: "high",
      category: "auth",
    });
  }

  const genericGreeting = /(dear customer|dear user|dear valued|hello sir|dear account holder)/.test(text)
    ? 1
    : 0;
  if (genericGreeting) {
    flags.push({
      id: "greeting",
      title: "Generic greeting",
      detail: "No personalization — typical of mass phishing kits.",
      severity: "medium",
      category: "language",
    });
  }

  const asksCredentials = /(password|otp|pin|cvv|credit card|bank account|ssn|login credentials|one[- ]time)/.test(
    text,
  )
    ? 1
    : 0;
  if (asksCredentials) {
    flags.push({
      id: "creds",
      title: "Credential / payment harvest",
      detail: "Body requests passwords, OTP, PAN, or banking secrets.",
      severity: "critical",
      category: "credential",
    });
  }

  if (injectionHits.length) {
    flags.push({
      id: "injection",
      title: "Prompt-injection / token hijack",
      detail: `Detected: ${injectionHits.join(", ")}. Body will not be treated as instructions.`,
      severity: "critical",
      category: "injection",
    });
  }

  if (piiHits.length) {
    flags.push({
      id: "pii",
      title: "PII present — masked before model",
      detail: `Redacted: ${piiHits.join(", ")}.`,
      severity: "low",
      category: "pii",
    });
  }

  return {
    features: {
      urgencyScore,
      numUrls: urls.length,
      hasUrl: urls.length ? 1 : 0,
      suspiciousUrl,
      lookalikeDomain,
      senderMismatch,
      spfFail,
      dkimFail,
      dmarcFail,
      genericGreeting,
      asksCredentials,
      injectionAttempt: injectionHits.length ? 1 : 0,
      piiDetected: piiHits.length ? 1 : 0,
    },
    redFlags: flags,
    urls,
    masked: {
      subject: subjMask.text,
      body: bodyMask.text,
      sender: sendMask.text,
      headers: headMask.text,
    },
    piiHits,
    injectionHits,
  };
}

export function scoreFromEngine(engine: EngineResult): {
  risk: number;
  phishingProb: number;
  label: "phishing" | "safe";
  needsHuman: boolean;
  confidence: number;
} {
  const f = engine.features;
  let raw =
    f.lookalikeDomain * 28 +
    f.senderMismatch * 22 +
    f.asksCredentials * 18 +
    f.suspiciousUrl * 12 +
    f.spfFail * 8 +
    f.dkimFail * 6 +
    f.dmarcFail * 8 +
    f.urgencyScore * 16 +
    f.genericGreeting * 6 +
    f.injectionAttempt * 10;

  const risk = Math.max(4, Math.min(99, Math.round(raw)));
  const phishingProb = risk / 100;
  const confidence = Math.max(phishingProb, 1 - phishingProb);

  let label: "phishing" | "safe" = phishingProb >= 0.5 ? "phishing" : "safe";
  let needsHuman = true;
  if (phishingProb >= 0.85) needsHuman = false;
  else if (1 - phishingProb >= 0.8) {
    label = "safe";
    needsHuman = false;
  }
  if (engine.features.injectionAttempt) needsHuman = true;
  if (engine.redFlags.filter((r) => r.severity === "critical").length >= 2 && risk < 85) {
    needsHuman = true;
  }

  return { risk, phishingProb, label, needsHuman, confidence };
}
