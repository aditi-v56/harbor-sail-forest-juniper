// PhishGuard – Overloaded Phishing Inbox
// Microsoft / Student Hackathon 2026 Pitch Deck

const pptxgen = require("pptxgenjs");

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "PhishGuard – Overloaded Phishing Inbox";
pres.author = "Team PhishGuard";
pres.subject = "Microsoft Hackathon / SIH 2026 Student Edition";

const SW = 13.333;
const SH = 7.5;
const BG = "0E1513";
const INK = "EDE9DE";
const INK_DIM = "8A8F86";
const INK_DIMMER = "5E635B";
const GREEN = "A8D95E";
const AMBER = "E8A54A";
const RED = "E85A4A";
const HAIRLINE = "2A322E";
const FONT_MONO = "Consolas";
const FONT_SERIF = "Georgia";
const FONT_BODY = "Calibri";
const MARGIN_L = 0.55;
const MARGIN_R = 0.55;
const HEADER_Y = 0.32;

const softShadow = () => ({
  type: "outer", color: "000000", blur: 8, offset: 2, angle: 90, opacity: 0.25,
});

function addCornerMarks(slide) {
  const len = 0.18;
  const pad = 0.2;
  const col = INK_DIMMER;
  slide.addShape(pres.shapes.LINE, { x: pad, y: pad, w: len, h: 0, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: pad, y: pad, w: 0, h: len, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: SW - pad - len, y: pad, w: len, h: 0, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: SW - pad, y: pad, w: 0, h: len, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: pad, y: SH - pad, w: len, h: 0, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: pad, y: SH - pad - len, w: 0, h: len, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: SW - pad - len, y: SH - pad, w: len, h: 0, line: { color: col, width: 0.75 } });
  slide.addShape(pres.shapes.LINE, { x: SW - pad, y: SH - pad - len, w: 0, h: len, line: { color: col, width: 0.75 } });
}

function addTopBar(slide, section, page) {
  slide.addText(
    [
      { text: "PHISHGUARD ", options: { color: INK } },
      { text: "// ", options: { color: INK_DIM } },
      { text: section, options: { color: GREEN } },
    ],
    { x: MARGIN_L, y: HEADER_Y, w: 9, h: 0.3, fontFace: FONT_MONO, fontSize: 11, charSpacing: 1.5, margin: 0 }
  );
  slide.addText(String(page).padStart(2, "0"), {
    x: SW - MARGIN_R - 0.6, y: HEADER_Y, w: 0.6, h: 0.3,
    fontFace: FONT_MONO, fontSize: 11, color: INK_DIM, align: "right", margin: 0,
  });
}

// SLIDE 1 – Title
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  slide.addText("PHISHGUARD", {
    x: MARGIN_L, y: 2.1, w: 12, h: 0.7,
    fontFace: FONT_MONO, fontSize: 42, color: GREEN, bold: true, charSpacing: 4, margin: 0,
  });
  slide.addText("Overloaded Phishing Inbox", {
    x: MARGIN_L, y: 2.85, w: 12, h: 0.55,
    fontFace: FONT_SERIF, fontSize: 28, color: INK, italic: true, margin: 0,
  });
  slide.addText("AI-powered triage that labels, explains, ranks risk, and routes low-confidence mail to humans.", {
    x: MARGIN_L, y: 3.55, w: 10, h: 0.45,
    fontFace: FONT_BODY, fontSize: 16, color: INK_DIM, margin: 0,
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: MARGIN_L, y: 4.3, w: 2.8, h: 0.08, fill: { color: GREEN }, line: { color: GREEN, width: 0 },
  });
  slide.addText("MICROSOFT / STUDENT HACKATHON 2026  ·  INDIA", {
    x: MARGIN_L, y: 4.6, w: 10, h: 0.3,
    fontFace: FONT_MONO, fontSize: 12, color: INK_DIM, charSpacing: 1, margin: 0,
  });
  slide.addText("Bank email-security team  ·  5,000 staff  ·  Report-phishing mailbox drowning", {
    x: MARGIN_L, y: 5.0, w: 10, h: 0.3,
    fontFace: FONT_BODY, fontSize: 14, color: INK_DIMMER, margin: 0,
  });
}

// SLIDE 2 – Problem
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "THE PROBLEM", 2);
  slide.addText("The report-phishing mailbox is drowning", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.5,
    fontFace: FONT_SERIF, fontSize: 26, color: INK, italic: true, margin: 0,
  });
  const problems = [
    { title: "Volume", body: "Thousands of staff reports flood the shared mailbox every week. Analysts cannot keep up." },
    { title: "Blind Spots", body: "Manual triage misses lookalike domains, failed authentication, and subtle social-engineering cues." },
    { title: "No Ranking", body: "Every email looks the same in the queue. Critical phishing sits next to false alarms." },
  ];
  problems.forEach((p, i) => {
    const x = MARGIN_L + i * 4.1;
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x, y: 1.7, w: 3.85, h: 3.4,
      fill: { color: "141C19" }, line: { color: HAIRLINE, width: 1 }, shadow: softShadow(),
    });
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x, y: 1.7, w: 0.08, h: 3.4, fill: { color: GREEN }, line: { width: 0 },
    });
    slide.addText(p.title, {
      x: x + 0.3, y: 2.0, w: 3.3, h: 0.4,
      fontFace: FONT_MONO, fontSize: 16, color: GREEN, bold: true, margin: 0,
    });
    slide.addText(p.body, {
      x: x + 0.3, y: 2.6, w: 3.3, h: 2.0,
      fontFace: FONT_BODY, fontSize: 15, color: INK, margin: 0,
    });
  });
}

// SLIDE 3 – Solution
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "SOLUTION", 3);
  slide.addText("PhishGuard in one sentence", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 24, color: INK, italic: true, margin: 0,
  });
  slide.addText("Read  →  Label  →  Explain  →  Rank  →  Human-or-Auto", {
    x: MARGIN_L, y: 1.4, w: 12, h: 0.4,
    fontFace: FONT_MONO, fontSize: 18, color: GREEN, margin: 0,
  });
  const steps = [
    { num: "01", title: "Ingest", desc: "Paste, .eml, Graph API or Report-Phishing button" },
    { num: "02", title: "Extract", desc: "TF-IDF + 16 structural red-flag features" },
    { num: "03", title: "Classify", desc: "Random Forest → phishing / safe + confidence" },
    { num: "04", title: "Decide", desc: "Risk 0-100 • Low-conf → human queue" },
    { num: "05", title: "Rank", desc: "Priority queue for analysts, highest risk first" },
  ];
  steps.forEach((s, i) => {
    const y = 2.1 + i * 0.9;
    slide.addText(s.num, {
      x: MARGIN_L, y: y, w: 0.8, h: 0.5,
      fontFace: FONT_MONO, fontSize: 20, color: GREEN, bold: true, margin: 0,
    });
    slide.addText(s.title, {
      x: MARGIN_L + 1.0, y: y, w: 2.5, h: 0.5,
      fontFace: FONT_BODY, fontSize: 18, color: INK, bold: true, margin: 0,
    });
    slide.addText(s.desc, {
      x: MARGIN_L + 3.6, y: y, w: 8, h: 0.5,
      fontFace: FONT_BODY, fontSize: 16, color: INK_DIM, margin: 0,
    });
  });
}

// SLIDE 4 – Red Flags
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "EXPLAINABILITY", 4);
  slide.addText("Every verdict is tagged with specific reasons", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  const flags = [
    { title: "Spoofed / Lookalike Sender", desc: "Display name vs domain mismatch, brand lookalikes (micros0ft, paypa1)" },
    { title: "Authentication Failures", desc: "SPF / DKIM / DMARC fail or missing in headers" },
    { title: "Urgency Language", desc: "“Act now”, “24 hours”, “account suspended” density score" },
    { title: "Risky Links", desc: "Suspicious TLDs (.xyz, .tk), IP-in-URL, shortened domains" },
    { title: "Credential Harvesting", desc: "Requests for password, OTP, CVV, bank details" },
    { title: "Generic Greeting", desc: "“Dear Customer / User” instead of real name" },
  ];
  flags.forEach((f, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = MARGIN_L + col * 6.3;
    const y = 1.55 + row * 1.65;
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x, y: y, w: 6.0, h: 1.45,
      fill: { color: "141C19" }, line: { color: HAIRLINE, width: 1 },
    });
    slide.addText(f.title, {
      x: x + 0.25, y: y + 0.25, w: 5.5, h: 0.35,
      fontFace: FONT_BODY, fontSize: 16, color: GREEN, bold: true, margin: 0,
    });
    slide.addText(f.desc, {
      x: x + 0.25, y: y + 0.7, w: 5.5, h: 0.55,
      fontFace: FONT_BODY, fontSize: 14, color: INK_DIM, margin: 0,
    });
  });
}

// SLIDE 5 – Metrics
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "PERFORMANCE", 5);
  slide.addText("Reported precision & recall", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  const mets = [
    { val: "97%+", label: "Precision" },
    { val: "95%+", label: "Recall" },
    { val: "96%+", label: "F1-Score" },
  ];
  mets.forEach((m, i) => {
    const x = MARGIN_L + i * 4.1;
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x, y: 1.6, w: 3.85, h: 2.4,
      fill: { color: "141C19" }, line: { color: HAIRLINE, width: 1 }, shadow: softShadow(),
    });
    slide.addText(m.val, {
      x: x, y: 2.0, w: 3.85, h: 0.9,
      fontFace: FONT_MONO, fontSize: 42, color: GREEN, bold: true, align: "center", margin: 0,
    });
    slide.addText(m.label, {
      x: x, y: 3.1, w: 3.85, h: 0.4,
      fontFace: FONT_BODY, fontSize: 16, color: INK_DIM, align: "center", margin: 0,
    });
  });
  slide.addText("Training data: public phishing corpora (SpamAssassin, Nazario) + Enron legitimate mail + synthetic realistic samples.\nLow-confidence threshold routes ambiguous cases to human analysts instead of auto-deciding.", {
    x: MARGIN_L, y: 4.4, w: 12, h: 1.2,
    fontFace: FONT_BODY, fontSize: 15, color: INK_DIM, margin: 0,
  });
}

// SLIDE 6 – Human-in-the-loop
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "HUMAN-IN-THE-LOOP", 6);
  slide.addText("Flag low-confidence emails for a human", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  const decisions = [
    { conf: "≥ 85% phishing", action: "Auto-label PHISHING", color: RED },
    { conf: "≥ 80% safe", action: "Auto-label SAFE", color: GREEN },
    { conf: "Anything else", action: "HUMAN REVIEW QUEUE", color: AMBER },
  ];
  decisions.forEach((d, i) => {
    const y = 1.7 + i * 1.3;
    slide.addShape(pres.shapes.RECTANGLE, {
      x: MARGIN_L, y: y, w: 12.2, h: 1.1,
      fill: { color: "141C19" }, line: { color: HAIRLINE, width: 1 },
    });
    slide.addShape(pres.shapes.RECTANGLE, {
      x: MARGIN_L, y: y, w: 0.12, h: 1.1, fill: { color: d.color }, line: { width: 0 },
    });
    slide.addText(d.conf, {
      x: MARGIN_L + 0.5, y: y + 0.3, w: 5, h: 0.5,
      fontFace: FONT_MONO, fontSize: 18, color: INK, margin: 0,
    });
    slide.addText(d.action, {
      x: MARGIN_L + 6, y: y + 0.3, w: 5.5, h: 0.5,
      fontFace: FONT_BODY, fontSize: 18, color: d.color, bold: true, margin: 0,
    });
  });
}

// SLIDE 7 – Ranked Queue
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "RANKED QUEUE", 7);
  slide.addText("Output: queue ranked by risk", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: MARGIN_L, y: 1.5, w: 12.2, h: 0.5, fill: { color: "1A2420" }, line: { width: 0 },
  });
  const headers = ["ID", "Subject", "Risk", "Verdict", "Human?"];
  const widths = [1.5, 5.5, 1.5, 2.0, 1.7];
  let hx = MARGIN_L + 0.2;
  headers.forEach((h, i) => {
    slide.addText(h, {
      x: hx, y: 1.55, w: widths[i], h: 0.4,
      fontFace: FONT_MONO, fontSize: 13, color: GREEN, bold: true, margin: 0,
    });
    hx += widths[i];
  });
  const rows = [
    ["RPT-1003", "URGENT: Account suspended in 24h…", "94", "PHISHING", "No"],
    ["RPT-1007", "Invoice #4821 – Payment overdue", "87", "PHISHING", "No"],
    ["RPT-1001", "Security alert – new device", "71", "PHISHING", "Yes"],
    ["RPT-1005", "Your monthly statement is ready", "12", "SAFE", "No"],
    ["RPT-1002", "Meeting reminder – Project sync", "08", "SAFE", "No"],
  ];
  rows.forEach((r, i) => {
    const y = 2.1 + i * 0.75;
    slide.addShape(pres.shapes.RECTANGLE, {
      x: MARGIN_L, y: y, w: 12.2, h: 0.7,
      fill: { color: i % 2 === 0 ? "141C19" : "121A17" }, line: { width: 0 },
    });
    let x = MARGIN_L + 0.2;
    r.forEach((cell, j) => {
      const col = j === 2 ? (parseInt(cell) >= 70 ? RED : GREEN) : INK;
      slide.addText(cell, {
        x: x, y: y + 0.15, w: widths[j], h: 0.4,
        fontFace: FONT_BODY, fontSize: 14, color: col, margin: 0,
      });
      x += widths[j];
    });
  });
}

// SLIDE 8 – Architecture
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "ARCHITECTURE", 8);
  slide.addText("Enterprise-grade, Microsoft-ready stack", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  const layers = [
    { title: "Ingestion", items: "Microsoft Graph • Outlook Report button • .eml upload • REST API" },
    { title: "Core Engine", items: "Python • scikit-learn (RF) • TF-IDF • Rule-based red-flag engine" },
    { title: "Decision", items: "Risk score 0-100 • Confidence gate • Human queue" },
    { title: "Surface", items: "Streamlit SOC dashboard • Ranked queue • Analyst feedback" },
    { title: "Scale Path", items: "Azure Functions • Cosmos DB • Microsoft Sentinel • Teams alerts" },
  ];
  layers.forEach((l, i) => {
    const y = 1.5 + i * 1.0;
    slide.addText(l.title, {
      x: MARGIN_L, y: y, w: 2.8, h: 0.7,
      fontFace: FONT_MONO, fontSize: 15, color: GREEN, bold: true, margin: 0,
    });
    slide.addText(l.items, {
      x: MARGIN_L + 3.0, y: y, w: 9, h: 0.7,
      fontFace: FONT_BODY, fontSize: 15, color: INK, margin: 0,
    });
  });
}

// SLIDE 9 – Why We Win
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "WHY WE WIN", 9);
  slide.addText("Beyond the brief", {
    x: MARGIN_L, y: 0.9, w: 12, h: 0.4,
    fontFace: FONT_SERIF, fontSize: 22, color: INK, italic: true, margin: 0,
  });
  const wins = [
    { num: "01", title: "Explainable by design", desc: "Every verdict ships with concrete red flags, not a black-box score." },
    { num: "02", title: "Human-in-the-loop", desc: "Low-confidence cases never auto-decide — analysts stay in control." },
    { num: "03", title: "Risk-ranked queue", desc: "Highest threat first. Analyst time is spent where it matters." },
    { num: "04", title: "Microsoft-native path", desc: "Graph, Defender, Sentinel, Teams — ready for bank production." },
    { num: "05", title: "Measurable", desc: "Precision, recall and F1 reported on every model release." },
    { num: "06", title: "Working prototype", desc: "Live Streamlit SOC dashboard + trained model + sample queue." },
  ];
  wins.forEach((w, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = MARGIN_L + col * 6.3;
    const y = 1.5 + row * 1.7;
    slide.addText(w.num, {
      x: x, y: y, w: 0.8, h: 0.4,
      fontFace: FONT_MONO, fontSize: 18, color: GREEN, bold: true, margin: 0,
    });
    slide.addText(w.title, {
      x: x + 0.9, y: y, w: 5, h: 0.4,
      fontFace: FONT_BODY, fontSize: 16, color: INK, bold: true, margin: 0,
    });
    slide.addText(w.desc, {
      x: x + 0.9, y: y + 0.5, w: 5, h: 0.8,
      fontFace: FONT_BODY, fontSize: 14, color: INK_DIM, margin: 0,
    });
  });
}

// SLIDE 10 – Demo CTA
{
  const slide = pres.addSlide();
  slide.background = { color: BG };
  addCornerMarks(slide);
  addTopBar(slide, "DEMO & NEXT", 10);
  slide.addText("Live prototype ready", {
    x: MARGIN_L, y: 1.5, w: 12, h: 0.5,
    fontFace: FONT_SERIF, fontSize: 28, color: INK, italic: true, margin: 0,
  });
  slide.addText("streamlit run app.py", {
    x: MARGIN_L, y: 2.3, w: 12, h: 0.5,
    fontFace: FONT_MONO, fontSize: 22, color: GREEN, margin: 0,
  });
  slide.addText("Analyze any email → see risk score, red flags, confidence, and human-queue decision in real time.", {
    x: MARGIN_L, y: 3.1, w: 11, h: 0.6,
    fontFace: FONT_BODY, fontSize: 16, color: INK_DIM, margin: 0,
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: MARGIN_L, y: 4.2, w: 4.5, h: 1.5,
    fill: { color: "141C19" }, line: { color: GREEN, width: 1.5 },
  });
  slide.addText("ASK US FOR", {
    x: MARGIN_L + 0.3, y: 4.4, w: 4, h: 0.3,
    fontFace: FONT_MONO, fontSize: 12, color: GREEN, margin: 0,
  });
  slide.addText("Live demo\nArchitecture deep-dive\nRoadmap to production", {
    x: MARGIN_L + 0.3, y: 4.8, w: 4, h: 0.8,
    fontFace: FONT_BODY, fontSize: 15, color: INK, margin: 0,
  });
  slide.addText("PhishGuard  ·  Protect the inbox. Free the analysts.", {
    x: MARGIN_L, y: 6.3, w: 12, h: 0.4,
    fontFace: FONT_BODY, fontSize: 16, color: INK_DIM, margin: 0,
  });
}

pres.writeFile({ fileName: "/home/workdir/artifacts/phishing-triage/PhishGuard_Pitch_Deck.pptx" })
  .then((name) => console.log("Wrote:", name))
  .catch((e) => console.error(e));
