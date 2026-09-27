import { useMemo, useState, type ReactNode } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle2,
  UserRoundSearch,
  ScanSearch,
  ChevronRight,
  Upload,
} from "lucide-react";
import { analyzeEmailLocal, SAMPLE_REPORTS, type AnalyzeOutput } from "@/lib/phishguard/orchestrator";
import { cn } from "@/lib/cn";

type QueueItem = AnalyzeOutput & {
  subject: string;
  sender: string;
};

function seedQueue(): QueueItem[] {
  return SAMPLE_REPORTS.map((s) => {
    const r = analyzeEmailLocal(s);
    return { ...r, id: s.seedId, subject: s.subject, sender: s.sender };
  }).sort((a, b) => b.risk - a.risk || Number(b.needsHuman) - Number(a.needsHuman));
}

export function SocConsole() {
  const [subject, setSubject] = useState(SAMPLE_REPORTS[0].subject);
  const [sender, setSender] = useState(SAMPLE_REPORTS[0].sender);
  const [headers, setHeaders] = useState(SAMPLE_REPORTS[0].headers);
  const [body, setBody] = useState(SAMPLE_REPORTS[0].body);
  const [queue, setQueue] = useState<QueueItem[]>(() => seedQueue());
  const [active, setActive] = useState<QueueItem | null>(null);
  const [busy, setBusy] = useState(false);

  const stats = useMemo(() => {
    const high = queue.filter((q) => q.risk >= 70).length;
    const human = queue.filter((q) => q.needsHuman).length;
    const phish = queue.filter((q) => q.label === "phishing").length;
    return { high, human, phish, total: queue.length };
  }, [queue]);

  function runAnalyze() {
    setBusy(true);
    window.setTimeout(() => {
      const result = analyzeEmailLocal({ subject, body, sender, headers });
      const item: QueueItem = { ...result, subject, sender };
      setQueue((prev) => [item, ...prev].sort((a, b) => b.risk - a.risk));
      setActive(item);
      setBusy(false);
    }, 280);
  }

  function loadSample(idx: number) {
    const s = SAMPLE_REPORTS[idx];
    setSubject(s.subject);
    setSender(s.sender);
    setHeaders(s.headers);
    setBody(s.body);
  }

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3 sm:px-5">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-sm bg-elevated text-crimson">
            <Shield className="size-4" strokeWidth={1.75} />
          </span>
          <div>
            <div className="font-mono text-[11px] tracking-[0.18em] text-muted">CONTOSO BANK · SOC</div>
            <h1 className="text-[15px] font-semibold leading-tight">Byte Me</h1>
          </div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2 font-mono text-[11px]">
          <Kpi label="QUEUE" value={String(stats.total)} />
          <Kpi label="PHISH" value={String(stats.phish)} tone="crimson" />
          <Kpi label="HIGH" value={String(stats.high)} tone="amber" />
          <Kpi label="HUMAN" value={String(stats.human)} tone="human" />
          <span className="hidden items-center gap-1 rounded-sm border border-border px-2 py-1 text-safe sm:flex">
            <Activity className="size-3" /> RULES-FIRST · MOCK LLM
          </span>
        </div>
      </header>

      <div className="grid min-h-[calc(100dvh-57px)] grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)_minmax(280px,0.9fr)]">
        <section className="flex min-h-0 flex-col border-b border-border lg:border-b-0 lg:border-r">
          <SectionTitle icon={<ScanSearch className="size-3.5" />} title="Ingest" hint="Paste four fields. Judges demo path." />
          <div className="flex flex-wrap gap-1.5 px-4 pb-2">
            {["Phish kit", "Invoice lure", "Lookalike", "Injection + PII", "Legit statement", "Internal mail"].map(
              (label, i) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => loadSample(i)}
                  className="rounded-sm border border-border bg-elevated px-2 py-1 text-[11px] text-muted hover:border-border-strong hover:text-fg"
                >
                  {label}
                </button>
              ),
            )}
          </div>
          <div className="flex flex-1 flex-col gap-2 overflow-auto px-4 pb-4">
            <Field label="From address" value={sender} onChange={setSender} />
            <Field label="Subject" value={subject} onChange={setSubject} />
            <Field label="Raw email headers" value={headers} onChange={setHeaders} rows={4} mono />
            <Field label="Body" value={body} onChange={setBody} rows={8} />
            <button
              type="button"
              onClick={runAnalyze}
              disabled={busy}
              className="mt-1 flex h-11 items-center justify-center gap-2 rounded-sm bg-accent text-sm font-semibold text-bg hover:opacity-90 disabled:opacity-50"
            >
              <Upload className="size-4" />
              {busy ? "Scoring…" : "Analyze report"}
            </button>
          </div>
        </section>

        <section className="flex min-h-0 flex-col border-b border-border lg:border-b-0 lg:border-r">
          <SectionTitle icon={<AlertTriangle className="size-3.5" />} title="Risk queue" hint="Highest risk first · human rows highlighted" />
          <div className="min-h-0 flex-1 overflow-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-surface font-mono text-[10px] uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">ID</th>
                  <th className="px-3 py-2 font-medium">Subject</th>
                  <th className="px-3 py-2 font-medium">Risk</th>
                  <th className="px-3 py-2 font-medium">Gate</th>
                </tr>
              </thead>
              <tbody>
                {queue.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setActive(row)}
                    className={cn(
                      "cursor-pointer border-t border-border hover:bg-elevated",
                      active?.id === row.id && "bg-elevated",
                      row.needsHuman && "bg-elevated/60",
                    )}
                  >
                    <td className="px-3 py-2.5 font-mono text-muted">{row.id}</td>
                    <td className="max-w-[220px] truncate px-3 py-2.5">{row.subject}</td>
                    <td className="px-3 py-2.5">
                      <RiskPill risk={row.risk} />
                    </td>
                    <td className="px-3 py-2.5">
                      {row.needsHuman ? (
                        <span className="font-mono text-[10px] text-human">HUMAN</span>
                      ) : row.label === "phishing" ? (
                        <span className="font-mono text-[10px] text-crimson">AUTO PHISH</span>
                      ) : (
                        <span className="font-mono text-[10px] text-safe">AUTO SAFE</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="flex min-h-0 flex-col bg-panel">
          <SectionTitle
            icon={<UserRoundSearch className="size-3.5" />}
            title="Investigation"
            hint="Grounded AI summary · no invented IOCs"
          />
          {active ? <Investigation item={active} /> : <EmptyInvestigate />}
        </aside>
      </div>
    </div>
  );
}

function SectionTitle({ icon, title, hint }: { icon: ReactNode; title: string; hint: string }) {
  return (
    <div className="flex items-start justify-between gap-2 px-4 py-3">
      <div>
        <div className="flex items-center gap-2 text-[13px] font-semibold">
          <span className="text-muted">{icon}</span>
          {title}
        </div>
        <p className="mt-0.5 text-[11px] text-subtle">{hint}</p>
      </div>
    </div>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: "crimson" | "amber" | "human" }) {
  const color =
    tone === "crimson" ? "text-crimson" : tone === "amber" ? "text-amber" : tone === "human" ? "text-human" : "text-fg";
  return (
    <span className="rounded-sm border border-border bg-surface px-2 py-1">
      <span className="text-subtle">{label}</span>{" "}
      <span className={cn("tabular-nums", color)}>{value}</span>
    </span>
  );
}

function Field({
  label,
  value,
  onChange,
  rows,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  mono?: boolean;
}) {
  const cls =
    "w-full rounded-sm border border-border bg-bg px-3 py-2 text-[13px] text-fg outline-none ring-0 placeholder:text-subtle focus:border-border-strong";
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-[10px] uppercase tracking-wider text-muted">{label}</span>
      {rows ? (
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          rows={rows}
          className={cn(cls, "resize-y min-h-20", mono && "font-mono text-[12px]")}
        />
      ) : (
        <input value={value} onChange={(e) => onChange(e.target.value)} className={cn(cls, "h-10")} />
      )}
    </label>
  );
}

function RiskPill({ risk }: { risk: number }) {
  const tone = risk >= 70 ? "text-crimson" : risk >= 40 ? "text-amber" : "text-safe";
  return <span className={cn("font-mono tabular-nums", tone)}>{risk}</span>;
}

function EmptyInvestigate() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6 pb-10 text-center">
      <ChevronRight className="size-5 text-subtle" />
      <p className="text-sm text-muted">Select a queue row or run Analyze.</p>
    </div>
  );
}

function Investigation({ item }: { item: QueueItem }) {
  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-auto px-4 pb-6">
      <div className="rounded-md border border-border bg-elevated p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="font-mono text-[11px] text-muted">{item.id}</div>
          {item.needsHuman ? (
            <span className="rounded-sm bg-human/15 px-2 py-0.5 font-mono text-[10px] text-human">HUMAN REVIEW</span>
          ) : item.label === "phishing" ? (
            <span className="flex items-center gap-1 font-mono text-[10px] text-crimson">
              <AlertTriangle className="size-3" /> AUTO PHISHING
            </span>
          ) : (
            <span className="flex items-center gap-1 font-mono text-[10px] text-safe">
              <CheckCircle2 className="size-3" /> AUTO SAFE
            </span>
          )}
        </div>
        <div className="mt-3 flex items-end justify-between">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-wider text-subtle">Risk</div>
            <div
              className={cn(
                "font-mono text-4xl tabular-nums leading-none",
                item.risk >= 70 ? "text-crimson" : item.risk >= 40 ? "text-amber" : "text-safe",
              )}
            >
              {item.risk}
            </div>
          </div>
          <div className="text-right font-mono text-[11px] text-muted">
            conf {(item.confidence * 100).toFixed(0)}%
            <div className="text-subtle">{item.mode}</div>
          </div>
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-bg">
          <div
            className={cn(
              "h-full",
              item.risk >= 70 ? "bg-crimson" : item.risk >= 40 ? "bg-amber" : "bg-safe",
            )}
            style={{ width: `${item.risk}%` }}
          />
        </div>
      </div>

      <div>
        <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted">Recommended response</div>
        <p className="rounded-sm border border-border bg-bg px-3 py-2 text-[12px] text-muted">{item.recommendedResponse}</p>
      </div>

      <div>
        <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted">Red flags</div>
        {item.redFlags.length === 0 ? (
          <p className="text-[13px] text-muted">None extracted.</p>
        ) : (
          <ul className="space-y-2">
            {item.redFlags.map((f) => (
              <li key={f.id} className="rounded-sm border border-border bg-bg px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] font-medium">{f.title}</span>
                  <span
                    className={cn(
                      "font-mono text-[10px] uppercase",
                      f.severity === "critical" || f.severity === "high"
                        ? "text-crimson"
                        : f.severity === "medium"
                          ? "text-amber"
                          : "text-muted",
                    )}
                  >
                    {f.severity}
                  </span>
                </div>
                <p className="mt-1 text-[12px] text-muted">{f.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted">Investigation summary</div>
        <pre className="whitespace-pre-wrap rounded-sm border border-border bg-bg p-3 font-mono text-[11px] leading-relaxed text-muted">
          {item.explanation}
        </pre>
      </div>

      <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
        <Badge ok={item.responsibleAi.piiMasked} label="PII masked" />
        <Badge ok={item.responsibleAi.injectionBlocked} label="Injection blocked" />
        <Badge ok={item.responsibleAi.grounded} label="Grounded facts" />
        <Badge ok={item.responsibleAi.humanGate} label="Human gate" />
      </div>
    </div>
  );
}

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className={cn("rounded-sm border border-border px-2 py-1.5", ok ? "text-safe" : "text-subtle")}>
      {ok ? "ON" : "—"} {label}
    </div>
  );
}
