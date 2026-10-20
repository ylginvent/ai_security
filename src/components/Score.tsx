import { PASS_SCORE } from "@/lib/scoring";

function tone(score: number): { stroke: string; bar: string; text: string } {
  if (score >= PASS_SCORE) return { stroke: "#067647", bar: "bg-ok", text: "text-ok" };
  if (score >= 50) return { stroke: "#B7791F", bar: "bg-sev-medium", text: "text-sev-medium-ink" };
  return { stroke: "#B42318", bar: "bg-sev-critical", text: "text-sev-critical" };
}

/** Trust score as a number with a thin bar; used in tables. */
export function ScoreBar({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-slate-400">—</span>;
  const t = tone(score);
  return (
    <span className="inline-flex items-center gap-2" title={`Trust score ${score} of 100`}>
      <span className="tabular w-7 text-right text-sm font-semibold text-slate-900">{score}</span>
      <span className="relative h-1.5 w-16 overflow-hidden rounded-full bg-slate-100" aria-hidden="true">
        <span className={`absolute inset-y-0 left-0 rounded-full ${t.bar}`} style={{ width: `${Math.max(2, Math.min(100, score))}%` }} />
        <span className="absolute inset-y-0 w-px bg-slate-400" style={{ left: `${PASS_SCORE}%` }} />
      </span>
    </span>
  );
}

/** Trust score ring for the decision banner. */
export function ScoreRing({ score, size = 104 }: { score: number; size?: number }) {
  const t = tone(score);
  const stroke = 8;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const passAngle = (PASS_SCORE / 100) * 2 * Math.PI - Math.PI / 2;
  const cx = size / 2;
  const tickInner = r - stroke / 2 - 1;
  const tickOuter = r + stroke / 2 + 1;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Trust score ${score} out of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#E2E8F0" strokeWidth={stroke} />
        <circle
          cx={cx}
          cy={cx}
          r={r}
          fill="none"
          stroke={t.stroke}
          strokeWidth={stroke}
          strokeDasharray={`${c * pct} ${c}`}
          transform={`rotate(-90 ${cx} ${cx})`}
        />
        <line
          x1={cx + tickInner * Math.cos(passAngle)}
          y1={cx + tickInner * Math.sin(passAngle)}
          x2={cx + tickOuter * Math.cos(passAngle)}
          y2={cx + tickOuter * Math.sin(passAngle)}
          stroke="#334155"
          strokeWidth={1.5}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`tabular text-[28px] font-semibold leading-none ${t.text}`}>{score}</span>
        <span className="mt-1 text-[11px] text-slate-500">of 100</span>
      </div>
    </div>
  );
}
