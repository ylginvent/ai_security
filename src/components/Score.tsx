import { PASS_SCORE } from "@/lib/scoring";

function tone(score: number): { stroke: string; bar: string; text: string } {
  if (score >= PASS_SCORE) return { stroke: "#12B76A", bar: "bg-[#12B76A]", text: "text-ok" };
  if (score >= 50) return { stroke: "#F79009", bar: "bg-[#F79009]", text: "text-warn" };
  return { stroke: "#F04438", bar: "bg-[#F04438]", text: "text-sev-critical" };
}

/** Trust score as a number with a thin bar; used in tables. */
export function ScoreBar({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-faint">—</span>;
  const t = tone(score);
  return (
    <span className="inline-flex items-center gap-2" title={`Trust score ${score} of 100`}>
      <span className="tabular w-7 text-right text-sm font-semibold text-ink">{score}</span>
      <span className="relative h-2 w-20 overflow-hidden rounded-full bg-line" aria-hidden="true">
        <span className={`absolute inset-y-0 left-0 rounded-full ${t.bar}`} style={{ width: `${Math.max(2, Math.min(100, score))}%` }} />
        <span className="absolute inset-y-0 w-px bg-white" style={{ left: `${PASS_SCORE}%` }} />
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
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Trust score ${score} out of 100, ${score >= PASS_SCORE ? "passes" : "below"} the ${PASS_SCORE} needed`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#EAECF0" strokeWidth={stroke} />
        <circle
          cx={cx}
          cy={cx}
          r={r}
          fill="none"
          stroke={t.stroke}
          strokeWidth={stroke}
          strokeLinecap="round"
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
        <span className={`tabular font-display text-[30px] font-bold leading-none ${t.text}`}>{score}</span>
        <span className="mt-1 text-xs text-subtle">of 100</span>
      </div>
    </div>
  );
}
