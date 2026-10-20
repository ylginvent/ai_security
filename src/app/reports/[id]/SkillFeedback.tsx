import { Card, CardHeader } from "@/components/Card";
import { AlertIcon, CheckCircleIcon, FileIcon } from "@/components/icons";
import { SkillIcon } from "@/components/icons-extra";
import { StatusPill } from "@/components/StatusPill";
import type { SkillCheck, SkillReview } from "@/lib/types";

/** Skill feedback: one block per reviewed SKILL.md, checks grouped by category with failures first. Server component. */

const CATEGORIES: { id: SkillCheck["category"]; label: string; intro: string }[] = [
  { id: "structure", label: "Structure", intro: "Does the skill follow the Agent Skills format?" },
  { id: "quality", label: "Quality", intro: "Will an agent understand when and how to use it?" },
  { id: "security", label: "Security", intro: "Could the skill or its scripts cause harm?" },
];

function tone(score: number): { stroke: string; text: string; label: string } {
  if (score >= 75) return { stroke: "#12B76A", text: "text-ok", label: "Good" };
  if (score >= 50) return { stroke: "#F79009", text: "text-warn", label: "Needs work" };
  return { stroke: "#F04438", text: "text-sev-critical", label: "Poor" };
}

function SkillScore({ score }: { score: number }) {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  const t = tone(s);
  const size = 84;
  const stroke = 7;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="flex shrink-0 flex-col items-center gap-1.5">
      <div className="relative" style={{ width: size, height: size }} role="img" aria-label={`Skill score ${s} out of 100: ${t.label}`}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#EAECF0" strokeWidth={stroke} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={t.stroke}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${(c * s) / 100} ${c}`}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`tabular font-display text-2xl font-bold leading-none ${t.text}`}>{s}</span>
          <span className="mt-0.5 text-[11px] text-subtle">of 100</span>
        </div>
      </div>
      <span className="text-xs font-medium text-subtle">Skill score</span>
    </div>
  );
}

function CheckRow({ check }: { check: SkillCheck }) {
  const failIcon = check.category === "security" ? "text-sev-critical" : "text-warn";
  return (
    <li className="flex gap-3 px-4 py-3.5 sm:px-5">
      {check.passed ? (
        <CheckCircleIcon size={20} className="mt-px shrink-0 text-ok" />
      ) : (
        <AlertIcon size={20} className={`mt-px shrink-0 ${failIcon}`} />
      )}
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium leading-5 text-ink">
          <span className="sr-only">{check.passed ? "Passed: " : "To improve: "}</span>
          {check.label}
        </p>
        {check.detail && <p className="mt-0.5 whitespace-pre-line break-words text-[13px] leading-5 text-muted">{check.detail}</p>}
        {!check.passed && check.suggestion && (
          <div className="mt-2.5 rounded-lg border border-brand/15 bg-tint px-3.5 py-2.5">
            <p className="text-[13px] font-semibold text-brand-strong">Suggestion</p>
            <p className="mt-0.5 whitespace-pre-line break-words text-[13px] leading-5 text-ink-2">{check.suggestion}</p>
          </div>
        )}
      </div>
    </li>
  );
}

function SkillBlock({ skill, index }: { skill: SkillReview; index: number }) {
  const checks = Array.isArray(skill.checks) ? skill.checks : [];
  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.length - passed;
  const folder = skill.path ? skill.path : "Top-level folder of the upload";
  const title = skill.name?.trim() || (skill.path ? skill.path.split("/").filter(Boolean).pop() : null) || "Unnamed skill";
  const scripts = Array.isArray(skill.scripts) ? skill.scripts : [];
  const headingId = `skill-${index}-title`;

  return (
    <article aria-labelledby={headingId} className="avoid-break px-5 py-6 sm:px-6">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-start">
        <SkillScore score={skill.score} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id={headingId} className="break-words text-lg font-bold text-ink">
              {title}
            </h3>
            <StatusPill tone={failed === 0 ? "ok" : "warn"}>
              {passed} of {checks.length} checks passed
            </StatusPill>
          </div>
          <p className="mt-1 flex min-w-0 items-center gap-1.5 text-[13px] text-subtle">
            <FileIcon size={14} className="shrink-0" />
            <span className={`truncate ${skill.path ? "font-mono text-xs" : ""}`} title={folder}>
              {folder}
            </span>
          </p>
          {skill.description ? (
            <p className="mt-2 line-clamp-2 max-w-3xl text-sm leading-6 text-muted print:line-clamp-none" title={skill.description}>
              {skill.description}
            </p>
          ) : (
            <p className="mt-2 text-sm text-faint">No description found in SKILL.md.</p>
          )}
          {skill.summary && <p className="mt-3 max-w-3xl text-[15px] leading-6 text-ink-2">{skill.summary}</p>}
          <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-subtle">
            <div className="flex gap-1">
              <dt>Files</dt>
              <dd className="tabular font-medium text-ink-2">{skill.files}</dd>
            </div>
            <div className="flex gap-1">
              <dt>SKILL.md lines</dt>
              <dd className="tabular font-medium text-ink-2">{skill.lines}</dd>
            </div>
            <div className="flex min-w-0 gap-1">
              <dt>Scripts</dt>
              <dd className="min-w-0 font-medium text-ink-2">
                {scripts.length === 0 ? (
                  "None"
                ) : (
                  <span className="break-all font-mono text-xs">
                    {scripts.slice(0, 3).join(", ")}
                    {scripts.length > 3 ? ` +${scripts.length - 3} more` : ""}
                  </span>
                )}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      {checks.length > 0 && (
        <div className="mt-6 space-y-4">
          {CATEGORIES.map((cat) => {
            const list = checks.filter((c) => c.category === cat.id).sort((a, b) => Number(a.passed) - Number(b.passed));
            if (list.length === 0) return null;
            const catFailed = list.filter((c) => !c.passed).length;
            const catId = `${headingId}-${cat.id}`;
            return (
              <section key={cat.id} aria-labelledby={catId} className="overflow-hidden rounded-xl border border-line">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-2 px-4 py-2.5 sm:px-5">
                  <div className="min-w-0">
                    <h4 id={catId} className="font-display text-sm font-bold text-ink">
                      {cat.label}
                    </h4>
                    <p className="text-xs text-subtle">{cat.intro}</p>
                  </div>
                  <StatusPill tone={catFailed === 0 ? "ok" : cat.id === "security" ? "danger" : "warn"}>
                    {catFailed === 0 ? "All passed" : `${catFailed} to improve`}
                  </StatusPill>
                </div>
                <ul className="divide-y divide-line bg-white">
                  {list.map((c, i) => (
                    <CheckRow key={`${c.id}-${i}`} check={c} />
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      )}
    </article>
  );
}

export default function SkillFeedback({ skills }: { skills: SkillReview[] }) {
  const many = skills.length > 1;
  return (
    <Card id="skill-feedback" labelledBy="skill-feedback-title" className="scroll-mt-24">
      <CardHeader
        id="skill-feedback-title"
        title={
          <>
            <SkillIcon size={20} className="text-brand" />
            Skill feedback
          </>
        }
        meta={many ? skills.length : undefined}
        description={
          many
            ? "We found several SKILL.md files and reviewed each one against the Agent Skills format and best practices."
            : "We reviewed the skill against the Agent Skills format and best practices. Start with the suggestions at the top of each group."
        }
      />
      <div className="divide-y divide-line">
        {skills.map((s, i) => (
          <SkillBlock key={`${s.path}-${i}`} skill={s} index={i} />
        ))}
      </div>
    </Card>
  );
}
