import type { ReactNode, SVGProps } from "react";

/** Additional line icons in the same style as icons.tsx (24px grid, 1.5 stroke, currentColor). */

type IconProps = Omit<SVGProps<SVGSVGElement>, "children"> & { size?: number };

function Icon({ size = 16, className, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...rest}
    >
      {children}
    </svg>
  );
}

/** Git branch: two commits on a line with a branch off it. */
export function GitBranchIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="6.5" cy="5.5" r="2" />
      <circle cx="6.5" cy="18.5" r="2" />
      <circle cx="17.5" cy="7.5" r="2" />
      <path d="M6.5 7.5v9M17.5 9.5c0 4-4.5 3.5-9.6 7.6" />
    </Icon>
  );
}

/** Circular arrow: loop back / resubmit. */
export function LoopIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M19.5 12a7.5 7.5 0 11-2.2-5.3" />
      <path d="M19.8 4.5v3.8H16" />
    </Icon>
  );
}

/** Application window with a small layout. */
export function AppIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" />
      <path d="M3.5 8.5h17M8 12.5h8M8 15.5h5" />
    </Icon>
  );
}

/** Agent skill: a document with a folded corner and a small spark-free "tool" mark. */
export function SkillIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M14 3.5H6.5v17h11V7L14 3.5z" />
      <path d="M14 3.5V7h3.5" />
      <path d="M9.5 12.5l1.8 1.8 3.2-3.3" />
      <path d="M9.5 17h5" />
    </Icon>
  );
}

/** Person with a check mark: reviewer sign-off. */
export function ReviewerIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="10" cy="8" r="3.5" />
      <path d="M3.5 19.5c.7-3.4 3.3-5.5 6.5-5.5 1.3 0 2.5.3 3.5.9" />
      <path d="M15 18l2 2 3.5-3.8" />
    </Icon>
  );
}

/** Catalogue: a grid of tiles. */
export function CatalogueIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <rect x="4" y="4" width="7" height="7" rx="1.5" />
      <rect x="13" y="4" width="7" height="7" rx="1.5" />
      <rect x="4" y="13" width="7" height="7" rx="1.5" />
      <rect x="13" y="13" width="7" height="7" rx="1.5" />
    </Icon>
  );
}

/** Play triangle in a circle: try the demo. */
export function PlayIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M10.2 8.8v6.4l5-3.2-5-3.2z" />
    </Icon>
  );
}
