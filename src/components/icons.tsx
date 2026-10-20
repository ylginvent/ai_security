import type { ReactNode, SVGProps } from "react";

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

export function CheckIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M5 12.5l4.5 4.5L19 7.5" />
    </Icon>
  );
}

export function CheckCircleIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.2 12.3l2.6 2.6 5-5.3" />
    </Icon>
  );
}

export function XCircleIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6" />
    </Icon>
  );
}

export function XIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Icon>
  );
}

export function AlertIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M12 3.8L2.8 19.5h18.4L12 3.8z" />
      <path d="M12 10v4.2M12 16.9v.1" />
    </Icon>
  );
}

export function InfoIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5M12 7.8v.1" />
    </Icon>
  );
}

export function ChevronRightIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M9.5 6l6 6-6 6" />
    </Icon>
  );
}

export function ChevronDownIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M6 9.5l6 6 6-6" />
    </Icon>
  );
}

export function ArrowLeftIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M19 12H5M11 6l-6 6 6 6" />
    </Icon>
  );
}

export function ArrowRightIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </Icon>
  );
}

export function DownloadIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 19.5h14" />
    </Icon>
  );
}

export function UploadIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M12 15.5V4.5M7.5 9L12 4.5 16.5 9M5 15v4.5h14V15" />
    </Icon>
  );
}

export function PrinterIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M7 8V3.5h10V8M7 17H4.5V9.5a1.5 1.5 0 011.5-1.5h12a1.5 1.5 0 011.5 1.5V17H17" />
      <path d="M7 13.5h10v7H7z" />
    </Icon>
  );
}

export function FileIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M14 3.5H6.5v17h11V7L14 3.5z" />
      <path d="M14 3.5V7h3.5" />
    </Icon>
  );
}

export function ArchiveIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M3.5 4.5h17v4h-17zM5 8.5v11h14v-11" />
      <path d="M10 12h4" />
    </Icon>
  );
}

export function SearchIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <circle cx="10.5" cy="10.5" r="6" />
      <path d="M15 15l5 5" />
    </Icon>
  );
}

export function ExternalLinkIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M13.5 4.5h6v6M19.5 4.5L11 13M18 14v5.5H4.5V6H10" />
    </Icon>
  );
}

export function ShieldIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6L12 3z" />
    </Icon>
  );
}

export function PlusIcon(p: IconProps) {
  return (
    <Icon {...p}>
      <path d="M12 5v14M5 12h14" />
    </Icon>
  );
}

export function SpinnerIcon({ className, ...p }: IconProps) {
  return (
    <Icon {...p} className={`animate-spin ${className ?? ""}`}>
      <circle cx="12" cy="12" r="8.5" opacity="0.2" />
      <path d="M20.5 12A8.5 8.5 0 0012 3.5" />
    </Icon>
  );
}

/** Product mark: a stylised gate (two posts and a bar). */
export function GateMark({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" className={className}>
      <rect width="24" height="24" rx="3" fill="#0070AD" />
      <path d="M7 18V7M17 18V7M7 10.5h10" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <path d="M10 14.5h4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" opacity="0.6" />
    </svg>
  );
}
