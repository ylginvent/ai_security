"use client";

import { btn } from "@/components/Card";
import { PrinterIcon } from "@/components/icons";

export default function PrintButton() {
  return (
    <button type="button" onClick={() => window.print()} className={btn.secondary}>
      <PrinterIcon size={16} />
      Print / Save as PDF
    </button>
  );
}
