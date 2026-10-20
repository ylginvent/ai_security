import type { Metadata } from "next";
import SubmitWizard from "./SubmitWizard";

export const metadata: Metadata = { title: "New submission" };

export default function SubmitPage() {
  return <SubmitWizard />;
}
