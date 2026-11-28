import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "TomOS POS · Business management", description: "Self-hosted point of sale and business management." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en-GB"><body>{children}</body></html>; }
