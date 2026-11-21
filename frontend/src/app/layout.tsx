import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "VULNEX AI | AI Builds Software. VULNEX Proves It Is Safe.",
  description:
    "AI-powered application security platform designed to analyze AI-generated applications, understand their security context, suggest secure repairs, and independently verify them.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`dark ${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-graphite-950 text-white min-h-screen antialiased selection:bg-cyan-500/30 selection:text-cyan-neon font-sans">
        {children}
      </body>
    </html>
  );
}
