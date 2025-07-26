// app/layout.tsx
import "./globals.css";
import type { Metadata } from "next";
import Script from "next/script";

export const metadata: Metadata = {
  title: "Shopify App",
  description: "A compliant Shopify public app",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Script
          src="https://unpkg.com/@shopify/app-bridge@4"
          strategy="beforeInteractive"
        />
        {children}
      </body>
    </html>
  );
}
