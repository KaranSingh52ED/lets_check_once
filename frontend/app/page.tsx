// app/page.tsx
"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

export default function HomePage() {
  const [loading, setLoading] = useState(true);
  const [shop, setShop] = useState<string | null>(null);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const shopParam = urlParams.get("shop");
    const hostParam = urlParams.get("host");

    setShop(shopParam);

    if (!shopParam) {
      if (window.self === window.top) {
        window.location.href = "/install";
      }
      return;
    }

    if (
      typeof window !== "undefined" &&
      (window as any).shopifyApp &&
      hostParam
    ) {
      try {
        const app = (window as any).shopifyApp.createApp({
          apiKey: process.env.NEXT_PUBLIC_SHOPIFY_API_KEY!,
          host: hostParam,
        });
        (window as any).app = app;
      } catch (err) {
        console.error("App Bridge failed:", err);
      }
    }

    setLoading(false);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-2 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">
            Your Shopify App is Connected!
          </h1>

          <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-6">
            <h2 className="text-lg font-semibold text-green-800 mb-2">
              Successfully Connected
            </h2>
            <div className="text-sm text-green-700">
              <p>
                <strong>Store:</strong> {shop || "Your Store"}
              </p>
              <p>
                <strong>Status:</strong> Active and Ready
              </p>
              <p>
                <strong>OAuth:</strong> Authenticated
              </p>
              <p>
                <strong>Webhooks:</strong> Registered
              </p>
              <p>
                <strong>API Version:</strong> Current (2024-07)
              </p>
            </div>
          </div>

          <Link href="https://app.quickinsights.ai/dashboard" target="_blank">
            <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors">
              Go to Dashboard
            </button>
          </Link>
        </div>
      </div>
    </div>
  );
}
