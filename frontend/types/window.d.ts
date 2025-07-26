// types/window.d.ts
interface ShopifyAppBridge {
  createApp(options: { apiKey: string; host: string }): any;
}

interface Window {
  shopifyApp?: ShopifyAppBridge;
  app?: any;
}
