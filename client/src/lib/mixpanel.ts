import mixpanel from "mixpanel-browser";

const token =
  (import.meta.env.VITE_MIXPANEL_TOKEN as string | undefined) ||
  (import.meta.env.VITE_MIXPANEL_PROJECT_TOKEN as string | undefined) ||
  "";

let initialized = false;

function ensureInit() {
  if (typeof window === "undefined" || initialized || !token) return;
  mixpanel.init(token, {
    debug: import.meta.env.MODE !== "production",
    track_pageview: false,
    persistence: "localStorage",
    ignore_dnt: true,
  });
  initialized = true;
}

ensureInit();

export const mp = mixpanel;

export function identifyUser(userId: string, traits: Record<string, unknown>) {
  ensureInit();
  if (!token) return;
  mixpanel.identify(userId);
  mixpanel.people.set(traits);
}

export function trackEvent(event: string, props: Record<string, unknown> = {}) {
  ensureInit();
  if (!token) return;
  mixpanel.track(event, {
    ...props,
    $insert_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
  });
}

export function resetMixpanel() {
  ensureInit();
  if (!token) return;
  mixpanel.reset();
}

/** Map app routes to dashboard analytics sections */
export function sectionFromPath(path: string): string {
  if (path === "/" || path.startsWith("/?")) return "overview";
  if (path.startsWith("/ai-assets")) return "assets";
  if (path.startsWith("/vulnerabilities") || path.startsWith("/threat-config")) return "risks";
  if (path.startsWith("/compliance") || path.startsWith("/health-governance")) return "policies";
  if (path.startsWith("/monitoring") || path.startsWith("/system-monitoring") || path.startsWith("/prompt-checks")) {
    return "alerts";
  }
  if (path.startsWith("/agentic")) return "reports";
  if (path.startsWith("/settings") || path.startsWith("/users")) return "settings";
  return "overview";
}
