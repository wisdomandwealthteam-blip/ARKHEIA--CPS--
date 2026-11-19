/**
 * frontend/config.js
 * ====================
 * Resolves the ClearCheck API base URL. Resolution order:
 *
 *   1. `?api=<url>` query parameter — persisted to localStorage so it
 *      survives the Stripe checkout redirect round-trip.
 *   2. A previously persisted localStorage override.
 *   3. localhost / 127.0.0.1 → the local uvicorn dev server.
 *   4. Anything else (the deployed Netlify site) → the Render backend.
 *
 * The deployed backend must list the frontend origin in its
 * CPS_ALLOWED_ORIGINS environment variable (see 02_render-1.yaml).
 */
(function () {
  "use strict";

  var LOCAL_API = "http://localhost:8000";
  var DEPLOYED_API = "https://arkheia-cps-10.onrender.com";
  var STORAGE_KEY = "arkheia_api_base";

  function sanitize(url) {
    return String(url).trim().replace(/\/+$/, "");
  }

  function resolveApiBase() {
    try {
      var params = new URLSearchParams(window.location.search);
      var override = params.get("api");
      if (override) {
        override = sanitize(override);
        if (/^https?:\/\//.test(override)) {
          localStorage.setItem(STORAGE_KEY, override);
          return override;
        }
      }
      var stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return sanitize(stored);
      }
    } catch (e) {
      /* localStorage unavailable (private mode) — fall through */
    }
    var host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "") {
      return LOCAL_API;
    }
    return DEPLOYED_API;
  }

  window.ARKHEIA_CONFIG = {
    apiBase: resolveApiBase(),
    clearApiOverride: function () {
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch (e) {
        /* ignore */
      }
    },
  };
})();
