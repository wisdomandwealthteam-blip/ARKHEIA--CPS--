/**
 * frontend/app.js
 * =================
 * ClearCheck consumer UI flow, wired against:
 *
 *   POST {API}/api/clearcheck/preview            — redacted preview + check_id
 *   POST {API}/api/clearcheck/checkout           — Stripe unlock payment URL
 *   GET  {API}/api/clearcheck/report/{check_id}  — 402 until unlocked
 *
 * Masking previews below mirror cps_backend/utils/redaction.py
 * (mask_value / mask_email) so the user sees, locally and before
 * submitting, exactly how the server will render their identifiers.
 */
(function () {
  "use strict";

  var API = window.ARKHEIA_CONFIG.apiBase;
  var CHECK_ID_KEY = "arkheia_last_check_id";

  var state = { checkId: null, unlockRequired: true };
  var reportRequestVersion = 0;

  // IDs are opaque backend keys. Check for blankness, but never normalize them.
  function validCheckId(id) {
    // Match Python str.strip(), whose Unicode whitespace differs from JS trim.
    return typeof id === "string" &&
      /[^\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/.test(id);
  }

  function savedCheckId() {
    try { return localStorage.getItem(CHECK_ID_KEY); } catch (e) { return null; }
  }

  function saveCheckId(id) {
    try {
      localStorage.setItem(CHECK_ID_KEY, id);
      return localStorage.getItem(CHECK_ID_KEY) === id;
    } catch (e) { return false; }
  }

  // ---------------------------------------------------------------
  // Masking mirrors of cps_backend/utils/redaction.py
  // ---------------------------------------------------------------
  function maskValue(value, visibleSuffix) {
    visibleSuffix = visibleSuffix === undefined ? 4 : visibleSuffix;
    if (!value) return "[REDACTED]";
    if (value.length <= visibleSuffix) return "*".repeat(value.length);
    return "*".repeat(value.length - visibleSuffix) + value.slice(-visibleSuffix);
  }

  function maskEmail(email) {
    if (!email) return "[REDACTED]";
    var at = email.indexOf("@");
    if (at <= 0) return "[REDACTED]";
    return email[0] + "***@" + email.slice(at + 1);
  }

  var MASKERS = {
    consumer_name: function (v) { return v ? "[REDACTED]" : ""; },
    consumer_email: function (v) { return v ? maskEmail(v) : ""; },
    ssn_last4: function (v) { return v ? "*".repeat(v.length) : ""; },
    account_number: function (v) { return v ? maskValue(v, 4) : ""; },
  };

  function bindMaskPreview(input, previewEl, masker) {
    function update() {
      var masked = masker(input.value);
      previewEl.textContent = masked ? "Will appear as: " + masked : "";
    }
    input.addEventListener("input", update);
    update();
  }

  // ---------------------------------------------------------------
  // DOM helpers
  // ---------------------------------------------------------------
  function $(id) { return document.getElementById(id); }

  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }

  function setStatus(el, message, kind) {
    el.textContent = message || "";
    el.className = "status" + (kind ? " " + kind : "");
  }

  // ---------------------------------------------------------------
  // Account rows
  // ---------------------------------------------------------------
  var accountsEl = $("accounts");
  var accountTemplate = $("account-template");

  function renumberAccounts() {
    var rows = accountsEl.querySelectorAll("[data-account]");
    rows.forEach(function (row, i) {
      row.querySelector("[data-account-index]").textContent = String(i + 1);
      row.querySelector("[data-remove-account]").disabled = rows.length === 1;
    });
  }

  function addAccount() {
    var node = accountTemplate.content.firstElementChild.cloneNode(true);
    var acctInput = node.querySelector('[data-field="account_number"]');
    var acctPreview = node.querySelector('[data-mask-field="account_number"]');
    bindMaskPreview(acctInput, acctPreview, MASKERS.account_number);
    node.querySelector("[data-remove-account]").addEventListener("click", function () {
      node.remove();
      renumberAccounts();
    });
    accountsEl.appendChild(node);
    renumberAccounts();
  }

  function readAccounts() {
    return Array.prototype.map.call(
      accountsEl.querySelectorAll("[data-account]"),
      function (row) {
        function val(name) {
          return row.querySelector('[data-field="' + name + '"]').value.trim();
        }
        var account = {
          account_number: val("account_number"),
          creditor_name: val("creditor_name"),
          status: val("status"),
          date_opened: val("date_opened"),
          reported_balance: parseFloat(val("reported_balance") || "0"),
          reported_past_due: parseFloat(val("reported_past_due") || "0"),
        };
        if (val("date_closed")) account.date_closed = val("date_closed");
        if (val("date_of_last_activity")) {
          account.date_of_last_activity = val("date_of_last_activity");
        }
        if (val("credit_limit") !== "") {
          account.credit_limit = parseFloat(val("credit_limit"));
        }
        return account;
      }
    );
  }

  // ---------------------------------------------------------------
  // API helpers
  // ---------------------------------------------------------------
  function apiFetch(path, options) {
    return fetch(API + path, options).then(
      function (res) {
        return res.text().then(function (text) {
          var body = null;
          try { body = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON */ }
          return { status: res.status, ok: res.ok, body: body };
        });
      },
      function () {
        throw new Error(
          "Could not reach the API at " + API +
          ". Check that the backend is running and that this origin is " +
          "listed in its CPS_ALLOWED_ORIGINS."
        );
      }
    );
  }

  function errorDetail(result, fallback) {
    // A response may echo submitted identifiers or provider details.
    return fallback + " (HTTP " + result.status + ")";
  }

  // ---------------------------------------------------------------
  // Preview rendering
  // ---------------------------------------------------------------
  function renderJurisMeta(dl, meta) {
    dl.textContent = "";
    Object.keys(meta).forEach(function (key) {
      var dt = document.createElement("dt");
      dt.textContent = key.replace(/_/g, " ");
      var dd = document.createElement("dd");
      var value = meta[key];
      dd.textContent = value === null || value === undefined ? "—" : String(value);
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
  }

  function renderLockState(unlockRequired) {
    state.unlockRequired = unlockRequired;
    if (unlockRequired) {
      show($("lock-locked"));
      hide($("lock-unlocked"));
    } else {
      hide($("lock-locked"));
      show($("lock-unlocked"));
    }
  }

  function renderPreview(data) {
    reportRequestVersion++;
    state.checkId = data.check_id;
    var saved = saveCheckId(data.check_id);
    // Do not leave an old URL recovery reference pointing at a different check.
    var url = new URL(window.location.href);
    if (url.searchParams.has("check_id")) {
      if (saved) url.searchParams.delete("check_id");
      else url.searchParams.set("check_id", data.check_id);
      window.history.replaceState({}, "", url.toString());
    }

    $("p-check-id").textContent = data.check_id;
    $("p-findings-count").textContent = String(data.findings_count);
    $("p-jurisdiction").textContent = data.jurisdiction;

    var summary = $("p-summary");
    summary.textContent = "";
    if (data.redacted_summary.length === 0) {
      var li = document.createElement("li");
      li.className = "clean";
      li.textContent = "No inconsistencies detected in the submitted data.";
      summary.appendChild(li);
    } else {
      data.redacted_summary.forEach(function (line) {
        var item = document.createElement("li");
        item.textContent = line;
        summary.appendChild(item);
      });
    }

    renderJurisMeta($("p-juris-meta"), data.jurisdiction_metadata);
    $("p-notice").textContent = data.notice;
    show($("preview-details"));
    hide($("retry-report-btn"));
    // A report response, not a preview or return URL, verifies an unlock.
    if (data.unlock_required) renderLockState(true);
    else {
      hide($("lock-locked"));
      hide($("lock-unlocked"));
    }
    setStatus($("lock-status"), "");

    hide($("report-card"));
    hide($("redirect-banner"));
    show($("preview-card"));
    $("preview-card").scrollIntoView({ behavior: "smooth", block: "start" });
    if (!data.unlock_required) fetchReport(data.check_id);
  }

  function renderReport(data) {
    $("r-check-id").textContent = data.check_id;
    $("r-findings-count").textContent = String(data.findings_count);
    $("r-jurisdiction").textContent = data.jurisdiction;

    var tbody = $("r-findings");
    tbody.textContent = "";
    if (data.findings.length === 0) {
      hide($("r-findings-table"));
      show($("r-no-findings"));
    } else {
      show($("r-findings-table"));
      hide($("r-no-findings"));
      data.findings.forEach(function (f) {
        var tr = document.createElement("tr");
        [
          { text: f.severity, cls: "sev sev-" + f.severity },
          { text: f.code, cls: "code" },
          { text: f.account_ref, cls: "mono" },
          { text: f.field, cls: "mono" },
          { text: f.description, cls: "" },
        ].forEach(function (cell) {
          var td = document.createElement("td");
          td.textContent = cell.text;
          if (cell.cls) td.className = cell.cls;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    }

    renderJurisMeta($("r-juris-meta"), data.jurisdiction_metadata);
    $("r-notice").textContent = data.notice;
    renderLockState(false);
    show($("report-card"));
    $("report-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---------------------------------------------------------------
  // Flow actions
  // ---------------------------------------------------------------
  function submitPreview(event) {
    event.preventDefault();
    var form = $("preview-form");
    if (!form.reportValidity()) return;

    var jurisdiction = $("jurisdiction").value;
    if (jurisdiction === "__other__") {
      jurisdiction = $("jurisdiction_other").value.trim() || "US";
    }

    var payload = {
      consumer_name: $("consumer_name").value.trim(),
      jurisdiction: jurisdiction,
      report_date: $("report_date").value,
      accounts: readAccounts(),
    };
    if ($("consumer_email").value.trim()) {
      payload.consumer_email = $("consumer_email").value.trim();
    }
    if ($("ssn_last4").value.trim()) {
      payload.ssn_last4 = $("ssn_last4").value.trim();
    }

    var status = $("form-status");
    setStatus(status, "Running checks…", "busy");
    $("run-preview").disabled = true;

    apiFetch("/api/clearcheck/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(function (result) {
        if (!result.ok) {
          throw new Error(errorDetail(result, "Preview failed"));
        }
        setStatus(status, "Preview ready.", "ok");
        renderPreview(result.body);
      })
      .catch(function (err) {
        setStatus(status, err.message, "error");
      })
      .then(function () {
        $("run-preview").disabled = false;
      });
  }

  function fetchReport(checkId) {
    var requestVersion = ++reportRequestVersion;
    var status = $("lock-status");
    hide($("retry-report-btn"));
    hide($("lock-locked"));
    hide($("lock-unlocked"));
    hide($("report-card"));
    setStatus(status, "Retrieving report…", "busy");
    var path;
    try {
      // Browsers normalize literal or encoded dot segments before sending.
      // Encoding the separator retains '.' and '..' as opaque backend IDs.
      path = "/api/clearcheck/report" +
        (checkId === "." || checkId === ".." ? "%2F" : "/") +
        encodeURIComponent(checkId);
    } catch (e) {
      setStatus(status, "Could not encode the report reference.", "error");
      show($("retry-report-btn"));
      return Promise.resolve();
    }
    return apiFetch(path, {
      method: "GET",
    }).then(function (result) {
      if (requestVersion !== reportRequestVersion || checkId !== state.checkId) return;
      if (result.status === 402) {
        renderLockState(true);
        setStatus(
          status,
          "Still locked — the unlock payment has not been confirmed yet. " +
          "If you just paid, Stripe's confirmation can take a few seconds; " +
          "try again shortly.",
          "warn"
        );
        return;
      }
      if (result.status === 404) {
        setStatus(
          status,
          "Unknown check ID — run a preview first (previews may expire if " +
          "the backend store was reset).",
          "error"
        );
        show($("retry-report-btn"));
        return;
      }
      if (!result.ok) {
        throw new Error("Report retrieval failed (HTTP " + result.status + ").");
      }
      if (!result.body || result.body.unlocked !== true ||
          result.body.check_id !== checkId || !Array.isArray(result.body.findings) ||
          !result.body.jurisdiction_metadata ||
          typeof result.body.jurisdiction_metadata !== "object") {
        throw new Error("Could not verify the report. Please try again.");
      }
      setStatus(status, "", "");
      renderReport(result.body);
    }).catch(function (err) {
      if (requestVersion !== reportRequestVersion || checkId !== state.checkId) return;
      setStatus(status, err.message, "error");
      show($("retry-report-btn"));
    });
  }

  function startCheckout() {
    if (!state.checkId) return;
    var checkoutId = state.checkId;
    var status = $("lock-status");
    setStatus(status, "Creating secure checkout…", "busy");
    $("unlock-btn").disabled = true;

    var payload = { check_id: checkoutId };
    var email = $("checkout_email").value.trim();
    if (email) payload.customer_email = email;

    apiFetch("/api/clearcheck/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(function (result) {
        if (state.checkId !== checkoutId) return;
        if (result.status === 400 && result.body &&
            result.body.error === "check_already_unlocked") {
          // Confirm the current state through the report endpoint.
          return fetchReport(checkoutId);
        }
        if (result.status === 503) {
          throw new Error("Checkout is temporarily unavailable. Please try again later.");
        }
        if (result.status === 400) {
          // Do not echo arbitrary server details that might contain submitted data.
          var code = result.body && result.body.error;
          throw new Error(code === "invalid_checkout_request"
            ? "Invalid checkout request (invalid_checkout_request)."
            : "Checkout failed (HTTP 400).");
        }
        if (!result.ok) {
          throw new Error(errorDetail(result, "Checkout failed"));
        }
        setStatus(status, "Redirecting to secure Stripe checkout…", "ok");
        window.location.assign(result.body.checkout_url);
      })
      .catch(function (err) {
        if (state.checkId !== checkoutId) return;
        setStatus(status, err.message, "error");
      })
      .then(function () {
        $("unlock-btn").disabled = false;
      });
  }

  // ---------------------------------------------------------------
  // Stripe redirect handling (legacy clearcheck and React-compatible params)
  // ---------------------------------------------------------------
  function handleRedirectParams() {
    var params = new URLSearchParams(window.location.search);
    var legacyOutcome = params.get("clearcheck");
    var checkoutOutcome = params.get("checkout");
    var outcome = legacyOutcome === "success" || legacyOutcome === "cancelled"
      ? legacyOutcome
      : !legacyOutcome && params.has("check_id") &&
          (checkoutOutcome === "success" || checkoutOutcome === "cancelled")
        ? checkoutOutcome : null;
    var banner = $("redirect-banner");
    var checkIds = params.getAll("check_id");
    var checkId = null;
    if (checkIds.length === 1) {
      checkId = checkIds[0];
    } else if (checkIds.length === 0) {
      // Existing legacy links and ordinary reloads recover from storage.
      checkId = savedCheckId();
    }
    // A duplicated or blank URL reference must not fall back to another check.
    if (!validCheckId(checkId)) checkId = null;

    if (checkId) {
      if (outcome) {
        banner.textContent = outcome === "success"
          ? "Returned from checkout. Checking your report status…"
          : "Checkout was cancelled. Checking your report status…";
        show(banner);
      }
      state.checkId = checkId;
      $("p-check-id").textContent = checkId;
      hide($("preview-details"));
      show($("preview-card"));
      fetchReport(checkId);
    } else if (outcome || checkIds.length) {
      banner.textContent = (outcome === "success"
        ? "Returned from checkout. " : outcome === "cancelled"
          ? "Checkout was cancelled. " : "") +
        "Run your preview again to check your report status.";
      banner.classList.add("warn");
      show(banner);
    }

    // Keep exactly one URL reference if storage cannot preserve it for reload.
    // Remove only return parameters and check_id; preserve unrelated parameters.
    var saved = checkId ? saveCheckId(checkId) : false;
    var url = new URL(window.location.href);
    if (legacyOutcome === "success" || legacyOutcome === "cancelled") {
      url.searchParams.delete("clearcheck");
    }
    if (outcome && checkoutOutcome === outcome) url.searchParams.delete("checkout");
    if (checkIds.length && (!checkId || saved)) url.searchParams.delete("check_id");
    if (outcome && checkId && !saved && !checkIds.length) {
      url.searchParams.set("check_id", checkId);
    }
    if (url.toString() !== window.location.href) {
      window.history.replaceState({}, "", url.toString());
    }
  }

  // ---------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------
  function init() {
    $("api-base").textContent = API;
    $("report_date").value = new Date().toISOString().slice(0, 10);

    ["consumer_name", "consumer_email", "ssn_last4"].forEach(function (id) {
      var input = $(id);
      var preview = document.querySelector('[data-mask-for="' + id + '"]');
      bindMaskPreview(input, preview, MASKERS[id]);
    });

    $("jurisdiction").addEventListener("change", function () {
      var other = $("jurisdiction_other");
      if (this.value === "__other__") show(other); else hide(other);
    });

    addAccount();
    $("add-account").addEventListener("click", addAccount);
    $("preview-form").addEventListener("submit", submitPreview);
    $("unlock-btn").addEventListener("click", startCheckout);
    $("check-report-btn").addEventListener("click", function () {
      if (state.checkId) fetchReport(state.checkId);
    });
    $("view-report-btn").addEventListener("click", function () {
      if (state.checkId) fetchReport(state.checkId);
    });
    $("retry-report-btn").addEventListener("click", function () {
      if (state.checkId) fetchReport(state.checkId);
    });
    $("copy-check-id").addEventListener("click", function () {
      if (state.checkId && navigator.clipboard) {
        navigator.clipboard.writeText(state.checkId);
      }
    });

    handleRedirectParams();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
