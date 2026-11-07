"use strict";

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const csrf = $('meta[name="csrf-token"]').content;
  const forms = {domain: $("#domain-form"), headers: $("#headers-form")};
  let plan = null;
  let currentReport = null;
  let controller = null;
  let generation = 0;
  let currentView = "home";

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    svg.setAttribute("aria-hidden", "true");
    return svg;
  }
  function buttonLabel(button, label, iconName = "arrow") {
    button.replaceChildren(document.createTextNode(label), icon(iconName));
  }
  function showError(form, message) {
    const node = $(".form-error", form);
    node.textContent = message;
    node.hidden = false;
    node.tabIndex = -1;
    node.focus();
  }
  function clearReport() {
    currentReport = null;
    for (const id of ["result-meta", "result-summary", "result-sections", "result-limitations", "result-sources"])
      $("#" + id).replaceChildren();
    $("#result-target").textContent = "";
    $("#result-title").textContent = "Analysebericht";
    $("#download-error").hidden = true;
  }
  function invalidatePlan(module) {
    plan = null;
    const form = forms[module];
    const panel = $(".plan-panel", form);
    panel.replaceChildren();
    panel.hidden = true;
    const external = module === "domain" || form.elements.enrich.checked;
    buttonLabel($('button[type="submit"]', form), external ? "Abfrageplan anzeigen" : "Header lokal auswerten");
    if (module === "headers") {
      $("#header-preflight").hidden = !external;
      $(".required-note", form).textContent = external ? "* Pflichtfelder · Externe Ergänzung ausgewählt" : "* Pflichtfelder · Headeranalyse ohne externe Abfragen";
    }
  }
  function clearSensitive() {
    generation += 1;
    if (controller) controller.abort();
    controller = null;
    clearReport();
    for (const [module, form] of Object.entries(forms)) {
      form.reset();
      form.elements.input.setCustomValidity("");
      $$("input, textarea, button", form).forEach(node => { if (!node.matches('input[type="checkbox"][disabled]')) node.disabled = false; });
      const button = $('button[type="submit"]', form);
      button.classList.remove("busy");
      button.removeAttribute("aria-busy");
      $(".form-error", form).hidden = true;
      $(".run-status", form)?.remove();
      invalidatePlan(module);
    }
    $("#header-size").textContent = "0 / 64 KiB";
  }
  function navigate() {
    const hash = location.hash.slice(1);
    const view = ["domain", "headers"].includes(hash) ? hash : "home";
    if (currentView !== view) clearSensitive();
    currentView = view;
    $$(".view").forEach(node => { node.hidden = node.id !== `view-${view}`; });
    $$('[data-nav]').forEach(node => {
      const active = node.dataset.nav === view;
      node.classList.toggle("active", active);
      if (active) node.setAttribute("aria-current", "page");
      else node.removeAttribute("aria-current");
    });
    const label = {home: "Übersicht", domain: "Domainanalyse", headers: "E-Mail-Header"}[view];
    $("#breadcrumb-current").textContent = label;
    document.title = `${label} · Web Forensics`;
    if (hash === "tools") $("#tools").scrollIntoView();
    else window.scrollTo(0, 0);
  }
  async function request(url, payload, signal) {
    const response = await fetch(url, {
      method: "POST", headers: {"Content-Type": "application/json", "X-CSRFToken": csrf},
      body: JSON.stringify(payload), credentials: "same-origin", cache: "no-store", signal,
    });
    if (!response.ok) {
      let message = "Die Anfrage ist fehlgeschlagen. Bitte erneut versuchen.";
      try { message = (await response.json()).error || message; } catch (_) { /* No server details are displayed. */ }
      throw new Error(message);
    }
    return response;
  }
  function renderPlan(module, data) {
    plan = {module, token: data.token};
    const panel = $(".plan-panel", forms[module]);
    panel.replaceChildren(element("h3", "", "Vorgesehene externe Abfragen"), element("p", "plan-intro", "Bitte die Empfänger und übermittelten Daten prüfen. Aktenzeichen und vollständige Header werden nicht an diese Dienste gesendet."));
    for (const [purpose, recipient, transmitted] of data.plan.recipients) {
      const node = element("div", "plan-recipient");
      node.append(element("strong", "", purpose));
      const hosts = element("div", "recipient-host", recipient);
      if (recipient.split(", ").length > 8) {
        const providers = element("details");
        providers.append(element("summary", "", `Mögliche Anbieter anzeigen (${recipient.split(", ").length})`), hosts);
        node.append(providers);
      } else node.append(hosts);
      node.append(element("p", "", transmitted));
      panel.append(node);
    }
    for (const message of data.plan.errors) panel.append(element("p", "plan-error", message + " Dieser Prüfbereich wird gegebenenfalls als nicht verfügbar ausgewiesen."));
    const consent = element("label", "check-row consent-row");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.name = "consent";
    checkbox.required = true;
    const text = element("span");
    text.append(element("strong", "", "Ich möchte die ausgewählten Abfragen an die aufgeführten Empfänger durchführen lassen."));
    consent.append(checkbox, text);
    panel.append(consent);
    panel.hidden = false;
    buttonLabel($('button[type="submit"]', forms[module]), "Analyse starten");
    panel.scrollIntoView({block: "center"});
    checkbox.focus({preventScroll: true});
  }
  function renderResult(data) {
    currentReport = {token: data.token, filename: data.filename};
    const report = data.report;
    $$(".view").forEach(node => { node.hidden = node.id !== "view-result"; });
    currentView = "result";
    $("#breadcrumb-current").textContent = "Analysebericht";
    document.title = "Analysebericht · Web Forensics";
    $("#result-title").textContent = report.module === "domain" ? "Domainanalyse" : "E-Mail-Header-Analyse";
    $("#result-target").textContent = report.target;
    const meta = $("#result-meta");
    meta.replaceChildren();
    const date = new Date(report.started_at).toLocaleString("de-DE", {timeZone: "UTC", dateStyle: "medium", timeStyle: "medium"}) + " UTC";
    for (const [label, value] of [["AKTENZEICHEN", report.case], ["ABFRAGEZEITPUNKT", date], ["ANALYSE-ID", report.id]]) {
      const cell = element("div", "meta-cell");
      cell.append(element("small", "", label), element("strong", "", value));
      meta.append(cell);
    }
    $("#result-summary").replaceChildren(...report.summary.map(item => {
      const node = element("div", `summary-item ${item.level}`);
      node.append(element("span", "", {warning: "Auffälligkeit", notice: "Hinweis", info: "Feststellung"}[item.level] || "Hinweis"), element("p", "", item.text));
      return node;
    }));
    $("#result-sections").replaceChildren(...report.sections.map((item, index) => {
      const details = element("details", "result-section");
      details.open = index < 2;
      const summary = element("summary");
      summary.append(element("span", "", item.title), element("span", `result-status ${item.status}`, {ok: "Ergebnis vorhanden", empty: "Kein Eintrag", unavailable: "Nicht verfügbar"}[item.status] || item.status));
      const body = element("div", "detail-body");
      if (item.source) body.append(element("p", "detail-source", "Quelle: " + item.source));
      if (item.note) body.append(element("p", "detail-note", item.note));
      if (item.rows.length) {
        const table = element("table", "result-table");
        const tbody = element("tbody");
        for (const [label, value] of item.rows) {
          const row = element("tr");
          const th = element("th", "", label);
          th.scope = "row";
          row.append(th, element("td", "", value));
          tbody.append(row);
        }
        table.append(tbody);
        body.append(table);
      }
      if (item.raw) {
        const rawDetails = element("details");
        rawDetails.append(element("summary", "", "Rohdaten anzeigen"), element("pre", "raw-data", item.raw));
        body.append(rawDetails);
      }
      details.append(summary, body);
      return details;
    }));
    $("#result-limitations").replaceChildren(...report.limitations.map(text => element("li", "", text)));
    $("#result-sources").replaceChildren(...report.sources.map(text => element("li", "", text)));
    $("#expand-results").textContent = "Alle aufklappen";
    window.scrollTo(0, 0);
    const heading = $("#result-title");
    heading.tabIndex = -1;
    heading.focus({preventScroll: true});
  }

  for (const [module, form] of Object.entries(forms)) {
    form.addEventListener("input", event => {
      if (event.target.name !== "consent") invalidatePlan(module);
      if (module === "headers") {
        const size = new TextEncoder().encode(form.elements.input.value).length;
        $("#header-size").textContent = `${(size / 1024).toFixed(1)} / 64 KiB`;
        form.elements.input.setCustomValidity(size > 65536 ? "Der Header darf maximal 64 KiB umfassen." : "");
      }
    });
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const button = $('button[type="submit"]', form);
      const external = module === "domain" || form.elements.enrich.checked;
      const isPlanRequest = external && (!plan || plan.module !== module);
      const payload = {module, case: form.elements.case.value, input: form.elements.input.value};
      if (module === "headers") payload.enrich = form.elements.enrich.checked;
      if (external && !isPlanRequest) {
        payload.plan_token = plan.token;
        payload.consent = form.elements.consent.checked;
      }
      $(".form-error", form).hidden = true;
      const marker = ++generation;
      controller = new AbortController();
      const signal = controller.signal;
      const status = element("p", "field-help run-status", isPlanRequest ? "Registrierungsdienste werden ermittelt …" : "Analyse läuft. Netzwerkabfragen können bis zu etwa zwei Minuten dauern …");
      status.setAttribute("role", "status");
      $(".form-actions", form).before(status);
      buttonLabel(button, isPlanRequest ? "Abfrageplan wird erstellt …" : "Analyse läuft …");
      button.classList.add("busy");
      button.setAttribute("aria-busy", "true");
      $$("input, textarea, button", form).forEach(node => { node.disabled = true; });
      try {
        let response;
        if (isPlanRequest) {
          const options = module === "domain" ? Object.fromEntries(["rdap", "whois", "network", "tls", "http"].map(key => [key, form.elements[key].checked])) : {network: true};
          response = await request("/api/plan", {module, domain: module === "domain" ? payload.input : "", options}, signal);
        } else response = await request("/api/analyze", payload, signal);
        const data = await response.json();
        if (marker !== generation) return;
        if (isPlanRequest) renderPlan(module, data);
        else renderResult(data);
      } catch (error) {
        if (marker === generation && error.name !== "AbortError") {
          if (external) invalidatePlan(module);
          showError(form, error.message || "Verbindung zur Anwendung fehlgeschlagen.");
        }
      } finally {
        status.remove();
        if (marker === generation) {
          button.classList.remove("busy");
          button.removeAttribute("aria-busy");
          $$("input, textarea, button", form).forEach(node => { node.disabled = false; });
          if (module === "domain") $('.checks input[type="checkbox"]', form).disabled = true;
          const label = external ? (plan ? "Analyse starten" : "Abfrageplan anzeigen") : "Header lokal auswerten";
          buttonLabel(button, label);
          controller = null;
        }
      }
    });
  }
  $("#sample-header").addEventListener("click", () => {
    forms.headers.elements.input.value = [
      "Received: from relay.example (relay.example [198.51.100.20]) by inbox.example; Fri, 06 Nov 2026 12:01:00 +0000",
      "Received: from sender.example (sender.example [203.0.113.10]) by relay.example; Fri, 06 Nov 2026 12:00:00 +0000",
      "Authentication-Results: inbox.example; spf=pass smtp.mailfrom=bounce.example; dkim=fail header.d=sender.example; dmarc=fail header.from=sender.example",
      "From: Beispielabsender <post@sender.example>", "Reply-To: service@antwort.example", "Return-Path: <bounce@bounce.example>",
      "To: empfang@inbox.example", "Subject: Fiktiver Header zur Demonstration", "Date: Fri, 06 Nov 2026 11:59:00 +0000", "Message-ID: <demo-001@sender.example>",
    ].join("\n");
    forms.headers.elements.input.dispatchEvent(new Event("input", {bubbles: true}));
  });
  $("#download-pdf").addEventListener("click", async () => {
    if (!currentReport) return;
    const button = $("#download-pdf");
    const marker = ++generation;
    controller = new AbortController();
    button.disabled = true;
    button.classList.add("busy");
    $("#download-error").hidden = true;
    try {
      const response = await request("/api/report.pdf", {token: currentReport.token}, controller.signal);
      const blob = await response.blob();
      if (marker !== generation) return;
      const url = URL.createObjectURL(blob);
      const link = element("a");
      link.href = url;
      link.download = currentReport.filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      clearSensitive();
      location.hash = "home";
      navigate();
      const toast = $("#toast");
      toast.textContent = "PDF-Download gestartet. Eingaben und Ergebnisansicht wurden geleert.";
      toast.hidden = false;
      setTimeout(() => { toast.hidden = true; }, 8000);
    } catch (error) {
      if (marker === generation && error.name !== "AbortError") {
        $("#download-error").textContent = error.message;
        $("#download-error").hidden = false;
      }
    } finally {
      button.disabled = false;
      button.classList.remove("busy");
    }
  });
  $("#clear-results").addEventListener("click", () => { clearSensitive(); location.hash = "home"; navigate(); });
  $("#expand-results").addEventListener("click", event => {
    const expand = event.currentTarget.textContent === "Alle aufklappen";
    $$("#result-sections > details").forEach(node => { node.open = expand; });
    event.currentTarget.textContent = expand ? "Alle zuklappen" : "Alle aufklappen";
  });
  $$('[data-dialog="privacy"]').forEach(button => button.addEventListener("click", () => $("#privacy-dialog").showModal()));
  $("#close-dialog").addEventListener("click", () => $("#privacy-dialog").close());
  $("#check-release").addEventListener("click", async () => {
    const button = $("#check-release");
    const status = $("#release-status");
    const details = $("#release-details");
    button.disabled = true;
    button.classList.add("busy");
    button.setAttribute("aria-busy", "true");
    details.hidden = true;
    $("#release-upgrade").hidden = true;
    $("#release-commands").textContent = "";
    status.textContent = "Veröffentlichte GitHub-Releases werden geprüft …";
    try {
      const response = await request("/api/releases/check", {});
      const data = await response.json();
      status.textContent = data.message;
      if (data.release) {
        details.hidden = false;
        $("#release-link").href = data.release.url;
        $("#release-link").textContent = `${data.release.tag} auf GitHub öffnen ↗`;
        const published = new Date(data.release.published_at).toLocaleString("de-DE", {timeZone: "UTC"});
        $("#release-time").textContent = `Veröffentlicht: ${published} UTC · Geprüft: ${new Date(data.checked_at).toLocaleString("de-DE", {timeZone: "UTC"})} UTC`;
      }
      if (data.status === "update_available" && data.instructions.length) {
        $("#release-commands").textContent = data.instructions.join(" &&\n");
        $("#release-upgrade").hidden = false;
        $("#copy-release").textContent = "Befehle kopieren";
      }
    } catch (error) {
      status.textContent = "Prüfung nicht möglich: " + error.message;
    } finally {
      button.disabled = false;
      button.classList.remove("busy");
      button.removeAttribute("aria-busy");
    }
  });
  $("#copy-release").addEventListener("click", async event => {
    const button = event.currentTarget;
    const code = $("#release-commands");
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = "Befehle kopiert";
    } catch (_) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(code);
      selection.removeAllRanges();
      selection.addRange(range);
      code.focus();
      $("#copy-release").textContent = "Befehle markiert – mit Strg+C kopieren";
    }
  });
  window.addEventListener("hashchange", navigate);
  document.addEventListener("click", event => {
    const anchor = event.target.closest('a[href^="#"]');
    if (anchor && anchor.hash === location.hash) {
      event.preventDefault();
      navigate();
    }
  });
  window.addEventListener("pagehide", clearSensitive);
  window.addEventListener("pageshow", event => { if (event.persisted) { clearSensitive(); navigate(); } });
  navigate();
})();
