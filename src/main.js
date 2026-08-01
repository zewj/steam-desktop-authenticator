// Frontend. Holds no secrets: it asks Rust for finished codes and metadata.

const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;
const { writeText } = window.__TAURI__.clipboardManager;
const { openPath } = window.__TAURI__.opener ?? {};
const appWindow = window.__TAURI__.window?.getCurrentWindow?.();

const $ = (id) => document.getElementById(id);
const el = {
  app: $("app"),
  list: $("account-list"),
  title: $("view-title"), sub: $("view-sub"),
  codeCard: $("code-card"), emptyView: $("empty-view"),
  code: $("code"), fill: $("fill"), countdown: $("countdown"),
  copy: $("copy-btn"), autocopy: $("autocopy"), autocopy2: $("autocopy2"),
  status: $("status"),
  accountGrid: $("account-grid"), revocation: $("revocation-value"),
  revocationCard: $("revocation-card"), reveal: $("reveal-btn"),
  clockDetail: $("clock-detail"), dirDetail: $("dir-detail"),
  wizard: $("wizard"), wizardBody: $("wizard-body"), wizardSteps: $("wizard-steps"),
  passkeyDialog: $("passkey-dialog"), passkeyInput: $("passkey-input"),
};

const state = {
  accounts: [],
  selected: 0,
  expiresAt: 0,
  stepMs: 30000,
  lastCode: "",
  autoCopy: localStorage.getItem("autoCopy") === "1",
  pendingPasskey: null,
  directory: "",
  offset: null,
  revealed: false,
  confirmations: [],
  view: "codes",
};

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const VIEWS = {
  codes: { title: "Codes", sub: "Steam Guard codes for the selected account" },
  confirmations: { title: "Confirmations", sub: "Trades and market listings waiting for approval" },
  account: { title: "Account", sub: "Details for the selected authenticator" },
  settings: { title: "Settings", sub: "Appearance, clock, and account files" },
};

/** Restart a CSS animation: drop the class, force reflow, put it back. */
function replay(node, className) {
  node.classList.remove(className);
  void node.offsetWidth;
  node.classList.add(className);
}

/** `<dialog>.close()` is instant, so play the exit first and close on its end. */
function closeDialog(dialog) {
  if (!dialog.open || dialog.classList.contains("closing")) return;
  if (reducedMotion) { dialog.close(); return; }

  dialog.classList.add("closing");
  dialog.addEventListener("animationend", function done(event) {
    // ::backdrop animations also bubble here; only the panel's exit ends it.
    if (event.animationName !== "surface-out") return;
    dialog.removeEventListener("animationend", done);
    dialog.classList.remove("closing");
    dialog.close();
  });
}

function setStatus(message, kind = "") {
  el.status.textContent = message;
  el.status.className = `status glass ${kind}`;
  replay(el.status, "flash");
}

const icon = (name) =>
  `<svg viewBox="0 0 24 24" aria-hidden="true"><use href="#i-${name}"/></svg>`;

// -------------------------------------------------------------------- theme

// The header button flips between light and dark, always against what is on
// screen, so a click is never a no-op. "Follow system" is a real third state
// but lives in Settings: cycling through it reads as a dead click whenever it
// resolves to the theme you are already on.
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");

function resolvedTheme(choice) {
  return choice === "system" ? (systemDark.matches ? "dark" : "light") : choice;
}

let themingTimer;
let themeChoice = localStorage.getItem("theme") || "system";

function applyTheme(choice) {
  const resolved = resolvedTheme(choice);
  const root = document.documentElement;

  // Cross-fade the colour change, but only for its duration — leaving the
  // transition on permanently would blunt every hover in the app.
  if (!reducedMotion && root.dataset.theme && root.dataset.theme !== resolved) {
    root.classList.add("theming");
    clearTimeout(themingTimer);
    themingTimer = setTimeout(() => root.classList.remove("theming"), 320);
  }
  root.dataset.theme = resolved;

  // The icon shows what the click will give you, not what you are on.
  const target = resolved === "dark" ? "light" : "dark";
  $("theme-icon").innerHTML = `<use href="#i-${target === "light" ? "sun" : "moon"}"/>`;
  const label = `Switch to ${target} theme` +
    (choice === "system" ? " (currently following system)" : "");
  $("theme-btn").title = label;
  $("theme-btn").setAttribute("aria-label", label);

  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-checked",
      String(button.dataset.themeChoice === choice));
  }
  appWindow?.setTheme?.(choice === "system" ? null : resolved).catch(() => {});
}

function setTheme(choice) {
  themeChoice = choice;
  if (choice === "system") localStorage.removeItem("theme");
  else localStorage.setItem("theme", choice);
  applyTheme(choice);
}

applyTheme(themeChoice);
systemDark.addEventListener("change", () => {
  if (themeChoice === "system") applyTheme("system");
});

// -------------------------------------------------------------------- views

function switchView(name) {
  state.view = name;
  for (const section of document.querySelectorAll(".view")) {
    section.classList.toggle("active", section.id === `view-${name}`);
  }
  for (const item of document.querySelectorAll(".nav-item")) {
    const on = item.dataset.view === name;
    item.classList.toggle("active", on);
    item.setAttribute("aria-current", on ? "page" : "false");
  }
  el.title.textContent = VIEWS[name].title;
  el.sub.textContent = VIEWS[name].sub;

  if (name === "account") renderAccount();
  if (name === "settings") renderSettings();
  if (name === "confirmations") loadConfirmations();
}

// ------------------------------------------------------- confirmations view

const confList = $("conf-list");
const confBadge = $("conf-badge");

function confNotice(iconName, title, body, bad = false) {
  confList.innerHTML =
    `<div class="card glass notice${bad ? " bad" : ""}">` +
    `<svg viewBox="0 0 24 24" aria-hidden="true"><use href="#i-${iconName}"/></svg>` +
    `<h2></h2><p></p></div>`;
  confList.querySelector("h2").textContent = title;
  confList.querySelector("p").textContent = body;
  $("conf-bulk").classList.toggle("hidden", true);
}

function setConfBadge(count) {
  confBadge.textContent = String(count);
  confBadge.classList.toggle("hidden", count === 0);
}

async function loadConfirmations() {
  if (!state.accounts.length) {
    confNotice("inbox", "No account selected", "Add or open an authenticator first.");
    setConfBadge(0);
    return;
  }

  confNotice("refresh", "Checking with Steam…", "Opening a session for this account.");
  try {
    const list = await invoke("list_confirmations", { index: state.selected });
    state.confirmations = list;
    renderConfirmations();
  } catch (error) {
    setConfBadge(0);
    confNotice("x", "Could not load confirmations", String(error), true);
  }
}

function renderConfirmations() {
  const list = state.confirmations;
  setConfBadge(list.length);

  if (!list.length) {
    confNotice("inbox", "Nothing waiting",
      "Trades and market listings needing approval will appear here.");
    return;
  }

  $("conf-bulk").classList.toggle("hidden", list.length < 2);
  confList.innerHTML = "";

  for (const item of list) {
    const row = document.createElement("div");
    row.className = "conf card glass";
    row.innerHTML =
      (item.icon ? `<img alt="" />` : "") +
      `<div class="conf-body"><span class="conf-kind"></span><b></b><span></span></div>` +
      `<div class="btn-pair">` +
      `<button class="btn small">${icon("check")}<span></span></button>` +
      `<button class="btn small deny">${icon("x")}<span></span></button>` +
      `</div>`;

    if (item.icon) row.querySelector("img").src = item.icon;
    row.querySelector(".conf-kind").textContent = item.kind;
    row.querySelector(".conf-body b").textContent = item.headline || "(no description)";
    row.querySelector(".conf-body span:last-child").textContent = item.summary;

    const [allowBtn, denyBtn] = row.querySelectorAll("button");
    allowBtn.querySelector("span").textContent = item.accept_label;
    denyBtn.querySelector("span").textContent = item.cancel_label;
    allowBtn.onclick = () => respond(item, true, row);
    denyBtn.onclick = () => respond(item, false, row);

    confList.append(row);
  }
}

async function respond(item, allow, row) {
  const buttons = row.querySelectorAll("button");
  buttons.forEach((b) => (b.disabled = true));
  try {
    await invoke("respond_to_confirmation", {
      index: state.selected, id: item.id, nonce: item.nonce, allow,
    });
    state.confirmations = state.confirmations.filter((c) => c.id !== item.id);
    renderConfirmations();
    setStatus(`${allow ? "Confirmed" : "Denied"}: ${item.headline || item.kind}`,
      allow ? "good" : "warn");
  } catch (error) {
    buttons.forEach((b) => (b.disabled = false));
    setStatus(String(error), "error");
  }
}

$("conf-refresh").onclick = loadConfirmations;

$("conf-allow-all").onclick = async () => {
  const pending = [...state.confirmations];
  if (!pending.length) return;
  $("conf-allow-all").disabled = true;
  let done = 0;
  for (const item of pending) {
    try {
      await invoke("respond_to_confirmation", {
        index: state.selected, id: item.id, nonce: item.nonce, allow: true,
      });
      done += 1;
      state.confirmations = state.confirmations.filter((c) => c.id !== item.id);
    } catch (error) {
      setStatus(`Stopped after ${done}: ${error}`, "error");
      break;
    }
  }
  $("conf-allow-all").disabled = false;
  renderConfirmations();
  if (done) setStatus(`Confirmed ${done} of ${pending.length}`, "good");
};

for (const item of document.querySelectorAll(".nav-item")) {
  item.onclick = () => switchView(item.dataset.view);
}

// sidebar collapse, remembered between runs
function setCollapsed(collapsed) {
  el.app.classList.toggle("collapsed", collapsed);
  localStorage.setItem("collapsed", collapsed ? "1" : "0");
  const button = $("collapse-btn");
  button.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
  button.setAttribute("aria-label", button.title);
  button.setAttribute("aria-expanded", String(!collapsed));
}
setCollapsed(localStorage.getItem("collapsed") === "1");
$("collapse-btn").onclick = () => setCollapsed(!el.app.classList.contains("collapsed"));
// Collapsed, the toggle hides with the brand row; the rail itself reopens it.
$("sidebar").addEventListener("dblclick", (event) => {
  if (event.target.closest(".account-row, .nav-item, .add-btn")) return;
  setCollapsed(!el.app.classList.contains("collapsed"));
});

// ------------------------------------------------------------------ loading

function renderAccountList() {
  el.list.innerHTML = "";
  state.accounts.forEach((account, index) => {
    const row = document.createElement("button");
    row.className = "account-row";
    row.setAttribute("role", "option");
    row.setAttribute("aria-selected", String(index === state.selected));
    row.title = account.label;
    row.innerHTML =
      `<span class="account-dot"></span>` +
      `<span class="account-meta"><b></b><span></span></span>`;
    row.querySelector("b").textContent = account.label;
    row.querySelector(".account-meta span").textContent = account.steamid || "—";
    row.onclick = () => selectAccount(index);
    el.list.append(row);
  });
}

function selectAccount(index) {
  state.selected = index;
  state.lastCode = "";
  state.revealed = false;
  state.confirmations = [];
  renderAccountList();
  refreshCode();
  if (state.view === "account") renderAccount();
}

function showAccounts(result) {
  state.accounts = result.accounts || [];
  if (result.directory) {
    state.directory = result.directory;
    // Remember where the accounts actually came from, so the next launch finds
    // them wherever the binary happens to live.
    if (state.accounts.length) localStorage.setItem("maFilesDir", result.directory);
  }

  const has = state.accounts.length > 0;
  el.codeCard.classList.toggle("hidden", !has);
  el.emptyView.classList.toggle("hidden", has);

  state.selected = Math.min(state.selected, Math.max(0, state.accounts.length - 1));
  renderAccountList();

  if (has) {
    state.lastCode = "";
    refreshCode();
  }
  if (state.view === "account") renderAccount();
  if (state.view === "settings") renderSettings();
}

async function loadDefaults() {
  // A folder you picked wins over the search paths. Without this, running the
  // binary from anywhere other than beside your maFiles (Downloads, Program
  // Files) opens empty every launch, because the automatic search only walks
  // up from the executable.
  const remembered = localStorage.getItem("maFilesDir");
  if (remembered) {
    try {
      const saved = await invoke("load_folder", { path: remembered, passkey: null });
      if (saved.accounts.length) {
        showAccounts(saved);
        setStatus(`Loaded ${saved.accounts.length} account(s) from ${saved.directory}`);
        return;
      }
      if (saved.needs_passkey) {
        showAccounts(saved);
        setStatus(`Encrypted maFiles in ${remembered} — unlock to use them`, "warn");
        askPasskey(remembered);
        return;
      }
    } catch {
      // Folder moved or gone: fall through to the automatic search.
    }
  }

  const result = await invoke("load_default_accounts");
  showAccounts(result);

  if (result.needs_passkey) {
    setStatus(`Encrypted maFiles in ${result.directory} — unlock to use them`, "warn");
    askPasskey(result.directory);
  } else if (result.accounts.length) {
    const skipped = result.errors.length ? ` — ${result.errors.length} skipped` : "";
    setStatus(`Loaded ${result.accounts.length} account(s) from ${result.directory}${skipped}`);
  } else {
    setStatus("No accounts loaded");
  }
}

function askPasskey(directory) {
  state.pendingPasskey = directory;
  el.passkeyInput.value = "";
  el.passkeyDialog.showModal();
  el.passkeyInput.focus();
}

// -------------------------------------------------------------------- codes

async function refreshCode() {
  if (!state.accounts.length) return;
  try {
    const view = await invoke("current_code", { index: state.selected });
    state.expiresAt = view.expires_at_ms;
    state.stepMs = view.step_ms;
    state.offset = view.clock_offset;

    if (view.code !== state.lastCode) {
      const rolled = state.lastCode !== "";
      state.lastCode = view.code;
      el.code.textContent = view.code;
      // Only animate a genuine rotation — not the first paint, and not a
      // manual account switch, where the movement would mean nothing.
      if (rolled) replay(el.code, "rotated");
      if (rolled && state.autoCopy) copyCode(true);
    }
  } catch (error) {
    setStatus(String(error), "error");
  }
}

function tick() {
  if (state.accounts.length) {
    const remaining = state.expiresAt - Date.now();
    if (remaining <= 0) {
      refreshCode();
    } else {
      const fraction = Math.max(0, Math.min(1, remaining / state.stepMs));
      el.fill.style.width = `${(fraction * 100).toFixed(2)}%`;

      const seconds = Math.ceil(remaining / 1000);
      const urgent = seconds <= 5;
      el.countdown.textContent = `expires in ${seconds}s`;
      el.countdown.classList.toggle("urgent", urgent);
      el.fill.classList.toggle("urgent", urgent);
    }
  }
  // Reduced motion: step once a second rather than animating every frame.
  if (reducedMotion) setTimeout(tick, 1000);
  else requestAnimationFrame(tick);
}

async function copyCode(silent = false) {
  if (!state.lastCode) return;
  await writeText(state.lastCode);
  replay(el.code, "copied");
  if (!silent) {
    el.copy.innerHTML = `${icon("check")}<span>Copied</span>`;
    setTimeout(() => {
      el.copy.innerHTML = `${icon("copy")}<span>Copy code</span>`;
    }, 1100);
  }
  setStatus(`Copied ${state.lastCode}`, "good");
}

// ------------------------------------------------------------- account view

function renderAccount() {
  const account = state.accounts[state.selected];
  el.accountGrid.innerHTML = "";
  el.revocationCard.classList.toggle("hidden", !account);

  if (!account) {
    el.accountGrid.innerHTML =
      `<p class="note">No account selected. Create one, or open an .maFile.</p>`;
    return;
  }

  const fields = [
    ["Account name", account.account_name || "—"],
    ["SteamID", account.steamid || "—"],
    ["Device ID", account.device_id || "—"],
    ["Identity secret", account.has_identity_secret ? "present" : "not in file"],
    ["File", account.path || "entered manually"],
  ];
  for (const [key, value] of fields) {
    const field = document.createElement("div");
    field.className = "field";
    field.innerHTML = "<dt></dt><dd></dd>";
    field.querySelector("dt").textContent = key;
    field.querySelector("dd").textContent = value;
    el.accountGrid.append(field);
  }

  // Hidden until asked for: it is the account's recovery secret, and this
  // window may well be on a stream or a shared screen.
  el.revocation.textContent = state.revealed
    ? (account.revocation_code || "—")
    : "••••••";
  el.reveal.innerHTML = state.revealed
    ? `${icon("eye-off")}<span>Hide</span>`
    : `${icon("eye")}<span>Reveal</span>`;
}

el.reveal.onclick = () => {
  state.revealed = !state.revealed;
  renderAccount();
};

// ------------------------------------------------------------ settings view

function renderSettings() {
  el.autocopy2.setAttribute("aria-checked", String(state.autoCopy));
  el.autocopy.setAttribute("aria-checked", String(state.autoCopy));
  el.dirDetail.textContent = state.directory || "none found yet";
  el.clockDetail.textContent =
    state.offset === null || state.offset === undefined
      ? "Not checked yet."
      : Math.abs(state.offset) <= 1
        ? "In sync with Steam."
        : `Local clock is ${Math.abs(state.offset)}s ` +
          `${state.offset > 0 ? "behind" : "ahead of"} Steam; codes are corrected.`;
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-checked",
      String(button.dataset.themeChoice === themeChoice));
  }
}

function setAutoCopy(on) {
  state.autoCopy = on;
  localStorage.setItem("autoCopy", on ? "1" : "0");
  el.autocopy.setAttribute("aria-checked", String(on));
  el.autocopy2.setAttribute("aria-checked", String(on));
}

el.autocopy.onclick = () => setAutoCopy(!state.autoCopy);
el.autocopy2.onclick = () => setAutoCopy(!state.autoCopy);
setAutoCopy(state.autoCopy);

for (const button of document.querySelectorAll("[data-theme-choice]")) {
  button.onclick = () => setTheme(button.dataset.themeChoice);
}

// ------------------------------------------------------------------ actions

async function pickFile() {
  const path = await open({
    multiple: false,
    filters: [{ name: "maFile", extensions: ["maFile", "json"] }],
  });
  if (!path) return;
  try {
    const result = await invoke("load_file", { path, passkey: null });
    if (result.needs_passkey) { askPasskey(path); return; }
    showAccounts(result);
    setStatus(`Loaded ${result.accounts.length} account(s)`);
  } catch (error) {
    setStatus(String(error), "error");
  }
}

async function pickFolder() {
  const path = await open({ directory: true });
  if (!path) return;
  const result = await invoke("load_folder", { path, passkey: null });
  if (result.needs_passkey) { askPasskey(path); return; }
  if (!result.accounts.length) {
    setStatus(result.errors[0] || "No usable accounts found", "warn");
    return;
  }
  showAccounts(result);
  setStatus(`Loaded ${result.accounts.length} account(s) from ${result.directory}`);
}

async function syncTime() {
  setStatus("Checking Steam server time…");
  try {
    const offset = await invoke("sync_time");
    state.offset = offset;
    setStatus(
      Math.abs(offset) <= 1 ? "Clock in sync with Steam"
        : `Clock adjusted ${offset >= 0 ? "+" : ""}${offset}s to match Steam`,
      Math.abs(offset) <= 1 ? "" : "warn");
    state.lastCode = "";
    refreshCode();
    if (state.view === "settings") renderSettings();
  } catch (error) {
    setStatus(`Time sync failed — using local clock (${error})`, "warn");
  }
}

$("theme-btn").onclick = () =>
  setTheme(resolvedTheme(themeChoice) === "dark" ? "light" : "dark");
$("sync-btn").onclick = syncTime;
$("sync-btn2").onclick = syncTime;
$("new-btn").onclick = () => startWizard();
$("empty-create").onclick = () => startWizard();
$("empty-open").onclick = pickFile;
$("open-file").onclick = pickFile;
el.copy.onclick = () => copyCode();
el.code.onclick = () => copyCode();

$("open-folder").onclick = async () => {
  if (!state.directory) { pickFolder(); return; }
  try {
    await openPath?.(state.directory);
  } catch {
    pickFolder();
  }
};

$("passkey-ok").onclick = async () => {
  const passkey = el.passkeyInput.value;
  if (!passkey) return;
  closeDialog(el.passkeyDialog);
  const target = state.pendingPasskey;
  try {
    const result = target.toLowerCase().endsWith(".mafile")
      ? await invoke("load_file", { path: target, passkey })
      : await invoke("load_folder", { path: target, passkey });
    if (!result.accounts.length) {
      setStatus(result.errors[0] || "That passkey did not work", "error");
      return;
    }
    showAccounts(result);
    setStatus(`Unlocked ${result.accounts.length} account(s)`, "good");
  } catch (error) {
    setStatus(String(error), "error");
  }
};
$("passkey-cancel").onclick = () => closeDialog(el.passkeyDialog);
el.passkeyInput.onkeydown = (e) => { if (e.key === "Enter") $("passkey-ok").click(); };

// ------------------------------------------------------------------ wizard

const STEPS = ["Sign in", "Confirm", "Attach", "Activate"];
const wizard = { step: 0, busy: false, saved: false, activated: false, cancelled: false };

function setStep(index) {
  wizard.step = index;
  [...el.wizardSteps.children].forEach((node, i) =>
    node.classList.toggle("done", i <= index));
}

function wizardHTML(html) {
  el.wizardBody.innerHTML = html;
  // Slide in from the right, matching the stepper's direction of travel.
  replay(el.wizardBody, "step-enter");
}

function startWizard() {
  wizard.step = 0; wizard.busy = false;
  wizard.saved = false; wizard.activated = false; wizard.cancelled = false;
  setStep(0);
  stepCredentials();
  el.wizard.showModal();
}

/** Guard every async wizard action: without this the Enter key can fire a
 *  second login while the first is still in flight, and repeated Steam login
 *  attempts get the account rate limited. */
async function guarded(button, work) {
  if (wizard.busy) return;
  wizard.busy = true;
  const label = button?.innerHTML;
  if (button) { button.disabled = true; button.textContent = "Working…"; }
  try {
    await work();
  } catch (error) {
    setWizardError(String(error));
  } finally {
    wizard.busy = false;
    if (button?.isConnected) { button.disabled = false; button.innerHTML = label; }
  }
}

function setWizardError(message) {
  let node = el.wizardBody.querySelector(".wizard-error");
  if (!node) {
    node = document.createElement("p");
    node.className = "wizard-error";
    node.style.color = "var(--danger)";
    node.setAttribute("role", "alert");
    el.wizardBody.append(node);
  }
  node.textContent = message.replace(/^Error:\s*/, "");
}

function stepCredentials() {
  setStep(0);
  wizardHTML(`
    <h2 id="wizard-title">Add a new authenticator</h2>
    <p>This attaches a brand-new Steam Guard authenticator to your account and
       saves the .maFile here. Your account needs a verified phone number, and
       any authenticator currently on your phone will be replaced.</p>
    <p class="faint">Your password is used once to sign in and is never saved.</p>
    <label for="w-account">Steam account name</label>
    <input type="text" id="w-account" autocomplete="off" />
    <label for="w-password">Password</label>
    <input type="password" id="w-password" autocomplete="off" />
    <button class="btn primary" id="w-signin">Sign in</button>
    <button class="btn ghost" id="w-cancel">Cancel</button>`);

  const signIn = $("w-signin");
  $("w-cancel").onclick = () => closeDialog(el.wizard);
  signIn.onclick = () => guarded(signIn, async () => {
    const accountName = $("w-account").value.trim();
    const password = $("w-password").value;
    if (!accountName || !password) {
      setWizardError("Enter both your account name and password.");
      return;
    }
    const result = await invoke("begin_login", { accountName, password });
    if (result.needs_code) stepGuardCode(result.needs_code);
    else stepWaiting();
  });
  $("w-password").onkeydown = (e) => { if (e.key === "Enter") signIn.click(); };
  $("w-account").focus();
}

function stepGuardCode(codeType) {
  setStep(1);
  wizardHTML(`
    <h2 id="wizard-title">Steam Guard</h2>
    <p>${codeType === 2
      ? "Steam emailed you a code. Enter it below."
      : "Enter the code from the authenticator currently on your account."}</p>
    <label for="w-code">Steam Guard code</label>
    <input type="text" id="w-code" autocomplete="off" />
    <button class="btn primary" id="w-continue">Continue</button>`);

  const go = $("w-continue");
  go.onclick = () => guarded(go, async () => {
    const code = $("w-code").value.trim();
    if (!code) { setWizardError("Enter the code first."); return; }
    await invoke("submit_guard_code", { code, codeType });
    stepWaiting();
  });
  $("w-code").onkeydown = (e) => { if (e.key === "Enter") go.click(); };
  $("w-code").focus();
}

function stepWaiting() {
  setStep(1);
  wizardHTML(`
    <h2 id="wizard-title">Waiting for Steam</h2>
    <p>Confirming the sign-in. If Steam asked you to approve this in the mobile
       app or by email, do that now.</p>
    <div class="track" style="margin-top:24px"><div class="fill pulse"></div></div>
    <button class="btn ghost" id="w-cancel">Cancel</button>`);
  $("w-cancel").onclick = () => { wizard.cancelled = true; closeDialog(el.wizard); };

  wizard.cancelled = false;
  const deadline = Date.now() + 180000;
  (async function poll() {
    while (!wizard.cancelled && Date.now() < deadline) {
      try {
        if (await invoke("poll_login")) { stepConfirm(); return; }
      } catch (error) {
        setWizardError(String(error));
        return;
      }
      await new Promise((r) => setTimeout(r, 2500));
    }
    if (!wizard.cancelled) setWizardError("Timed out waiting for the login to be approved.");
  })();
}

async function stepConfirm() {
  setStep(2);
  const dir = await invoke("enrollment_target_dir");
  wizardHTML(`
    <h2 id="wizard-title">Ready to attach</h2>
    <p class="warn">The next step asks Steam to create the authenticator. From
       that moment Steam Guard codes for this account come from here, and you
       will need the revocation code shown next to undo it.</p>
    <p class="faint">Saving to ${dir}</p>
    <button class="btn primary" id="w-create">Create the authenticator</button>
    <button class="btn ghost" id="w-cancel">Cancel</button>`);

  const create = $("w-create");
  $("w-cancel").onclick = () => closeDialog(el.wizard);
  create.onclick = () => guarded(create, async () => {
    const result = await invoke("add_authenticator");
    wizard.saved = true;
    stepRevocation(result);
  });
}

function stepRevocation(result) {
  setStep(3);
  wizardHTML(`
    <h2 id="wizard-title">Write this down now</h2>
    <p class="plate">${result.revocation_code || "(none returned)"}</p>
    <p class="warn">This revocation code is the only way to remove the
       authenticator if you lose access. Steam will not show it again — write it
       somewhere that is not this computer.</p>
    <p class="faint">Saved to ${result.path}</p>
    <p>${result.phone_hint
      ? `Steam is sending a confirmation code to the phone ending ${result.phone_hint}.`
      : "Steam is sending a confirmation code by SMS or email."}</p>
    <label for="w-activation">Confirmation code</label>
    <input type="text" id="w-activation" autocomplete="off" />
    <div class="row" style="justify-content:flex-start">
      <button class="switch" id="w-ack" role="switch" aria-checked="false"
              aria-labelledby="w-ack-label"></button>
      <span id="w-ack-label">I have written down the revocation code</span>
    </div>
    <button class="btn primary" id="w-activate">Activate</button>`);

  const ack = $("w-ack");
  ack.onclick = () => ack.setAttribute("aria-checked",
    ack.getAttribute("aria-checked") === "true" ? "false" : "true");

  const activate = $("w-activate");
  activate.onclick = () => guarded(activate, async () => {
    if (ack.getAttribute("aria-checked") !== "true") {
      setWizardError("Confirm you have saved the revocation code first.");
      return;
    }
    const activationCode = $("w-activation").value.trim();
    if (!activationCode) {
      setWizardError("Enter the confirmation code Steam sent you.");
      return;
    }
    await invoke("finalize_authenticator", { activationCode });
    wizard.activated = true;
    stepDone(result);
  });
  $("w-activation").onkeydown = (e) => { if (e.key === "Enter") activate.click(); };
  $("w-activation").focus();
}

function stepDone(result) {
  setStep(3);
  wizardHTML(`
    <h2 id="wizard-title">Authenticator active</h2>
    <p style="color:var(--good);font-weight:600">Steam Guard codes for this
       account now come from this app.</p>
    <p>Account: ${result.account_name}</p>
    <p class="warn">Revocation code: ${result.revocation_code}</p>
    <p class="faint">File: ${result.path}</p>
    <button class="btn primary" id="w-done">Done</button>`);
  $("w-done").onclick = () => closeDialog(el.wizard);
}

el.wizard.addEventListener("close", () => {
  if (wizard.saved && !wizard.activated) {
    setStatus("Authenticator created but not activated — the .maFile with your " +
      "revocation code is saved.", "warn");
  }
  loadDefaults();
});

// Escape would close instantly and skip the exit animation, so take it over.
for (const dialog of [el.wizard, el.passkeyDialog]) {
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    // Never abandon an enrollment request that is still in flight.
    if (dialog === el.wizard && wizard.busy) return;
    closeDialog(dialog);
  });
}

// The webview's own context menu (Reload, Back, Inspect) does not belong in a
// desktop app. Text inputs keep theirs: right-click paste is genuinely useful
// when filling in a password from a manager, or an SMS code.
document.addEventListener("contextmenu", (event) => {
  if (event.target.closest("input, textarea")) return;
  event.preventDefault();
});

// Drag-and-drop of a file onto the window would navigate the webview away from
// the app entirely, leaving a blank frame with no way back.
for (const name of ["dragover", "drop"]) {
  document.addEventListener(name, (event) => event.preventDefault());
}

// -------------------------------------------------------------------- start

switchView("codes");
loadDefaults().then(syncTime);
tick();
