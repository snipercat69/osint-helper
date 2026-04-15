const modeEl = document.getElementById("mode");
const formEl = document.getElementById("osintForm");
const singleRow = document.getElementById("singleRow");
const iocRow = document.getElementById("iocRow");
const probeRow = document.getElementById("probeRow");
const valueEl = document.getElementById("value");
const indicatorsEl = document.getElementById("indicators");
const probeEl = document.getElementById("probe");
const textOutEl = document.getElementById("textOut");
const jsonOutEl = document.getElementById("jsonOut");
const copyBtn = document.getElementById("copyBtn");
const sampleBtn = document.getElementById("sampleBtn");
const runBtn = document.getElementById("runBtn");

const MODE_PLACEHOLDERS = {
  username: "snipercat1822",
  domain: "example.com",
  ip: "8.8.8.8",
  email: "analyst@example.com",
  phone: "+15551234567",
  asn: "AS15169",
};

function updateModeUi() {
  const mode = modeEl.value;
  const ioc = mode === "ioc";
  const username = mode === "username";

  singleRow.classList.toggle("hidden", ioc);
  iocRow.classList.toggle("hidden", !ioc);
  probeRow.classList.toggle("hidden", !username);

  if (!ioc) {
    valueEl.placeholder = MODE_PLACEHOLDERS[mode] || "value";
  }
}

function loadSample() {
  const mode = modeEl.value;
  if (mode === "ioc") {
    indicatorsEl.value = [
      "google.com",
      "8.8.8.8",
      "xpoejay@gmail.com",
      "https://example.com/login",
    ].join("\n");
    return;
  }
  valueEl.value = MODE_PLACEHOLDERS[mode] || "";
  if (mode === "username") {
    probeEl.checked = false;
  }
}

async function runQuery(ev) {
  ev.preventDefault();
  runBtn.disabled = true;
  runBtn.textContent = "Running...";
  textOutEl.textContent = "Working...";

  try {
    const mode = modeEl.value;
    const payload = { mode };

    if (mode === "ioc") {
      const lines = indicatorsEl.value
        .split(/\n|,/g)
        .map((s) => s.trim())
        .filter(Boolean);
      payload.indicators = lines;
    } else {
      payload.value = valueEl.value.trim();
      if (mode === "username") {
        payload.probe = !!probeEl.checked;
      }
    }

    const resp = await fetch("/api/osint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await resp.json();
    jsonOutEl.textContent = JSON.stringify(data, null, 2);

    if (!resp.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }

    textOutEl.textContent = data.text || "(no output)";
  } catch (err) {
    textOutEl.textContent = `Error: ${err.message}`;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run";
  }
}

async function copyOutput() {
  try {
    await navigator.clipboard.writeText(textOutEl.textContent || "");
    copyBtn.textContent = "Copied";
    setTimeout(() => {
      copyBtn.textContent = "Copy text";
    }, 900);
  } catch {
    copyBtn.textContent = "Copy failed";
    setTimeout(() => {
      copyBtn.textContent = "Copy text";
    }, 900);
  }
}

modeEl.addEventListener("change", updateModeUi);
formEl.addEventListener("submit", runQuery);
sampleBtn.addEventListener("click", loadSample);
copyBtn.addEventListener("click", copyOutput);

updateModeUi();
