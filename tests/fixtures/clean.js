// CLEAN fixture — secure patterns only. Must produce zero findings.
function renderPreview(userInput) {
  const el = document.getElementById("preview");
  el.textContent = userInput; // safe sink
}

async function status() {
  // fixed allow-listed URL, no user input
  const res = await fetch("https://api.example.com/v1/status");
  return res.json();
}
