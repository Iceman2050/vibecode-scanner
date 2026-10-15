// VULNERABLE fixture — fires VC-009.
function renderPreview(userInput) {
  const el = document.getElementById("preview");
  // VC-009 — untrusted input straight into innerHTML
  el.innerHTML = location.hash;
  document.write(userInput);
}
