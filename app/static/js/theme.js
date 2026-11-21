/* Runs in <head> so the saved theme is applied before the page paints. */
(function () {
  var theme = "dark";
  try { theme = localStorage.getItem("labids-theme") || "dark"; } catch (e) {}
  document.documentElement.setAttribute("data-bs-theme", theme);
})();
