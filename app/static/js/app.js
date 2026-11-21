(function () {
  "use strict";
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("labids-theme", next); } catch (e) {}
      document.dispatchEvent(new CustomEvent("themechange"));
    });
  });
})();

// "Print" button on the recovery-codes page (inline scripts are blocked by the CSP)
document.querySelectorAll("[data-print]").forEach(function (btn) {
  btn.addEventListener("click", function () { window.print(); });
});
