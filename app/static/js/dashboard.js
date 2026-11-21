(function () {
  "use strict";
  var css = function (name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); };
  var palette = ["#3ddc97", "#3aa0d9", "#d9a21b", "#d9534f", "#8e6bd9", "#e07bb4", "#7d8794", "#2fb4b4", "#c9803a", "#9aa84a"];
  var lastAlertId = 0;
  var charts = {};

  function el(tag, text, cls) {
    var n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  }
  function fmtTime(iso) {
    var d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function fmtHour(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function getJSON(url) {
    return fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) {
        if (r.status === 401 || r.redirected) { window.location.reload(); throw new Error("login"); }
        return r.json();
      });
  }
  function themeColors() {
    var dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    return { text: dark ? "#aab4c2" : "#4a5565", grid: dark ? "rgba(255,255,255,.08)" : "rgba(0,0,0,.08)" };
  }
  function applyTheme(chart) {
    var c = themeColors();
    Chart.defaults.color = c.text;
    Object.keys(chart.options.scales || {}).forEach(function (k) {
      var s = chart.options.scales[k];
      s.grid = s.grid || {}; s.grid.color = c.grid;
      s.ticks = s.ticks || {}; s.ticks.color = c.text;
    });
    chart.options.plugins.legend.labels.color = c.text;
    chart.update("none");
  }

  function makeCharts() {
    var c = themeColors();
    Chart.defaults.color = c.text;
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    charts.traffic = new Chart(document.getElementById("chart-traffic"), {
      type: "line",
      data: { labels: [], datasets: [
        { label: "From lab (Kbit/s)", data: [], borderColor: "#3ddc97", backgroundColor: "rgba(61,220,151,.15)", fill: true, tension: .25, pointRadius: 0, borderWidth: 2 },
        { label: "To lab (Kbit/s)", data: [], borderColor: "#3aa0d9", backgroundColor: "rgba(58,160,217,.12)", fill: true, tension: .25, pointRadius: 0, borderWidth: 2 }
      ] },
      options: { maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
        scales: { x: { grid: { color: c.grid }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, grid: { color: c.grid } } },
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } } }
    });
    charts.cat = new Chart(document.getElementById("chart-cat"), {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: palette, borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "62%",
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } } }
    });
    charts.timeline = new Chart(document.getElementById("chart-timeline"), {
      type: "bar",
      data: { labels: [], datasets: [{ label: "Alerts", data: [], backgroundColor: "#d9a21b", borderRadius: 3 }] },
      options: { maintainAspectRatio: false, animation: false,
        scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: c.grid } } },
        plugins: { legend: { display: false } } }
    });
  }

  function setPill(id, label, st) {
    var p = document.getElementById(id);
    p.textContent = label + ": " + (st.ok ? "running" : "not running");
    p.className = "badge rounded-pill text-bg-" + (st.ok ? "success" : "danger");
    p.title = st.detail || "";
  }

  function refreshSummary() {
    getJSON("/api/summary").then(function (s) {
      document.getElementById("s-total").textContent = s.total_24h;
      document.getElementById("s-open").textContent = s.open_24h;
      document.getElementById("s-high").textContent = s.high_24h;
      document.getElementById("s-dev").textContent = s.devices_active;
      document.getElementById("s-devtotal").textContent = s.devices_total;
      setPill("pill-suricata", "Suricata", s.status.suricata);
      setPill("pill-sensor", "Sensor", s.status.sensor);
      var cats = Object.keys(s.by_category);
      charts.cat.data.labels = cats;
      charts.cat.data.datasets[0].data = cats.map(function (k) { return s.by_category[k]; });
      charts.cat.update();
      charts.timeline.data.labels = s.timeline.map(function (p) { return fmtHour(p.t); });
      charts.timeline.data.datasets[0].data = s.timeline.map(function (p) { return p.n; });
      charts.timeline.update();
      var ul = document.getElementById("top-sources");
      ul.textContent = "";
      if (!s.top_sources.length) { ul.appendChild(el("li", "No alerts yet.", "text-secondary")); }
      s.top_sources.forEach(function (t) {
        var li = el("li", null, "d-flex justify-content-between border-bottom py-1");
        var a = el("a", t.ip); a.href = "/alerts?ip=" + encodeURIComponent(t.ip);
        li.appendChild(a); li.appendChild(el("span", t.n, "badge text-bg-secondary"));
        ul.appendChild(li);
      });
    }).catch(function () {});
  }

  function refreshTraffic() {
    var mins = document.getElementById("traffic-range").value;
    getJSON("/api/traffic?minutes=" + encodeURIComponent(mins)).then(function (rows) {
      charts.traffic.data.labels = rows.map(function (r) { return fmtTime(r.t); });
      charts.traffic.data.datasets[0].data = rows.map(function (r) { return r.rx_kbps; });
      charts.traffic.data.datasets[1].data = rows.map(function (r) { return r.tx_kbps; });
      charts.traffic.update("none");
    }).catch(function () {});
  }

  function addFeedRow(a, prepend) {
    var tb = document.getElementById("feed");
    var tr = document.createElement("tr");
    var tdTime = el("td", fmtTime(a.t), "text-nowrap");
    var tdSev = document.createElement("td");
    tdSev.appendChild(el("span", a.severity, "badge sev-" + a.severity));
    var tdSig = el("td", a.signature, "sig");
    var tdFlow = el("td", a.src + " → " + a.dst, "text-nowrap");
    tr.appendChild(tdTime); tr.appendChild(tdSev); tr.appendChild(el("td", a.category));
    tr.appendChild(tdSig); tr.appendChild(tdFlow);
    var a1 = document.createElement("a"); a1.href = "/alerts/" + a.id; a1.className = "link-body-emphasis";
    a1.textContent = a.signature; tdSig.textContent = ""; tdSig.appendChild(a1);
    if (prepend) { tb.insertBefore(tr, tb.firstChild); } else { tb.appendChild(tr); }
    while (tb.children.length > 40) { tb.removeChild(tb.lastChild); }
  }

  function refreshFeed(first) {
    getJSON("/api/alerts/latest?after=" + lastAlertId).then(function (rows) {
      var tb = document.getElementById("feed");
      if (rows.length && tb.querySelector("td[colspan]")) { tb.textContent = ""; }
      if (first && !rows.length) {
        tb.textContent = ""; var tr = document.createElement("tr");
        var td = el("td", "No alerts yet.", "text-secondary"); td.colSpan = 5; tr.appendChild(td); tb.appendChild(tr);
      }
      rows.forEach(function (a) {
        addFeedRow(a, !first);
        if (a.id > lastAlertId) lastAlertId = a.id;
      });
      if (first) {
        // first load arrives oldest -> newest; show newest on top
        var items = Array.prototype.slice.call(tb.children).reverse();
        tb.textContent = ""; items.forEach(function (n) { tb.appendChild(n); });
      }
    }).catch(function () {});
  }

  document.addEventListener("DOMContentLoaded", function () {
    makeCharts();
    refreshSummary(); refreshTraffic(); refreshFeed(true);
    setInterval(refreshSummary, 10000);
    setInterval(refreshTraffic, 5000);
    setInterval(function () { refreshFeed(false); }, 4000);
    document.getElementById("traffic-range").addEventListener("change", refreshTraffic);
    document.addEventListener("themechange", function () { Object.keys(charts).forEach(function (k) { applyTheme(charts[k]); }); });
  });
})();
