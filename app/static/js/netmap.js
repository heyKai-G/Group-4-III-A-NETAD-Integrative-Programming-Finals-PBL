(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var svg = document.getElementById("netmap");
  var info = document.getElementById("map-info");
  var W = 900, H = 560, CX = W / 2, CY = H / 2;

  function s(tag, attrs, text) {
    var n = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function color(n) {
    if (n.gateway) return "#3aa0d9";
    if (n.attacker_alerts > 0) return "#d9534f";
    if (n.target_alerts > 0) return "#d9a21b";
    return n.active ? "#3ddc97" : "#7d8794";
  }
  function describe(n) {
    var parts = [n.ip || "(no IP)", n.mac];
    if (n.hostname) parts.push(n.hostname);
    parts.push(n.active ? "active" : "idle");
    if (n.gateway) parts.push("gateway");
    if (n.attacker_alerts) parts.push(n.attacker_alerts + " alert(s) as source in the last hour");
    if (n.target_alerts) parts.push(n.target_alerts + " alert(s) as target in the last hour");
    return parts.join(" - ");
  }

  function draw(data) {
    svg.textContent = "";
    var gw = null, others = [];
    data.nodes.forEach(function (n) { if (n.gateway && !gw) gw = n; else others.push(n); });
    var gx = CX, gy = 70, idsX = CX, idsY = CY - 20;

    // IDS laptop (centre)
    var ids = { x: idsX, y: idsY };
    var links = s("g"), nodes = s("g");
    svg.appendChild(links); svg.appendChild(nodes);

    // gateway node
    links.appendChild(s("line", { x1: gx, y1: gy, x2: idsX, y2: idsY }));
    var gnode = s("g", { "class": "node", transform: "translate(" + gx + "," + gy + ")" });
    gnode.appendChild(s("circle", { r: 24, fill: "#3aa0d9" }));
    gnode.appendChild(s("text", { y: 42, "text-anchor": "middle" }, (data.gateway || "Gateway")));
    gnode.appendChild(s("text", { y: -32, "text-anchor": "middle" }, "Router"));
    gnode.addEventListener("mouseenter", function () { info.textContent = gw ? describe(gw) : "Gateway " + data.gateway + " (not seen yet)"; });
    nodes.appendChild(gnode);

    var inode = s("g", { "class": "node", transform: "translate(" + idsX + "," + idsY + ")" });
    inode.appendChild(s("rect", { x: -28, y: -20, width: 56, height: 40, rx: 8, fill: "#8e6bd9" }));
    inode.appendChild(s("text", { y: 38, "text-anchor": "middle" }, "IDS laptop"));
    inode.addEventListener("mouseenter", function () { info.textContent = "IDS laptop - traffic crossing this machine is monitored."; });
    nodes.appendChild(inode);

    // devices on a ring below
    var n = others.length, r = Math.min(210, 90 + n * 8);
    others.forEach(function (d, i) {
      var ang = Math.PI * (0.12 + 0.76 * (n === 1 ? 0.5 : i / (n - 1)));
      var x = CX + Math.cos(ang) * r * 1.9 * (n === 1 ? 0 : 1);
      var y = idsY + 70 + Math.sin(ang) * r * 0.95;
      if (n === 1) { x = CX; y = idsY + 150; }
      var line = s("line", { x1: idsX, y1: idsY, x2: x, y2: y });
      if (d.attacker_alerts > 0) line.setAttribute("class", "hot");
      links.appendChild(line);
      var g = s("g", { "class": "node", transform: "translate(" + x + "," + y + ")", tabindex: 0 });
      g.appendChild(s("circle", { r: 15, fill: color(d) }));
      g.appendChild(s("text", { y: 30, "text-anchor": "middle" }, d.hostname || d.ip || d.mac));
      g.addEventListener("mouseenter", function () { info.textContent = describe(d); });
      g.addEventListener("click", function () { info.textContent = describe(d); });
      g.addEventListener("focus", function () { info.textContent = describe(d); });
      nodes.appendChild(g);
    });
    if (!n) { info.textContent = "No devices seen yet. They appear once the sensor learns them from ARP/DHCP/traffic."; }
  }

  function load() {
    fetch("/api/network", { credentials: "same-origin" }).then(function (r) { return r.json(); })
      .then(draw).catch(function () {});
  }
  load(); setInterval(load, 10000);
})();
