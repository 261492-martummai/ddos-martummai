      // ── Session guard — redirect to login if not authenticated ──
      (async () => {
        try {
          const res = await fetch("/auth/me", { credentials: "include" });
          if (!res.ok) window.location.replace("/login");
        } catch {
          window.location.replace("/login");
        }
      })();

      // ── Logout ────────────────────────────────────────────
      document
        .getElementById("logout-btn")
        .addEventListener("click", async () => {
          await fetch("/auth/logout", {
            method: "POST",
            credentials: "include",
          });
          window.location.replace("/login");
        });

      // ── Clock ──────────────────────────────────────────────
      const clockEl = document.getElementById("clock");
      setInterval(() => {
        clockEl.textContent = new Date().toLocaleTimeString("en-GB", {
          hour12: false,
        });
      }, 1000);

      // ── Chart defaults ────────────────────────────────────
      Chart.defaults.color = "#4a7090";
      Chart.defaults.borderColor = "#0f2744";
      Chart.defaults.font.family = "'Share Tech Mono', monospace";
      Chart.defaults.font.size = 10;

      const ACCENT = "#00ffe7";
      const ACCENT2 = "#ff6b35";

      // ── Bandwidth chart ───────────────────────────────────
      // Tracks a sliding dynamic Y-axis: max stays just above the current peak,
      // but decays smoothly when traffic drops — so the line always fills the chart.
      let yMax = 1000; // current Y ceiling (animates toward target)
      let yTarget = 1000; // next target ceiling

      const TCP_COLOR = "#00ffe7"; // cyan
      const UDP_COLOR = "#ff6b35"; // orange

      const bwChart = new Chart(document.getElementById("bw"), {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "TCP",
              data: [],
              borderColor: TCP_COLOR,
              borderWidth: 2,
              tension: 0.35,
              fill: true,
              backgroundColor: (ctx) => {
                const g = ctx.chart.ctx.createLinearGradient(
                  0,
                  0,
                  0,
                  ctx.chart.height,
                );
                g.addColorStop(0, "rgba(0,255,231,0.2)");
                g.addColorStop(1, "rgba(0,255,231,0.0)");
                return g;
              },
              pointRadius: 0,
              pointHoverRadius: 4,
              pointHoverBackgroundColor: TCP_COLOR,
            },
            {
              label: "UDP",
              data: [],
              borderColor: UDP_COLOR,
              borderWidth: 2,
              tension: 0.35,
              fill: true,
              backgroundColor: (ctx) => {
                const g = ctx.chart.ctx.createLinearGradient(
                  0,
                  0,
                  0,
                  ctx.chart.height,
                );
                g.addColorStop(0, "rgba(255,107,53,0.2)");
                g.addColorStop(1, "rgba(255,107,53,0.0)");
                return g;
              },
              pointRadius: 0,
              pointHoverRadius: 4,
              pointHoverBackgroundColor: UDP_COLOR,
            },
          ],
        },
        options: {
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: {
              display: true,
              position: "top",
              align: "end",
              labels: {
                boxWidth: 12,
                boxHeight: 12,
                padding: 10,
                font: { size: 10, family: "'Share Tech Mono', monospace" },
                color: "#4a7090",
                usePointStyle: true,
              },
            },
            tooltip: {
              backgroundColor: "#080f1c",
              borderColor: "#0f2744",
              borderWidth: 1,
              titleColor: "#4a7090",
              bodyColor: ACCENT,
              callbacks: {
                label: (ctx) =>
                  ` ${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()} B/s`,
              },
            },
          },
          scales: {
            x: {
              grid: { color: "rgba(15,39,68,0.8)" },
              ticks: { maxTicksLimit: 10, color: "#4a7090" },
              title: { display: true, text: "Time (s)", color: "#4a7090" },
            },
            y: {
              min: 0,
              // max is updated dynamically below
              grid: { color: "rgba(15,39,68,0.8)" },
              ticks: {
                color: "#4a7090",
                callback: (v) => (v >= 1000 ? (v / 1000).toFixed(1) + "k" : v),
              },
              title: { display: true, text: "Bytes/s", color: "#4a7090" },
            },
          },
        },
      });

      // Smoothly nudge yMax toward yTarget each frame (ease-out)
      function tickYAxis() {
        const diff = yTarget - yMax;
        if (Math.abs(diff) > 1) {
          yMax += diff * 0.08; // 8% of gap per frame ≈ smooth decay
          bwChart.options.scales.y.max = Math.ceil(yMax);
          bwChart.update("none"); // redraw without animation
        }
        requestAnimationFrame(tickYAxis);
      }
      requestAnimationFrame(tickYAxis);

      // ── Request Rate chart ────────────────────────────────
      let yMaxRate = 100; // current Y ceiling for rate
      let yTargetRate = 100; // next target ceiling for rate

      const rateChart = new Chart(document.getElementById("rate"), {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "TCP",
              data: [],
              borderColor: TCP_COLOR,
              borderWidth: 2,
              tension: 0.35,
              fill: true,
              backgroundColor: (ctx) => {
                const g = ctx.chart.ctx.createLinearGradient(
                  0,
                  0,
                  0,
                  ctx.chart.height,
                );
                g.addColorStop(0, "rgba(0,255,231,0.2)");
                g.addColorStop(1, "rgba(0,255,231,0.0)");
                return g;
              },
              pointRadius: 0,
              pointHoverRadius: 4,
              pointHoverBackgroundColor: TCP_COLOR,
            },
            {
              label: "UDP",
              data: [],
              borderColor: UDP_COLOR,
              borderWidth: 2,
              tension: 0.35,
              fill: true,
              backgroundColor: (ctx) => {
                const g = ctx.chart.ctx.createLinearGradient(
                  0,
                  0,
                  0,
                  ctx.chart.height,
                );
                g.addColorStop(0, "rgba(255,107,53,0.2)");
                g.addColorStop(1, "rgba(255,107,53,0.0)");
                return g;
              },
              pointRadius: 0,
              pointHoverRadius: 4,
              pointHoverBackgroundColor: UDP_COLOR,
            },
          ],
        },
        options: {
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: {
              display: true,
              position: "top",
              align: "end",
              labels: {
                boxWidth: 12,
                boxHeight: 12,
                padding: 10,
                font: { size: 10, family: "'Share Tech Mono', monospace" },
                color: "#4a7090",
                usePointStyle: true,
              },
            },
            tooltip: {
              backgroundColor: "#080f1c",
              borderColor: "#0f2744",
              borderWidth: 1,
              titleColor: "#4a7090",
              callbacks: {
                label: (ctx) =>
                  ` ${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()} pkt/s`,
              },
            },
          },
          scales: {
            x: {
              grid: { color: "rgba(15,39,68,0.8)" },
              ticks: { maxTicksLimit: 10, color: "#4a7090" },
              title: { display: true, text: "Time (s)", color: "#4a7090" },
            },
            y: {
              min: 0,
              grid: { color: "rgba(15,39,68,0.8)" },
              ticks: { color: "#4a7090" },
              title: { display: true, text: "Packets/s", color: "#4a7090" },
            },
          },
        },
      });

      // Smoothly nudge yMaxRate toward yTargetRate each frame
      function tickYAxisRate() {
        const diff = yTargetRate - yMaxRate;
        if (Math.abs(diff) > 1) {
          yMaxRate += diff * 0.08;
          rateChart.options.scales.y.max = Math.ceil(yMaxRate);
          rateChart.update("none");
        }
        requestAnimationFrame(tickYAxisRate);
      }
      requestAnimationFrame(tickYAxisRate);

      // ── Port chart ────────────────────────────────────────
      const portChart = new Chart(document.getElementById("ports"), {
        type: "bar",
        data: {
          labels: [],
          datasets: [
            {
              label: "Packets",
              data: [],
              backgroundColor: [],
              borderRadius: 2,
              barThickness: 18,
              maxBarThickness: 22,
            },
          ],
        },
        options: {
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#080f1c",
              borderColor: "#0f2744",
              borderWidth: 1,
              bodyColor: ACCENT2,
            },
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: "#4a7090" },
              title: { display: true, text: "Port", color: "#4a7090" },
            },
            y: {
              min: 0,
              grid: { color: "rgba(15,39,68,0.8)" },
              ticks: { stepSize: 1, color: "#4a7090" },
              title: { display: true, text: "Count", color: "#4a7090" },
            },
          },
        },
      });

      // ── Table helper ──────────────────────────────────────
      const tableBody = document.getElementById("flow-table");

      function renderTable(rows) {
        const html = rows
          .map(
            (p, i) => `
        <tr class="${i === 0 ? "new-row" : ""}">
          <td>${p.time}</td>
          <td>${p.src}</td>
          <td>${p.dst}</td>
          <td>${p.port}</td>
          <td>${p.packets}</td>
          <td>${p.bytes}</td>
          <td>${p.syn}</td>
          <td>${p.ack}</td>
          <td>${p.psh}</td>
          <td>${p.rst}</td>
          <td>${p.fin}</td>
          <td>${p.start}</td>
          <td>${p.duration}</td>
        </tr>`,
          )
          .join("");
        tableBody.innerHTML = html;
      }

      // ── WebSocket ─────────────────────────────────────────
      const statusEl = document.getElementById("ws-status");

      function connect() {
        const ws = new WebSocket("ws://localhost:8000/ws");

        ws.onopen = () => {
          statusEl.textContent = "LIVE";
          statusEl.style.color = "var(--accent)";
        };

        ws.onclose = () => {
          statusEl.textContent = "RECONNECTING...";
          statusEl.style.color = "var(--accent2)";
          setTimeout(connect, 2000); // auto-reconnect
        };

        ws.onerror = () => ws.close();

        ws.onmessage = (e) => {
          const data = JSON.parse(e.data);

          // ── bandwidth: update data + compute new Y target ──
          bwChart.data.labels = data.bw_labels;
          bwChart.data.datasets[0].data = data.bandwidth_tcp; // TCP
          bwChart.data.datasets[1].data = data.bandwidth_udp; // UDP

          const peakTcp = Math.max(...data.bandwidth_tcp, 0);
          const peakUdp = Math.max(...data.bandwidth_udp, 0);
          const peak = Math.max(peakTcp, peakUdp);

          // Target = peak + 20% headroom, floored at 500 so chart never collapses
          yTarget = Math.max(500, peak * 1.2);
          bwChart.update("none");

          // ── request rate: update data + compute new Y target ──
          rateChart.data.labels = data.bw_labels;
          rateChart.data.datasets[0].data = data.pkt_rate_tcp; // TCP
          rateChart.data.datasets[1].data = data.pkt_rate_udp; // UDP

          const peakRateTcp = Math.max(...data.pkt_rate_tcp, 0);
          const peakRateUdp = Math.max(...data.pkt_rate_udp, 0);
          const peakRate = Math.max(peakRateTcp, peakRateUdp);

          yTargetRate = Math.max(50, peakRate * 1.2);
          rateChart.update("none");

          // ── ports ──────────────────────────────────────────
          const portKeys = Object.keys(data.ports);
          const portVals = Object.values(data.ports);
          const portColors = portKeys.map(
            (p) => `hsl(${(p * 47) % 360},70%,55%)`,
          );

          portChart.data.labels = portKeys;
          portChart.data.datasets[0].data = portVals;
          portChart.data.datasets[0].backgroundColor = portColors;

          // Nudge Y max to current data max + 2
          const portMax = Math.max(...portVals, 5);
          portChart.options.scales.y.max = portMax + 2;
          portChart.update("none");

          // ── table ──────────────────────────────────────────
          renderTable(data.table);
        };
      }

      // ── Theme toggle ──────────────────────────────────────
      const THEMES = {
        dark: {
          label: "DARK",
          icon: "🌙",
          accent: "#00ffe7",
          accent2: "#ff6b35",
          gridColor: "rgba(15,39,68,0.8)",
          tickColor: "#4a7090",
          tooltipBg: "#080f1c",
          tooltipBorder: "#0f2744",
          tcpColor: "#00ffe7",
          udpColor: "#ff6b35",
          tcpGrad0: "rgba(0,255,231,0.2)",
          tcpGrad1: "rgba(0,255,231,0.0)",
          udpGrad0: "rgba(255,107,53,0.2)",
          udpGrad1: "rgba(255,107,53,0.0)",
          tooltipTitle: "#4a7090", // สีหัวข้อ tooltip (เทาอ่อน)
          tooltipBody: "#c8ddf0", // สีเนื้อหา tooltip (ขาวอมฟ้า)
        },
        light: {
          label: "LIGHT",
          icon: "☀️",
          accent: "#0077aa",
          accent2: "#d45000",
          gridColor: "rgba(180,200,220,0.6)",
          tickColor: "#6a8aaa",
          tooltipBg: "#ffffff",
          tooltipBorder: "#c8d8e8",
          tooltipTitle: "#6a8aaa", // สีหัวข้อ (เทาฟ้า)
          tooltipBody: "#1a2a3a", // สีเนื้อหา (เทาเข้ม)
          tcpColor: "#0077aa",
          udpColor: "#d45000",
          tcpGrad0: "rgba(0,119,170,0.15)",
          tcpGrad1: "rgba(0,119,170,0.0)",
          udpGrad0: "rgba(212,80,0,0.15)",
          udpGrad1: "rgba(212,80,0,0.0)",
        },
      };

      let currentTheme = "dark";

      function applyChartTheme(t) {
        const cfg = THEMES[t];

        // Global chart defaults
        Chart.defaults.color = cfg.tickColor;
        Chart.defaults.borderColor = cfg.gridColor;

        // Bandwidth chart — TCP line
        bwChart.data.datasets[0].borderColor = cfg.tcpColor;
        bwChart.data.datasets[0].pointHoverBackgroundColor = cfg.tcpColor;
        bwChart.data.datasets[0].backgroundColor = (ctx) => {
          const g = ctx.chart.ctx.createLinearGradient(
            0,
            0,
            0,
            ctx.chart.height,
          );
          g.addColorStop(0, cfg.tcpGrad0);
          g.addColorStop(1, cfg.tcpGrad1);
          return g;
        };

        // Bandwidth chart — UDP line
        bwChart.data.datasets[1].borderColor = cfg.udpColor;
        bwChart.data.datasets[1].pointHoverBackgroundColor = cfg.udpColor;
        bwChart.data.datasets[1].backgroundColor = (ctx) => {
          const g = ctx.chart.ctx.createLinearGradient(
            0,
            0,
            0,
            ctx.chart.height,
          );
          g.addColorStop(0, cfg.udpGrad0);
          g.addColorStop(1, cfg.udpGrad1);
          return g;
        };

        // Bandwidth chart — other properties
        bwChart.options.plugins.legend.labels.color = cfg.tickColor;
        bwChart.options.plugins.tooltip.backgroundColor = cfg.tooltipBg;
        bwChart.options.plugins.tooltip.borderColor = cfg.tooltipBorder;
        bwChart.options.plugins.tooltip.titleColor = cfg.tooltipTitle;
        bwChart.options.plugins.tooltip.bodyColor = cfg.tooltipBody;
        bwChart.options.scales.x.grid.color = cfg.gridColor;
        bwChart.options.scales.x.ticks.color = cfg.tickColor;
        bwChart.options.scales.x.title.color = cfg.tickColor;
        bwChart.options.scales.y.grid.color = cfg.gridColor;
        bwChart.options.scales.y.ticks.color = cfg.tickColor;
        bwChart.options.scales.y.title.color = cfg.tickColor;
        bwChart.update("none");

        // Rate chart — TCP line
        rateChart.data.datasets[0].borderColor = cfg.tcpColor;
        rateChart.data.datasets[0].pointHoverBackgroundColor = cfg.tcpColor;
        rateChart.data.datasets[0].backgroundColor = (ctx) => {
          const g = ctx.chart.ctx.createLinearGradient(
            0,
            0,
            0,
            ctx.chart.height,
          );
          g.addColorStop(0, cfg.tcpGrad0);
          g.addColorStop(1, cfg.tcpGrad1);
          return g;
        };

        // Rate chart — UDP line
        rateChart.data.datasets[1].borderColor = cfg.udpColor;
        rateChart.data.datasets[1].pointHoverBackgroundColor = cfg.udpColor;
        rateChart.data.datasets[1].backgroundColor = (ctx) => {
          const g = ctx.chart.ctx.createLinearGradient(
            0,
            0,
            0,
            ctx.chart.height,
          );
          g.addColorStop(0, cfg.udpGrad0);
          g.addColorStop(1, cfg.udpGrad1);
          return g;
        };

        // Rate chart — other properties
        rateChart.options.plugins.legend.labels.color = cfg.tickColor;
        rateChart.options.plugins.tooltip.backgroundColor = cfg.tooltipBg;
        rateChart.options.plugins.tooltip.borderColor = cfg.tooltipBorder;
        rateChart.options.plugins.tooltip.titleColor = cfg.tooltipTitle;
        rateChart.options.plugins.tooltip.bodyColor = cfg.tooltipBody;
        rateChart.options.scales.x.grid.color = cfg.gridColor;
        rateChart.options.scales.x.ticks.color = cfg.tickColor;
        rateChart.options.scales.x.title.color = cfg.tickColor;
        rateChart.options.scales.y.grid.color = cfg.gridColor;
        rateChart.options.scales.y.ticks.color = cfg.tickColor;
        rateChart.options.scales.y.title.color = cfg.tickColor;
        rateChart.update("none");

        // Port chart
        portChart.options.plugins.tooltip.backgroundColor = cfg.tooltipBg;
        portChart.options.plugins.tooltip.borderColor = cfg.tooltipBorder;
        portChart.options.plugins.tooltip.bodyColor = cfg.accent2;
        portChart.options.plugins.tooltip.titleColor = cfg.tooltipTitle;
        portChart.options.plugins.tooltip.bodyColor = cfg.tooltipBody;
        portChart.options.scales.x.ticks.color = cfg.tickColor;
        portChart.options.scales.x.title.color = cfg.tickColor;
        portChart.options.scales.y.grid.color = cfg.gridColor;
        portChart.options.scales.y.ticks.color = cfg.tickColor;
        portChart.options.scales.y.title.color = cfg.tickColor;
        portChart.update("none");
      }

      function toggleTheme() {
        currentTheme = currentTheme === "dark" ? "light" : "dark";
        const cfg = THEMES[currentTheme];

        // Toggle class on <html> — all CSS vars flip instantly
        document.documentElement.classList.toggle(
          "light",
          currentTheme === "light",
        );

        // Update button label + icon
        document.querySelector("#theme-btn .icon").textContent = cfg.icon;
        document.querySelector("#theme-btn .label").textContent = cfg.label;

        // Sync chart colours
        applyChartTheme(currentTheme);

        // Persist preference
        localStorage.setItem("nm-theme", currentTheme);
      }

      document
        .getElementById("theme-btn")
        .addEventListener("click", toggleTheme);

      // Restore saved preference on load
      const savedTheme = localStorage.getItem("nm-theme");
      if (savedTheme && savedTheme !== currentTheme) toggleTheme();

      connect();