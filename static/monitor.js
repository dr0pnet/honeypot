setInterval(async () => {
  const res = await fetch('/api/monitor_stats');
  const data = await res.json();

  document.getElementById('cpu-line').innerText = `├─ CPU Usage: ${data.cpu}%`;
  document.getElementById('ram-line').innerText = `├─ RAM Usage: ${data.ram_used} / ${data.ram_total} GB`;
  document.getElementById('disk-line').innerText = `├─ Disk Usage: ${data.disk}`;
  document.getElementById('uptime-line').innerText = `├─ Uptime: ${data.uptime}`;
  document.getElementById('trap-line').innerText = `└─ Active Traps: ${data.active_traps} / 8`;
}, 5000);
