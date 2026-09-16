document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get({ threats: [] }, (data) => {
    const list = document.getElementById('threat-list');
    
    if (data.threats.length > 0) {
      list.innerHTML = '';
      data.threats.forEach(t => {
        const div = document.createElement('div');
        div.className = 'threat-item';
        div.innerHTML = `
          <div class="threat-type">${t.type} <span style="color:#888; font-weight:normal;">at ${t.time}</span></div>
          <div class="threat-url" title="${t.url}">${t.url}</div>
        `;
        list.appendChild(div);
      });
    }
  });
});
