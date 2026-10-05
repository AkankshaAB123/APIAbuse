document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  
  const typeText = params.get('type') || 'Unknown Threat';
  const urlText = params.get('url') || 'Unknown URL';
  
  document.getElementById('threat-type').innerText = typeText;
  document.getElementById('threat-url').innerText = urlText;
  
  document.getElementById('back-button').addEventListener('click', () => {
    window.history.back();
  });
});
