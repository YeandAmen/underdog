(() => {
  try {
    const theme = localStorage.getItem('identityshield-theme');
    document.documentElement.dataset.theme = theme || 'light';
  } catch {
    document.documentElement.dataset.theme = 'light';
  }
})();
