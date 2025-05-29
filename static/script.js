let darkMode = true;

function toggleSubmenu(id) {
  const submenu = document.getElementById(id);
  submenu.style.display = submenu.style.display === 'flex' ? 'none' : 'flex';
}

function loadPage(page) {
  fetch(`/page/${page}`)
    .then(res => res.text())
    .then(html => {
      document.getElementById('main').innerHTML = html;
    });
}

function toggleTheme() {
  darkMode = !darkMode;

  const root = document.documentElement;
  const isDark = darkMode;

  document.body.style.backgroundColor = isDark ? 'var(--bg-dark)' : 'var(--bg-light)';
  document.getElementById('main').style.backgroundColor = isDark ? 'var(--bg-dark)' : 'var(--bg-light)';
  document.getElementById('sidebar').style.backgroundColor = isDark ? 'var(--bg-dark)' : 'var(--bg-light)';
  document.body.style.color = isDark ? 'var(--text-dark)' : 'var(--text-light)';

  document.querySelectorAll('.menu-btn').forEach(btn => {
    btn.style.color = isDark ? 'var(--text-dark)' : 'var(--text-light)';
  });

  document.querySelector('.toggle-theme').style.color = isDark ? 'var(--text-dark)' : 'var(--text-light)';
  document.querySelector('.toggle-sidebar').style.color = isDark ? 'var(--text-dark)' : 'var(--text-light)';
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
}
console.log('JavaScript loaded!');