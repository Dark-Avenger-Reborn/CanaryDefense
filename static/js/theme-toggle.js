// Dark mode toggle functionality
function initThemeToggle() {
    const html = document.documentElement;
    const toggleBtn = document.getElementById('theme-toggle');
    
    // Load saved theme preference or check system preference
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
    
    // Apply theme
    applyTheme(initialTheme);
    
    // Listen for toggle button clicks
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const currentTheme = html.getAttribute('data-theme') || 'light';
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
            updateToggleIcon(newTheme);
        });
    }
    
    // If user has not explicitly chosen a theme, follow system preference updates.
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        const saved = localStorage.getItem('theme');
        if (!saved) {
            const newTheme = e.matches ? 'dark' : 'light';
            applyTheme(newTheme);
        }
    });
}

function applyTheme(theme) {
    const html = document.documentElement;
    html.setAttribute('data-theme', theme);
    html.style.colorScheme = theme;
    html.style.backgroundColor = theme === 'dark' ? '#0f172a' : '#f7fafc';
    updateToggleIcon(theme);
}

function updateToggleIcon(theme) {
    const toggleBtn = document.getElementById('theme-toggle');
    if (!toggleBtn) return;
    
    if (theme === 'dark') {
        toggleBtn.innerHTML = '☀️';
        toggleBtn.setAttribute('aria-label', 'Switch to light mode');
        toggleBtn.title = 'Light mode';
    } else {
        toggleBtn.innerHTML = '🌙';
        toggleBtn.setAttribute('aria-label', 'Switch to dark mode');
        toggleBtn.title = 'Dark mode';
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initThemeToggle);
} else {
    initThemeToggle();
}
