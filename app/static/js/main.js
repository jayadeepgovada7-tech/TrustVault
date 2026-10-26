// Trust vault — Client Helpers & Theme Engine
// Theme is applied before paint via an inline script in base.html (no FOUC).
// This file handles: dropdown UI, OS preference listener, auto-dismiss alerts.

(function () {
    'use strict';

    // ── Theme constants ──────────────────────────────────────────────────────
    var STORAGE_KEY = 'tv_theme';   // 'light' | 'dark'
    var HTML_EL     = document.documentElement;

    /**
     * Resolve the effective Bootstrap theme ('light'|'dark') from the
     * stored preference. 'system' follows window.matchMedia.
     */
    function resolveTheme(pref) {
        return pref === 'dark' ? 'dark' : 'light';
    }

    /** Apply the theme to <html> and sync the toggle UI. */
    function applyTheme(pref) {
        var effective = resolveTheme(pref);
        HTML_EL.setAttribute('data-bs-theme', effective);
        localStorage.setItem(STORAGE_KEY, pref);
        syncToggleUI(pref);
    }

    /** Update the navbar toggle label and check-marks. */
    function syncToggleUI(pref) {
        var labels = { light: 'Light', dark: 'Dark' };
        var icons  = { light: 'bi-sun-fill', dark: 'bi-moon-fill' };

        var btn = document.getElementById('tv-theme-btn');
        if (btn) {
            var iconEl = btn.querySelector('i');
            if (iconEl) {
                iconEl.className = 'bi ' + (icons[pref] || icons.light);
            }
            var labelEl = btn.querySelector('.tv-theme-label');
            if (labelEl) {
                labelEl.textContent = labels[pref] || 'Light';
            }
        }

        // Highlight the active dropdown item
        document.querySelectorAll('.theme-menu .dropdown-item').forEach(function (el) {
            if (el.dataset.theme === pref) {
                el.classList.add('active');
            } else {
                el.classList.remove('active');
            }
        });
    }

    // ── Wire dropdown items ──────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {

        // Theme menu items
        var themeButton = document.getElementById('tv-theme-btn');
        if (themeButton) {
            themeButton.addEventListener('click', function () {
                var current = localStorage.getItem(STORAGE_KEY) || 'light';
                applyTheme(current === 'dark' ? 'light' : 'dark');
            });
        }

        // Sync UI on load; theme preference is saved across visits.
        var stored = localStorage.getItem(STORAGE_KEY) || 'light';
        applyTheme(stored);

        // ── Auto-dismiss flash alerts after 6 seconds ────────────────────────
        setTimeout(function () {
            document.querySelectorAll('.alert-dismissible').forEach(function (alert) {
                var bsAlert = bootstrap.Alert.getInstance(alert);
                if (bsAlert) bsAlert.close();
            });
        }, 6000);
    });

})();
