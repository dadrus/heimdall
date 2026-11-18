// Preserve the documentation menu's scroll position across full page loads.
// The menu and links stay usable without JavaScript or sessionStorage.
(() => {
    // The header also renders this menu in a mobile offcanvas. Only the
    // desktop sidebar has its own scrollable navigation.
    const menu = document.querySelector('.docs-layout > .docs-sidebar .docs-menu-container > nav')
    if (!menu || !menu.getClientRects().length) return

    const key = `heimdall:docs-menu-scroll:${menu.dataset.scrollKey}`
    try {
        const stored = sessionStorage.getItem(key)
        const offset = Number(stored)
        if (stored !== null && Number.isFinite(offset) && offset >= 0) {
            menu.scrollTop = offset
        }
    } catch {
        // Storage can be disabled; active-link visibility still works.
    }

    const active = menu.querySelector('a.active')
    if (!active || active === menu.querySelector('a')) {
        // Overview pages and the first menu entry should start at the top,
        // not inherit a deep scroll position from another page.
        menu.scrollTop = 0
    } else {
        // Keep the saved context when possible, but always reveal the active
        // page if it falls outside the visible menu (including the fades).
        const viewport = menu.getBoundingClientRect()
        const entry = active.getBoundingClientRect()
        const fade = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16
        if (entry.top < viewport.top + fade) {
            menu.scrollTop -= viewport.top + fade - entry.top
        } else if (entry.bottom > viewport.bottom - fade) {
            menu.scrollTop += entry.bottom - viewport.bottom + fade
        }
    }

    window.addEventListener('pagehide', () => {
        try {
            sessionStorage.setItem(key, String(menu.scrollTop))
        } catch {
            // Persisting the position is optional.
        }
    })
})()
