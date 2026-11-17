// Preserve the documentation menu's scroll position across full page loads.
// The menu and links stay usable without JavaScript or sessionStorage.
(() => {
    // The header also renders this menu in a mobile offcanvas. Only the
    // desktop sidebar has its own scrollable navigation.
    const menu = document.querySelector('.docs-layout > .docs-sidebar .docs-menu-container > nav')
    if (!menu || !menu.getClientRects().length) return

    const key = `heimdall:docs-menu-scroll:${menu.dataset.scrollKey}`
    let restored = false
    try {
        const stored = sessionStorage.getItem(key)
        const offset = Number(stored)
        if (stored !== null && Number.isFinite(offset) && offset >= 0) {
            menu.scrollTop = offset
            restored = true
        }
    } catch {
        // Storage can be disabled; active-link visibility still works.
    }

    // On first entry, reveal the active link without moving the document.
    // With a saved position, preserve the user's menu context exactly.
    const active = !restored && menu.querySelector('a.active')
    if (active) {
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
