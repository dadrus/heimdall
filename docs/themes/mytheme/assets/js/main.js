// Shared entry point: Bootstrap behavior is independent of document search.
import { Modal } from "bootstrap"
import "./doc-version-select.js"
import "./linkable-headline-area.js"
import "./code-blocks.js"
import "./doc-search.js"

// Use the same Bootstrap dialog as the search buttons; no extra modal state.
document.addEventListener('keydown', event => {
    if (event.key.toLowerCase() !== 'k' || (!event.ctrlKey && !event.metaKey)
        || event.altKey || event.shiftKey) return

    const dialog = document.getElementById('docSearch')
    if (!dialog) return

    event.preventDefault()
    if (dialog.classList.contains('show')) return

    const previousFocus = document.activeElement
    dialog.addEventListener('hidden.bs.modal', () => {
        if (previousFocus?.isConnected) previousFocus.focus()
    }, { once: true })
    Modal.getOrCreateInstance(dialog).show()
})
