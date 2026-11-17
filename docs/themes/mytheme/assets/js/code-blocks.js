// Enhance long code blocks consistently across Docs, Guides and OpenAPI.
// Unenhanced <pre> elements remain fully readable when JavaScript is disabled.
(() => {
    const previewLines = 15
    let nextId = 0

    function enhanceCodeBlocks(root = document) {
        for (const pre of root.querySelectorAll('.docs-content pre')) {
            if (pre.closest('.code-block') || !pre.getClientRects().length) continue

            const style = getComputedStyle(pre)
            const lineHeight = parseFloat(style.lineHeight) || parseFloat(style.fontSize) * 1.5
            const padding = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom)
            const previewHeight = Math.ceil(previewLines * lineHeight + padding)
            if (pre.scrollHeight <= previewHeight + 2) continue

            const wrapper = document.createElement('div')
            wrapper.className = 'code-block code-block--collapsed'
            wrapper.style.setProperty('--code-preview-height', `${previewHeight}px`)

            const viewport = document.createElement('div')
            viewport.className = 'code-block__viewport'
            // Chroma wraps its <pre> in .highlight; keep the background and
            // the syntax highlighting together, with the button outside it.
            const block = pre.parentElement.classList.contains('highlight') ? pre.parentElement : pre
            if (block.classList.contains('highlight') || pre.classList.contains('highlight')) {
                wrapper.classList.add('code-block--highlighted')
            }
            block.before(wrapper)
            wrapper.append(viewport)
            viewport.append(block)

            if (!pre.id) {
                do { nextId++ } while (document.getElementById(`code-block-${nextId}`))
                pre.id = `code-block-${nextId}`
            }

            const toggle = document.createElement('button')
            toggle.type = 'button'
            toggle.className = 'code-block__toggle'
            toggle.setAttribute('aria-controls', pre.id)
            toggle.setAttribute('aria-expanded', 'false')
            toggle.textContent = 'Show full code'
            toggle.addEventListener('click', () => {
                const expanded = !wrapper.classList.toggle('code-block--collapsed')
                toggle.setAttribute('aria-expanded', String(expanded))
                toggle.textContent = expanded ? 'Show less' : 'Show full code'
            })
            wrapper.append(toggle)
        }
    }

    // Code blocks inside closed native <details> have no measurable height yet.
    // Enhance them when the user opens the details element.
    document.addEventListener('toggle', event => {
        if (event.target.matches('details[open]')) enhanceCodeBlocks(event.target)
    }, true)

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => enhanceCodeBlocks())
    } else {
        enhanceCodeBlocks()
    }
})()
