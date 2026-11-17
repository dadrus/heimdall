import HugoFlexSearch from "hugo-flexsearch";

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[char])
}

class SingleResult {
    constructor(args) {
        this.title = args.title
        this.url = args.url
        this.snippet = args.snippet
    }

    render() {
        return `
        <a class="list-group-item list-group-item-action" href="${escapeHTML(this.url)}">
            <div class="fw-bold mb-0 text-secondary">${escapeHTML(this.title)}</div>
            <div class="text-muted">${this.snippet}</div>
        </a>`
    }
}

class SearchResult {
    constructor(args) {
        this.title = args.title
        this.sections = args.sections
        this.items = args.items
    }

    render() {
        const heading = [...this.sections, this.title].map(escapeHTML).join(" / ")
        return `
        <div class="p-2">
          <div class="mb-1 fw-bold">${heading}</div>
          <div class="list-group">${this.items.map(item => item.render()).join("")}</div>
        </div>`
    }
}

// hugo-flexsearch 1.0.2 uses the same localStorage keys for every index.
// Scope both the index and its hash to the current documentation version.
class VersionedHugoFlexSearch extends HugoFlexSearch {
    getCache(key) {
        return super.getCache(`${key}:${this.config.indexUrl}`)
    }

    setCache(key, value) {
        if (key === "HugoSearch.index") {
            // One serialized index is several MB; do not fill localStorage with
            // copies of every visited version (or the old unscoped cache).
            for (let i = localStorage.length - 1; i >= 0; i--) {
                const stored = localStorage.key(i)
                if (stored && /^HugoSearch\.(index|hash)(:|$)/.test(stored)
                    && !stored.endsWith(`:${this.config.indexUrl}`)) {
                    localStorage.removeItem(stored)
                }
            }
        }
        super.setCache(`${key}:${this.config.indexUrl}`, value)
    }
}

class DocSearch extends HTMLElement {
    async connectedCallback() {
        new VersionedHugoFlexSearch({
            indexUrl: this.indexFile,
            indexedFields: ["content"],
            limit: 30,
            suggestions: true,
            searchLogic: "and",
            resultTemplate: this.resultTemplate.bind(this),
            emptyTemplate: this.emptyTemplate.bind(this),
        });

        const searchDialogue = document.getElementById("docSearch");
        const searchInput = document.getElementById("search-input")
        searchDialogue.addEventListener('shown.bs.modal', event => {
            searchInput.focus()
        })
    }

    get indexFile() {
        const indexFile = this.hasAttribute('index-file') ? this.getAttribute('index-file') : null

        if (!indexFile) {
            throw new Error('No index info data provided! Please add the attribute "index-file"!')
        }

        return indexFile
    }

    get pathPrefix() {
        return this.hasAttribute('path-prefix') ? this.getAttribute('path-prefix') : ""
    }

    // Index sections by heading IDs, shared by AsciiDoc and rendered OpenAPI content.
    contentSections(html) {
        const doc = new DOMParser().parseFromString(html, 'text/html')
        const sections = new Map()
        const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT)
        let current = null
        let lastHeading = null
        let node

        while ((node = walker.nextNode())) {
            if (!node.textContent.trim()) continue
            const heading = node.parentElement.closest('h2, h3, h4, h5, h6')
            if (heading && heading !== lastHeading) {
                lastHeading = heading
                const id = heading.id || heading.closest('[id]')?.id
                if (!id) {
                    current = null
                } else {
                    if (!sections.has(id)) {
                        sections.set(id, { id, title: heading.textContent.trim(), text: [] })
                    }
                    current = sections.get(id)
                }
            }
            if (current) current.text.push(node.textContent)
        }

        return [...sections.values()].map(section => ({
            ...section,
            text: section.text.join(' ').replace(/\s+/g, ' ').trim(),
        }))
    }

    snippet(content, query) {
        const text = String(content || '').replace(/\s+/g, ' ').trim()
        const search = query.trim()
        const terms = [search, ...search.split(/\s+/)].filter(Boolean)
        const term = terms.find(value => text.toLowerCase().includes(value.toLowerCase()))
        const position = term ? text.toLowerCase().indexOf(term.toLowerCase()) : 0
        const start = Math.max(0, position - 45)
        const end = Math.min(text.length, position + (term ? term.length : 0) + 90)
        const prefix = start > 0 ? '… ' : ''
        const suffix = end < text.length ? ' …' : ''

        if (!term) return prefix + escapeHTML(text.slice(start, end)) + suffix
        return prefix
            + escapeHTML(text.slice(start, position))
            + '<mark>' + escapeHTML(text.slice(position, position + term.length)) + '</mark>'
            + escapeHTML(text.slice(position + term.length, end)) + suffix
    }

    resultTemplate(post) {
        const search = document.getElementById('search-input').value.trim()
        const terms = search.toLowerCase().split(/\s+/).filter(Boolean)
        if (!terms.length) return ''

        const sections = this.contentSections(post.html_content)
        const hasTerm = (section, term) =>
            section.id.toLowerCase().includes(term) || section.text.toLowerCase().includes(term)
        const matching = sections.filter(section => terms.every(term => hasTerm(section, term)))
        // If an AND match spans multiple sections, link to the page rather
        // than to individual sections that match only part of the query.
        const items = matching.map(section => new SingleResult({
            title: section.title,
            url: this.pathPrefix + post.url + '#' + encodeURIComponent(section.id),
            snippet: this.snippet(
                terms.some(term => section.text.toLowerCase().includes(term))
                    ? section.text : section.id + ' ' + section.text, search),
        }))

        // Pages without headings (or hits in the page title/intro) are searchable too.
        if (!items.length) {
            items.push(new SingleResult({
                title: post.title,
                url: this.pathPrefix + post.url,
                snippet: this.snippet(post.content, search),
            }))
        }

        return new SearchResult({
            title: post.title,
            sections: post.sections || [],
            items,
        }).render()
    }

    emptyTemplate() {
        return `<p class="text-center mt-5">No results found</p>`
    }
}

customElements.define('doc-search', DocSearch)
