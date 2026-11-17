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

// hugo-flexsearch 1.0.2 caches one index globally and re-downloads index.json
// to check freshness. Scope the cache to a documentation version and use the
// build hash embedded in HTML instead of fetching the entire JSON again.
class VersionedHugoFlexSearch extends HugoFlexSearch {
    // Search only when the query changes, not when navigating with arrow keys.
    addSearchListeners(searchInputs) {
        for (const input of searchInputs) {
            input.addEventListener('input', () => this.search(input.value.toLowerCase()))
        }
    }

    display(results) {
        super.display(results)
        this.config.onResultsUpdated?.()
    }

    initCache() {
        try {
            return window.localStorage
        } catch {
            return undefined
        }
    }

    getCache(key) {
        try {
            return this.cache?.getItem(`${key}:${this.config.indexUrl}`) || null
        } catch {
            return null
        }
    }

    clearCache() {
        try {
            this.cache?.removeItem(`HugoSearch.index:${this.config.indexUrl}`)
            this.cache?.removeItem(`HugoSearch.hash:${this.config.indexUrl}`)
        } catch {
            // Cache access is optional; search still works without it.
        }
    }

    setCache(key, value) {
        if (!this.cache) return false
        try {
            if (key === "HugoSearch.index") {
                // Avoid keeping multiple multi-MB indexes across versions.
                for (let i = this.cache.length - 1; i >= 0; i--) {
                    const stored = this.cache.key(i)
                    if (stored && /^HugoSearch\.(index|hash)(:|$)/.test(stored)
                        && !stored.endsWith(`:${this.config.indexUrl}`)) {
                        this.cache.removeItem(stored)
                    }
                }
            }
            this.cache.setItem(`${key}:${this.config.indexUrl}`, value)
            return true
        } catch {
            return false
        }
    }

    showStatus(message) {
        for (const element of this.searchOutputs) {
            element.innerHTML = `<p class="text-center mt-5">${escapeHTML(message)}</p>`
        }
    }

    loadData() {
        if (this.dataLoaded || this.loadingPromise) return

        const cachedHash = this.getCache("HugoSearch.hash")
        const cachedIndex = cachedHash && cachedHash === this.config.indexHash
            ? this.getCache("HugoSearch.index") : null
        if (cachedIndex) {
            try {
                this.index.import(cachedIndex)
                this.dataLoaded = true
                return
            } catch {
                this.index = this.createIndex()
                this.clearCache()
            }
        }

        this.fetchData()
    }

    fetchData() {
        if (this.loadingPromise) return
        this.showStatus('Loading search index…')
        this.loadingPromise = fetch(this.config.indexUrl)
            .then(response => {
                if (!response.ok) throw new Error(`Search index request failed (${response.status})`)
                return response.json()
            })
            .then(data => {
                const hash = data?.[data.length - 1]?.hash
                if (!Array.isArray(data) || typeof hash !== 'string') {
                    throw new Error('Invalid search index')
                }

                this.index = this.createIndex()
                this.postCount = 0
                for (const post of data.slice(0, -1)) {
                    const formatted = this.format(post)
                    if (formatted) this.index.add(formatted)
                }
                this.dataLoaded = true

                if (this.cache) {
                    try {
                        if (!this.setCache('HugoSearch.index', this.index.export())
                            || !this.setCache('HugoSearch.hash', hash)) {
                            this.clearCache()
                        }
                    } catch {
                        this.clearCache()
                    }
                }

                // A query may have been typed while the first fetch was pending.
                const query = this.searchInputs[0]?.value.toLowerCase().trim()
                if (query) this.search(query)
                else this.showStatus('No recent searches')
            })
            .catch(error => {
                this.log(error)
                this.showStatus('Search is currently unavailable. Please try again.')
            })
            .finally(() => { this.loadingPromise = null })
    }

    search(query) {
        this.loadData()
        if (this.dataLoaded) super.search(query)
    }
}
class DocSearch extends HTMLElement {
    async connectedCallback() {
        new VersionedHugoFlexSearch({
            indexUrl: this.indexFile,
            indexHash: this.getAttribute("index-hash"),
            indexedFields: ["content"],
            limit: 30,
            suggestions: true,
            searchLogic: "and",
            resultTemplate: this.resultTemplate.bind(this),
            emptyTemplate: this.emptyTemplate.bind(this),
            onResultsUpdated: () => this.selectFirstResult(),
        });

        const searchInput = this.querySelector('#search-input')
        searchInput.addEventListener('keydown', event => this.onSearchKeydown(event))
        this.addEventListener('shown.bs.modal', () => searchInput.focus())
    }

    get resultLinks() {
        return [...this.querySelectorAll('.search-results a.list-group-item-action')]
    }

    selectFirstResult() {
        const first = this.resultLinks[0]
        if (first) first.classList.add('search-result-active')
        this.querySelector('#search-result-status').textContent = ''
    }

    onSearchKeydown(event) {
        if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey
            || !['ArrowDown', 'ArrowUp', 'Enter'].includes(event.key)) return

        const links = this.resultLinks
        if (!links.length) return

        const current = links.findIndex(link => link.classList.contains('search-result-active'))
        if (event.key === 'Enter') {
            if (current < 0) return
            event.preventDefault()
            links[current].click()
            return
        }

        event.preventDefault()
        const step = event.key === 'ArrowDown' ? 1 : -1
        const next = current < 0
            ? (step === 1 ? 0 : links.length - 1)
            : (current + step + links.length) % links.length
        if (current >= 0) links[current].classList.remove('search-result-active')
        links[next].classList.add('search-result-active')
        links[next].scrollIntoView({ block: 'nearest' })

        const title = links[next].querySelector('.fw-bold')?.textContent?.trim() || links[next].textContent.trim()
        this.querySelector('#search-result-status').textContent = `${next + 1} of ${links.length}: ${title}`
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

        const sections = post.search_sections || []
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
