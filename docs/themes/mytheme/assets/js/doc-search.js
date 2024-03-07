import HugoFlexSearch from "hugo-flexsearch";
import * as bs from "bootstrap";

class SingleResult {
    constructor(args) {
        this.title = args.title
        this.url = args.url
        this.snippet = args.snippet
    }

    render() {
        return `
        <a class="list-group-item list-group-item-action" href="${this.url}">
            <div class="fw-bold mb-0 text-secondary">${this.title}</div>
            <div class="text-muted">${this.snippet}</div>
        </a>`
    }
}

class SearchResult {
    constructor(args) {
        this.title = args.title
        this.url = args.url
        this.sections = args.sections
        this.items = args.items
    }

    render() {
        return `
        <div class="p-2">
          <div class="mb-1 fw-bold" >${this.sections.join(" / ")} / ${this.title}</div>
          <div class="list-group">${this.items.reduce((prev, cur) => prev + cur.render(), "")}</div>
        </div>`
    }
}

class DocSearch extends HTMLElement {
    async connectedCallback() {
        new HugoFlexSearch({
            indexUrl: this.indexFile,
            indexedFields: ["title", "content", "url"],
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

    resultTemplate(post) {
        const searchValue = document.getElementById("search-input").value
        const pathPrefix = this.pathPrefix

        const parser = new DOMParser()
        const doc = parser.parseFromString(post.html_content, 'text/html')

        let headingSelector = "h3"
        let sections = Array.prototype.slice.call(doc.querySelectorAll(".sect2"))
        let matches = sections
            .filter(el => el.textContent.toLowerCase().indexOf(searchValue.toLowerCase()) > -1)
        if (matches.length === 0) {
            sections = Array.prototype.slice.call(doc.querySelectorAll(".sect1"))
            matches = sections
                .filter(el => el.textContent.toLowerCase().indexOf(searchValue.toLowerCase()) > -1)
            headingSelector = "h2"
        }

        if (matches.length === 0) {
            return ""
        }

        const items = matches.map(el => {
            const section = el.querySelector(headingSelector)
            const idx = el.textContent.toLowerCase().indexOf(searchValue.toLowerCase())
            let snippet = el.textContent.substring(idx - 10, idx + 40)

            const start = snippet.toLowerCase().indexOf(searchValue.toLowerCase())
            const beforeVal = snippet.substring(0, start)
            const afterVal = snippet.substring(start + searchValue.length)
            snippet = '... ' + beforeVal + '<mark>' + searchValue + '</mark>' + afterVal + ' ...'

            return new SingleResult({
                "title": section.textContent,
                "url": pathPrefix + post.url + "#" + section.attributes.id.value,
                "snippet": snippet,
            })
        })

        return new SearchResult({
            "title": post.title,
            "url": pathPrefix + post.url,
            "sections": post.sections,
            "items": items
        }).render()
    }

    emptyTemplate() {
        return `<p class="text-center mt-5">No results found</p>`
    }
}

customElements.define('doc-search', DocSearch)
