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
            <div class="text-muted">${this.snippet}</div>
            <div class="fw-bold mb-0 text-primary">${this.title}</div>
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
        <div class="p-3">
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
            limit: 10,
            suggestions: true,
            searchLogic: "and",
            resultTemplate: this.resultTemplate.bind(this),
            emptyTemplate: this.emptyTemplate.bind(this),
        });

        const searchForm = document.getElementById("docs-search");
        const searchSuggestions = bs.Collapse.getOrCreateInstance(
            document.getElementById("search-suggestions"), {toggle: false});

        searchForm.addEventListener("keydown", (ev) => {
            if (["Esc", "Escape"].includes(ev.key)) {
                searchSuggestions.hide();
            }
        });

        function checkFocus(ev) {
            if (searchForm.contains(ev.relatedTarget)) {
                return; // Special case for tab key
            }

            if (searchForm.contains(document.activeElement)) {
                searchSuggestions.show();
                document.body.style.overflow = "hidden";
            } else {
                searchSuggestions.hide();
                document.body.style.overflow = "auto";
            }
        }

        window.addEventListener("blur", checkFocus, true);
        window.addEventListener("focus", checkFocus, true);
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
        const searchValue = document.getElementById("search").value
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
        return `<div class="p-3"><p>No results found.</p></div>`
    }
}

customElements.define('doc-search', DocSearch)
