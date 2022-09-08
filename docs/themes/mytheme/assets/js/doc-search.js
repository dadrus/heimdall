import HugoFlexSearch from "hugo-flexsearch";
import * as bs from "bootstrap";

class DocSearch extends HTMLElement {
    async connectedCallback() {
        new HugoFlexSearch({
            indexUrl: this.indexFile,
            indexedFields: ["title", "content", "url"],
            limit: 10,
            suggestions: true,
            searchLogic: "and",
            resultTemplate: this.resultTemplate,
            emptyTemplate: this.emptyTemplate,
        });

        const searchForm = document.getElementById("docs-search");
        const searchSuggestions = bs.Collapse.getOrCreateInstance(
            document.getElementById("search-suggestions"));

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
            } else {
                searchSuggestions.hide();
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

    resultTemplate(post) {
        const searchValue = document.getElementById("search").value

        if (searchValue.length < 3) {
            return ""
        }

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

        const results = matches.map(el => {
            const section = el.querySelector(headingSelector)
            const idx = el.textContent.toLowerCase().indexOf(searchValue.toLowerCase())
            let snippet = el.textContent.substring(idx - 10, idx + 40)

            const start = snippet.toLowerCase().indexOf(searchValue.toLowerCase())
            const beforeVal = snippet.substring(0, start)
            const afterVal = snippet.substring(start + searchValue.length)
            snippet = '... ' + beforeVal + '<span class="text-primary">' + searchValue + '</span>' + afterVal + ' ...'

            return {
                "title": section.textContent,
                "url": post.url + "#" + section.attributes.id.value,
                "snippet": snippet
            }
        })

        console.log(results)

        let result = `<div class="mb-2 p-1"><p>${post.section} - ${post.title}</p>`

        result += `<p class="text-muted">`
        results.forEach(res => {
            result +=  `<a href="${res.url}"><h4>${res.title}</h4></a>`
            result += `<p class="text-muted">${res.snippet}</p>`
        })

        result += `</div><hr class="mb-2" />`

        return result
    }

    emptyTemplate() {
        return `<div class="p-3"><p>No results found.</p></div>`
    }
}

customElements.define('doc-search', DocSearch)
