import HugoFlexSearch from "hugo-flexsearch";
import * as bs from "bootstrap";

class DocSearch extends HTMLElement {
    async connectedCallback() {
        new HugoFlexSearch({
            indexUrl: this.indexFile,
            indexedFields: [ "title", "content", "url" ],
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

        let result = `<div class="mb-2 p-1"><a href="${post.url}"><h4>${post.title}</h4></a>`

        if (searchValue.length > 2) {
            let results = []

            let idx = -1
            do {
                idx = post.content.toLowerCase().indexOf(searchValue.toLowerCase(), idx + 1)
                if (idx > -1) {
                    const snippet = post.content.substring(idx - 30, idx + 30)
                    const start = snippet.toLowerCase().indexOf(searchValue.toLowerCase())
                    const beforeVal = snippet.substring(0, start)
                    const afterVal = snippet.substring(start + searchValue.length)
                    results.push('... ' + beforeVal + '<span class="text-primary">' + searchValue + '</span>' + afterVal + ' ...')
                }
            } while (idx > -1)

            console.log(results)

            result += `<p class="text-muted">`
            results.filter((val, idx, arr) => idx < 5).forEach(res => result += `${res}<br>`)
            result += `</p>`
        }

        result += `</div><hr class="mb-2" />`

        return result
    }

    emptyTemplate() {
        return `<div class="p-3"><p>No results found.</p></div>`
    }
}

customElements.define('doc-search', DocSearch)
