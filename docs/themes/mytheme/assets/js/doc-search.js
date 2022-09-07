import HugoFlexSearch from "hugo-flexsearch";
import * as bs from "bootstrap";

export const search = new HugoFlexSearch({
    indexUrl: "/index.json",
    indexedFields: [
        "title",
        "content",
        "url",
    ],
    limit: 10,
    suggestions: true,
    searchLogic: "and",
    resultTemplate: (post) => {
        const searchValue = searchInput.value
        let results = []

        let result = `<div class="mb-2 p-1"><a href="${post.url}"><h4>${post.title}</h4></a>`

        if (searchValue.length > 2) {
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

            result += `<p class="text-muted">`
            results.filter((val, idx, arr) => idx < 5).forEach(res => result += `${res}<br>`)
            result += `</p>`
        }

        result += `</div><hr class="mb-2" />`

        return result
    },
    emptyTemplate: () => { return `<div class="p-3"><p>No results found.</p></div>` },
});

const searchForm = document.getElementById("docs-search");
const searchInput = document.getElementById("search");
const suggestionsEl = document.getElementById("search-suggestions");
const searchSuggestions = bs.Collapse.getOrCreateInstance(suggestionsEl);

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

searchForm.addEventListener("keydown", (ev) => {
    if (["Esc", "Escape"].includes(ev.key)) {
        searchSuggestions.hide();
    }
});
