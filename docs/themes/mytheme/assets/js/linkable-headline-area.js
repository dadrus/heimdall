class LinkableContentArea extends HTMLElement {
    connectedCallback() {
        const headlines = Array.from(this.querySelectorAll('h1,h2,h3,h4'))

        for (const headline of headlines) {
            if (headline.hasAttribute('id')) {
                const l = link(`#${headline.getAttribute('id')}`)
                headline.insertAdjacentElement('beforeend', l)
            }
        }
    }
}

customElements.define('linkable-headline-area', LinkableContentArea)


function link(href) {
    const a = document.createElement('a')
    a.setAttribute('href', href)
    a.classList.add('reference-link')
    a.textContent = '#'
    console.log(a)
    return a
}