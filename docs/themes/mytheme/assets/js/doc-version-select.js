function splitVersionString(version) {
    const [corepre, build] = version.split('+')
    const [core, pre] = corepre.split('-').map(x => String(x).split('.').map(y => isNaN(y) ? y : parseInt(y, 10)))
    return {core, pre, build}
}

function compareCore(a, b) {
    for (let i = 0; i < 3; i++) {
        if (a[i] < b[i]) {
            return -1
        } else if (a[i] > b[i]) {
            return 1
        }
    }

    return 0
}

function comparePre(a, b) {
    if (a && !b) {
        return -1
    } else if (!a && b) {
        return 1
    } else {
        const len = a.length > b.length ? a.length : b.length
        for (let i = 0; i < len; i++) {
            if (typeof a[i] === 'undefined' && typeof b[i] !== 'undefined') {
                return -1
            } else if (typeof a[i] !== 'undefined' && typeof b[i] === 'undefined') {
                return 1
            } else if (typeof a[i] === 'number' && typeof b[i] === 'string') {
                return -1
            } else if (typeof a[i] === 'string' && typeof b[i] === 'number') {
                return 1
            } else if (a[i] < b[i]) {
                return -1
            } else if (a[i] > b[i]) {
                return 1
            }
        }
    }
}

const semanticCompare = (a, b) => {
    const va = splitVersionString(a)
    const vb = splitVersionString(b)

    const core = compareCore(va.core, vb.core)

    if (core) {
        return core
    }

    const pre = comparePre(va.pre, vb.pre)

    if (pre) {
        return pre
    }

    return 0
}

const html = htmlSnippet => {
    const parser = new DOMParser()
    const doc = parser.parseFromString(htmlSnippet, 'text/html')
    return doc.body.firstChild
}

const linkListItem = (currentVersion, currentPath) => element => `
<li><a class="dropdown-item ${currentVersion === element.version ? 'current' : ''}" href="${element.path}${currentPath}">${element.version}</a></li>`

const linkList = (elements = [], currentVersion, currentPath) => {
    const linkItem = linkListItem(currentVersion, currentPath)

    return html(`
    <ul class="dropdown-menu  bg-dark">
      ${linkItem(elements[0])}
      <li><hr class="dropdown-divider"></li>
      ${elements.slice(1).map(linkItem).sort(semanticCompare).reverse().join('\n')}
    </ul>
  `)
}

const load = async dataFile => {
    const result = await fetch(dataFile, {
        headers: {Accept: 'application/json'},
        credentials: 'same-origin',
        method: 'GET',
        mode: 'same-origin',
        redirect: 'follow'
    })

    if (!result.ok) {
        throw new Error(`Data could not be loaded: ${result.status}`)
    }

    return result.json()
}

class DocVersionSelect extends HTMLElement {
    async connectedCallback() {
        const versions = await load(this.versionsFile)

        this.appendChild(linkList(versions, this.currentVersion, this.currentPage))
    }

    get currentPage() {
        const page = this.hasAttribute('current-page') ? this.getAttribute('current-page') : null

        return page || '/'
    }

    get versionsFile() {
        const versionsFile = this.hasAttribute('version-file') ? this.getAttribute('version-file') : null

        if (!versionsFile) {
            throw new Error('No version info data provided! Please add the attribute "version-file"!')
        }

        return versionsFile
    }

    get currentVersion() {
        const currentVersion = this.hasAttribute('current-version') ? this.getAttribute('current-version') : null
        return currentVersion || 'unknown'
    }
}

customElements.define('doc-version-select', DocVersionSelect)
