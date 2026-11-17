function splitVersionString(version) {
    const [corepre] = version.replace(/^v/, '').split('+')
    const [core, pre] = corepre.split('-').map(x => x.split('.').map(y => /^\d+$/.test(y) ? Number(y) : y))
    return {core, pre}
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
    } else if (!a && !b) {
        return 0
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

    return 0
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

// Until the target version's sitemap is available, link to its home page.
// This avoids 404s even when switching immediately after opening the menu.
const linkListItem = (currentVersion, currentPath) => element => `
<li><a class="dropdown-item ${currentVersion === element.version ? 'current' : ''}" ${currentVersion === element.version ? 'aria-current="page"' : ''} data-version-path="${element.path}" href="${element.path}${currentVersion === element.version ? currentPath : '/'}">${element.version}</a></li>`

const linkList = (elements = [], currentVersion, currentPath) => {
    const linkItem = linkListItem(currentVersion, currentPath)
    const additionalCurrent = currentVersion !== 'unknown' && !elements.some(element => element.version === currentVersion)
        ? `
      <li><hr class="dropdown-divider"></li>
      <li><span class="dropdown-header text-white-50">Currently viewing</span></li>
      <li><a class="dropdown-item current" aria-current="page" href="${window.location.href}">${currentVersion}</a></li>`
        : ''

    return html(`
    <ul class="dropdown-menu  bg-dark">
      ${linkItem(elements[0])}
      <li><hr class="dropdown-divider"></li>
      ${elements.slice(1).sort((a, b) => semanticCompare(b.version, a.version)).map(linkItem).join('\n')}
      ${additionalCurrent}
    </ul>
  `)
}

// Every published version already has a Hugo sitemap. Its page paths do not
// include the /heimdall/<version> deployment prefix, just like .RelPermalink.
// Choose the requested page if it exists, otherwise its nearest available
// parent (e.g. /openapi/), and ultimately the version's homepage.
function closestAvailablePage(currentPath, availablePages) {
    const parts = currentPath.split('/').filter(Boolean)
    for (let count = parts.length; count >= 0; count--) {
        const path = count ? `/${parts.slice(0, count).join('/')}/` : '/'
        if (availablePages.has(path)) return path
    }
    return '/'
}

// The browser's HTTP cache handles the sitemap responses. Retain only their
// parsed paths across full page loads so version links can be resolved at once.
const sitemapCachePrefix = 'heimdall:version-sitemap:'
const devRefreshMs = 30 * 60 * 1000
const releaseRefreshMs = 24 * 60 * 60 * 1000
const failedRetryMs = 10 * 60 * 1000

function readCachedSitemap(versionPath) {
    try {
        const cached = JSON.parse(localStorage.getItem(sitemapCachePrefix + versionPath))
        if (!cached || !Array.isArray(cached.paths) || !Number.isFinite(cached.refreshAfter)
            || cached.paths.some(path => typeof path !== 'string' || !path.startsWith('/'))) return null
        return {pages: new Set(cached.paths), refreshAfter: cached.refreshAfter}
    } catch {
        return null // Storage is optional (private mode, quota, disabled storage).
    }
}

function cacheSitemap(versionPath, pages, refreshIn) {
    try {
        localStorage.setItem(sitemapCachePrefix + versionPath, JSON.stringify({
            paths: [...pages], refreshAfter: Date.now() + refreshIn
        }))
    } catch {
        // Still update the current page's links when persistence is unavailable.
    }
}

function setVersionLink(link, currentPath, availablePages) {
    if (!availablePages.size) return // Keep the safe version-home fallback.
    const closest = closestAvailablePage(currentPath, availablePages)
    link.href = link.getAttribute('data-version-path') + closest
    if (closest !== currentPath) {
        link.title = 'Page not available in this version; opening the nearest available section.'
    } else {
        link.removeAttribute('title')
    }
}

async function fetchSitemap(versionPath) {
    const response = await fetch(`${versionPath}/sitemap.xml`, {credentials: 'same-origin'})
    if (!response.ok) throw new Error(`Sitemap could not be loaded: ${response.status}`)

    const xml = new DOMParser().parseFromString(await response.text(), 'application/xml')
    if (xml.querySelector('parsererror')) throw new Error('Invalid sitemap XML')
    const pages = new Set(Array.from(xml.getElementsByTagName('loc'), element =>
        new URL(element.textContent).pathname))
    if (!pages.size) throw new Error('Empty sitemap')
    return pages
}

function prepareVersionLinks(links, versions, currentPath) {
    const versionsByPath = new Map(versions.map(version => [version.path, version.version]))
    const missingOrStale = []

    // Set every cached link synchronously, even if background requests are slow.
    for (const link of links) {
        if (link.getAttribute('aria-current') === 'page') continue
        const path = link.getAttribute('data-version-path')
        const cached = readCachedSitemap(path)
        if (cached) setVersionLink(link, currentPath, cached.pages)
        if (!cached || cached.refreshAfter <= Date.now()) {
            missingOrStale.push({link, path, cached, version: versionsByPath.get(path)})
        }
    }

    // Start immediately after building the dropdown, never when it is opened
    // or a link is clicked. Limit concurrent requests on a cold cache.
    let next = 0
    async function preloadNext() {
        while (next < missingOrStale.length) {
            const {link, path, cached, version} = missingOrStale[next++]
            try {
                const pages = await fetchSitemap(path)
                cacheSitemap(path, pages, version === 'dev' ? devRefreshMs : releaseRefreshMs)
                setVersionLink(link, currentPath, pages)
            } catch {
                // Use stale paths if present, and avoid retrying a broken
                // sitemap on every single page load.
                cacheSitemap(path, cached?.pages || new Set(), failedRetryMs)
            }
        }
    }
    for (let i = 0; i < Math.min(2, missingOrStale.length); i++) preloadNext()
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

        prepareVersionLinks(this.querySelectorAll('a[data-version-path]'), versions, this.currentPage)
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
