const html = htmlSnippet => {
  const parser = new DOMParser()
  const doc = parser.parseFromString(htmlSnippet, 'text/html')
  return doc.body.firstChild
}

const linkListItem = currentVersion => element => `
<li><a class="dropdown-item ${currentVersion === element.version ? 'current' : ''}" href="${element.path}">${element.version}</a></li>`

const linkList = (elements = [], currentVersion) => {
  const linkItem = linkListItem(currentVersion)

  return html(`
    <ul class="dropdown-menu">
      ${linkItem(elements[0])}
      <li><hr class="dropdown-divider"></li>
      ${elements.slice(1).map(linkItem).join('\n')}
    </ul>
  `)
}

const load = async dataFile => {
  const result = await fetch(dataFile, {
    headers: { Accept: 'application/json' },
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
  async connectedCallback () {
    const versions = await load(this.versionInfoFile)

    this.appendChild(linkList(versions, this.currentVersion))
  }

  get versionInfoFile () {
    const versionInfoFile = this.hasAttribute('version-info') ? this.getAttribute('version-info') : null

    if (!versionInfoFile) {
      throw new Error('No version info data provided! Please add the attribute "version-info"!')
    }

    return versionInfoFile
  }

  get currentVersion () {
    const currentVersion = this.hasAttribute('current-version') ? this.getAttribute('current-version') : null
    return currentVersion || 'unknown'
  }
}

customElements.define('doc-version-select', DocVersionSelect)
