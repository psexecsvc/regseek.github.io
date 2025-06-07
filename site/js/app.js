// Global variables
let allArtifacts = [];
let filteredArtifacts = [];
let currentFilters = {
    search: '',
    category: '',
    criticality: '',
    investigation: '',
    windowsVersion: '',
    hive: '',
    hasTools: ''
};

// Load artifacts from JSON file
async function loadArtifacts() {
    try {
        const response = await fetch('build/artifacts.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        allArtifacts = data.artifacts;
        
        console.log(`Loaded ${allArtifacts.length} artifacts`);
        
        // Initialize the UI
        init(data);
    } catch (error) {
        console.error('Failed to load artifacts:', error);
        showError('Failed to load artifacts. Please check the console for details.');
    }
}

// Initialize application
function init(data) {
    populateFilterOptions(data);
    filteredArtifacts = [...allArtifacts];
    renderArtifacts(filteredArtifacts);
    updateStats(data.statistics);
    setupEventListeners();
}

// Populate filter dropdown options
function populateFilterOptions(data) {
    // Categories
    const categorySelect = document.getElementById('filter-category');
    if (categorySelect && data.categories) {
        data.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category.charAt(0).toUpperCase() + category.slice(1).replace('-', ' ');
            categorySelect.appendChild(option);
        });
    }
    
    // Windows versions
    const versionSelect = document.getElementById('filter-windows-version');
    if (versionSelect && data.statistics?.windows_versions) {
        data.statistics.windows_versions.forEach(version => {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = version;
            versionSelect.appendChild(option);
        });
    }
}

// Render artifacts
function renderArtifacts(artifacts) {
    const grid = document.getElementById('registry-grid');
    grid.innerHTML = '';
    
    if (artifacts.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <h3>No artifacts found</h3>
                <p>Try adjusting your search criteria or filters</p>
            </div>
        `;
        return;
    }
    
    artifacts.forEach((artifact, index) => {
        const item = createArtifactElement(artifact, index);
        grid.appendChild(item);
    });
    
    updateVisibleCount(artifacts.length);
}

// Create artifact element
function createArtifactElement(artifact, index) {
    const div = document.createElement('div');
    div.className = 'registry-item';
    div.dataset.category = artifact.category;
    div.dataset.index = index;
    
    const metadata = artifact.metadata || {};
    const criticality = metadata.criticality || 'unspecified';
    const primaryPath = artifact.paths ? artifact.paths[0] : 'Unknown path';
    
    // Create tags from investigation types and other metadata
    const tags = [];
    if (metadata.investigation_types) {
        tags.push(...metadata.investigation_types.slice(0, 3)); // Show max 3
    }
    if (metadata.tags) {
        tags.push(...metadata.tags.slice(0, 2)); // Show max 2 more
    }
    
    const tagsHtml = tags.length > 0 ? `
        <div class="item-tags">
            ${tags.map(tag => `<span class="item-tag">${tag}</span>`).join('')}
        </div>
    ` : '';
    
    const criticalityBadge = criticality !== 'unspecified' ? `
        <span class="item-criticality ${criticality}">${criticality}</span>
    ` : '';
    
    div.innerHTML = `
        <div class="item-header">
            <div class="item-badges">
                <span class="item-category">${artifact.category}</span>
                ${criticalityBadge}
            </div>
            <h3 class="item-title">${artifact.title}</h3>
        </div>
        <div class="item-path">${primaryPath}</div>
        <div class="item-description">${artifact.description}</div>
        ${tagsHtml}
        <div class="item-footer">
            <span class="item-meta">Click for details</span>
            <span class="item-arrow">→</span>
        </div>
    `;
    
    div.addEventListener('click', () => showModal(artifact));
    return div;
}

// Show modal with artifact details
function showModal(artifact) {
    const modal = document.getElementById('modal');
    const modalBody = document.getElementById('modal-body');
    
    const metadata = artifact.metadata || {};
    const details = artifact.details || {};
    const author = artifact.author || {};
    const contribution = artifact.contribution || {};
    
    const criticality = metadata.criticality || 'unspecified';
    const criticalityBadge = criticality !== 'unspecified' ? `
        <span class="modal-criticality ${criticality}">${criticality} Priority</span>
    ` : '';
    
    // Format tools
    const tools = details.tools || [];
    const toolsHtml = tools.map(tool => {
        if (typeof tool === 'string') {
            return `<span class="tool-link">${tool}</span>`;
        }
        if (tool.url) {
            return `<a href="${tool.url}" class="tool-link" target="_blank" rel="noopener">${tool.name}</a>`;
        }
        return `<span class="tool-link">${tool.name}</span>`;
    }).join('');
    
    // Format examples
    const examples = details.examples || [];
    const examplesHtml = examples.map(ex => `<li>${ex}</li>`).join('');
    
    // Format metadata sections
    const windowsVersions = metadata.windows_versions || [];
    const investigationTypes = metadata.investigation_types || [];
    const references = metadata.references || [];
    
    modalBody.innerHTML = `
        <div class="modal-header">
            <h2 class="modal-title">${artifact.title}</h2>
            <div class="modal-badges">
                <span class="modal-category">${artifact.category}</span>
                ${criticalityBadge}
            </div>
        </div>
        <div class="modal-body">
            <div class="detail-section">
                <h3>Registry Paths</h3>
                ${(artifact.paths || []).map(path => `<div class="code-block">${path}</div>`).join('')}
            </div>
            
            <div class="detail-section">
                <h3>What It Stores</h3>
                <p>${details.what || 'No details available'}</p>
            </div>
            
            <div class="detail-section">
                <h3>Forensic Value</h3>
                <p>${details.forensic_value || 'No forensic value description'}</p>
            </div>
            
            <div class="detail-section">
                <h3>Data Structure & Format</h3>
                <p>${details.structure || 'No structure information'}</p>
            </div>
            
            ${examples.length > 0 ? `
            <div class="detail-section">
                <h3>Examples</h3>
                <ul class="example-list">
                    ${examplesHtml}
                </ul>
            </div>
            ` : ''}
            
            ${tools.length > 0 ? `
            <div class="detail-section">
                <h3>Analysis Tools</h3>
                <div class="tool-links">
                    ${toolsHtml}
                </div>
            </div>
            ` : ''}
            
            ${windowsVersions.length > 0 ? `
            <div class="detail-section">
                <h3>Supported Windows Versions</h3>
                <p>${windowsVersions.join(', ')}</p>
            </div>
            ` : ''}
            
            ${investigationTypes.length > 0 ? `
            <div class="detail-section">
                <h3>Investigation Types</h3>
                <p>${investigationTypes.map(type => type.replace('-', ' ')).join(', ')}</p>
            </div>
            ` : ''}
            
            ${references.length > 0 ? `
            <div class="detail-section">
                <h3>References</h3>
                <ul>
                    ${references.map(ref => `
                        <li>
                            ${ref.url ? `<a href="${ref.url}" target="_blank" rel="noopener">${ref.title}</a>` : ref.title}
                            ${ref.type ? ` (${ref.type})` : ''}
                        </li>
                    `).join('')}
                </ul>
            </div>
            ` : ''}
            
            ${author.name || contribution.date_added ? `
            <div class="detail-section">
                <h3>Contribution Info</h3>
                <p>
                    ${author.name ? `Author: ${author.name}` : ''}
                    ${author.organization ? ` (${author.organization})` : ''}
                    ${contribution.date_added ? `<br>Added: ${contribution.date_added}` : ''}
                    ${contribution.version ? ` (v${contribution.version})` : ''}
                </p>
            </div>
            ` : ''}
        </div>
    `;
    
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(performSearch, 300));
    }
    
    // Quick filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentFilters.category = e.target.dataset.filter === 'all' ? '' : e.target.dataset.filter;
            performSearch();
        });
    });
    
    // Advanced search toggle
    const advancedBtn = document.getElementById('advanced-search-btn');
    const advancedPanel = document.getElementById('advanced-search-panel');
    if (advancedBtn && advancedPanel) {
        advancedBtn.addEventListener('click', () => {
            advancedPanel.classList.toggle('open');
        });
    }
    
    // Advanced search filters
    const filterElements = [
        'filter-category', 'filter-criticality', 'filter-investigation',
        'filter-windows-version', 'filter-hive', 'filter-has-tools'
    ];
    
    filterElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('change', updateAdvancedFilters);
        }
    });
    
    // Advanced search actions
    const applyBtn = document.getElementById('apply-filters');
    const clearBtn = document.getElementById('clear-filters');
    
    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            updateAdvancedFilters();
            advancedPanel.classList.remove('open');
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', clearAllFilters);
    }
    
    // Sort functionality
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) {
        sortSelect.addEventListener('change', handleSort);
    }
    
    // Modal functionality
    const closeModal = document.getElementById('close-modal');
    const modal = document.getElementById('modal');
    
    if (closeModal) {
        closeModal.addEventListener('click', hideModal);
    }
    
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target.id === 'modal') {
                hideModal();
            }
        });
    }
    
    // ESC key to close modal
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideModal();
        }
    });
}

// Update advanced filters
function updateAdvancedFilters() {
    currentFilters.category = document.getElementById('filter-category')?.value || '';
    currentFilters.criticality = document.getElementById('filter-criticality')?.value || '';
    currentFilters.investigation = document.getElementById('filter-investigation')?.value || '';
    currentFilters.windowsVersion = document.getElementById('filter-windows-version')?.value || '';
    currentFilters.hive = document.getElementById('filter-hive')?.value || '';
    currentFilters.hasTools = document.getElementById('filter-has-tools')?.value || '';
    
    performSearch();
}

// Clear all filters
function clearAllFilters() {
    // Reset form elements
    document.getElementById('filter-category').value = '';
    document.getElementById('filter-criticality').value = '';
    document.getElementById('filter-investigation').value = '';
    document.getElementById('filter-windows-version').value = '';
    document.getElementById('filter-hive').value = '';
    document.getElementById('filter-has-tools').value = '';
    document.getElementById('search').value = '';
    
    // Reset quick filters
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector('.filter-btn[data-filter=\"all\"]').classList.add('active');
    
    // Reset filters object
    currentFilters = {
        search: '',
        category: '',
        criticality: '',
        investigation: '',
        windowsVersion: '',
        hive: '',
        hasTools: ''
    };
    
    performSearch();
}

// Perform search with all active filters
function performSearch() {
    const searchInput = document.getElementById('search');
    currentFilters.search = searchInput ? searchInput.value.toLowerCase() : '';
    
    filteredArtifacts = allArtifacts.filter(artifact => {
        // Text search
        if (currentFilters.search) {
            const searchableText = [
                artifact.title,
                artifact.description,
                artifact.category,
                ...(artifact.paths || []),
                ...(artifact.search_tags || []),
                ...(artifact.metadata?.tags || [])
            ].join(' ').toLowerCase();
            
            if (!searchableText.includes(currentFilters.search)) {
                return false;
            }
        }
        
        // Category filter
        if (currentFilters.category && artifact.category !== currentFilters.category) {
            return false;
        }
        
        // Criticality filter
        if (currentFilters.criticality) {
            const criticality = artifact.metadata?.criticality;
            if (criticality !== currentFilters.criticality) {
                return false;
            }
        }
        
        // Investigation type filter
        if (currentFilters.investigation) {
            const investigationTypes = artifact.metadata?.investigation_types || [];
            if (!investigationTypes.includes(currentFilters.investigation)) {
                return false;
            }
        }
        
        // Windows version filter
        if (currentFilters.windowsVersion) {
            const versions = artifact.metadata?.windows_versions || [];
            if (!versions.includes(currentFilters.windowsVersion)) {
                return false;
            }
        }
        
        // Registry hive filter
        if (currentFilters.hive) {
            const paths = artifact.paths || [];
            const hasHive = paths.some(path => path.startsWith(currentFilters.hive + '\\\\'));
            if (!hasHive) {
                return false;
            }
        }
        
        // Has tools filter
        if (currentFilters.hasTools) {
            const tools = artifact.details?.tools || [];
            const hasTools = tools.length > 0;
            if (currentFilters.hasTools === 'yes' && !hasTools) {
                return false;
            }
            if (currentFilters.hasTools === 'no' && hasTools) {
                return false;
            }
        }
        
        return true;
    });
    
    renderArtifacts(filteredArtifacts);
}

// Handle sorting
function handleSort() {
    const sortSelect = document.getElementById('sort-select');
    const sortBy = sortSelect.value;
    
    const sorted = [...filteredArtifacts].sort((a, b) => {
        switch (sortBy) {
            case 'title':
                return a.title.localeCompare(b.title);
            case 'title-desc':
                return b.title.localeCompare(a.title);
            case 'category':
                return a.category.localeCompare(b.category) || a.title.localeCompare(b.title);
            case 'criticality':
                const criticalityOrder = { 'high': 3, 'medium': 2, 'low': 1, 'unspecified': 0 };
                const aCrit = a.metadata?.criticality || 'unspecified';
                const bCrit = b.metadata?.criticality || 'unspecified';
                return criticalityOrder[bCrit] - criticalityOrder[aCrit] || a.title.localeCompare(b.title);
            case 'recent':
                const aDate = a.contribution?.date_added || '0000-00-00';
                const bDate = b.contribution?.date_added || '0000-00-00';
                return bDate.localeCompare(aDate) || a.title.localeCompare(b.title);
            default:
                return 0;
        }
    });
    
    renderArtifacts(sorted);
}

// Hide modal
function hideModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}

// Update statistics
function updateStats(statistics) {
    const elements = {
        'total-artifacts': statistics?.total || allArtifacts.length,
        'total-categories': statistics?.by_category ? Object.keys(statistics.by_category).length : 0,
        'visible-artifacts': filteredArtifacts.length,
        'high-criticality': statistics?.by_criticality?.high || 0
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });
}

// Update visible count
function updateVisibleCount(count) {
    const element = document.getElementById('visible-artifacts');
    if (element) {
        element.textContent = count;
    }
}

// Show error message
function showError(message) {
    const grid = document.getElementById('registry-grid');
    if (grid) {
        grid.innerHTML = `
            <div class="empty-state">
                <h3>Error</h3>
                <p>${message}</p>
            </div>
        `;
    }
}

// Utility: debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Load artifacts when page loads
document.addEventListener('DOMContentLoaded', loadArtifacts);
