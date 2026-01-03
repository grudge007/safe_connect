// Main JS - Safe Connect UI

// Utility: Format Date
function formatDate(timestamp) {
    if (!timestamp) return 'N/A';
    return timestamp;
}

// Utility: Create Risk Badge
function createRiskBadge(level) {
    let icon = '';
    if (level === 'SAFE') icon = '<i class="fa-solid fa-check"></i>';
    else if (level === 'SUSPICIOUS') icon = '<i class="fa-solid fa-triangle-exclamation"></i>';
    else if (level === 'MALICIOUS') icon = '<i class="fa-solid fa-skull-crossbones"></i>';
    else icon = '<i class="fa-solid fa-question"></i>';

    return `<span class="badge badge-${level}">${icon} ${level}</span>`;
}

// Global: History Data for filtering
let allHistoryData = [];
// Global: Connections Data for pagination
let allConnectionsData = [];
let currentPage = 1;
const ITEMS_PER_PAGE = 25;

// Fetch Dashboard Data
async function fetchData() {
    const tableBody = document.getElementById('connections-table-body');
    const updateTime = document.getElementById('last-updated');
    const refreshBtn = document.getElementById('refresh-btn');

    // Rotate animation
    if (refreshBtn) refreshBtn.style.transform = 'rotate(360deg)';

    try {
        const response = await fetch('/api/data');
        const data = await response.json();

        // Update Stats
        document.getElementById('stat-all').textContent = data.stats.all;
        document.getElementById('stat-safe').textContent = data.stats.safe;
        document.getElementById('stat-suspicious').textContent = data.stats.suspicious;
        document.getElementById('stat-malicious').textContent = data.stats.malicious;

        // Store all data and render current page
        allConnectionsData = data.connections;
        renderDashboardTable();

        // Update Last Updated
        if (updateTime) {
            const now = new Date();
            updateTime.textContent = 'Updated: ' + now.toLocaleTimeString();
        }

    } catch (error) {
        console.error('Error fetching data:', error);
        if (tableBody) tableBody.innerHTML = '<tr><td colspan="8" class="loading-cell" style="color:var(--malicious-color)">Error connecting to server</td></tr>';
    }

    // Reset animation
    setTimeout(() => {
        if (refreshBtn) refreshBtn.style.transform = 'none';
    }, 500);
}

function renderDashboardTable() {
    const tableBody = document.getElementById('connections-table-body');
    const pageInfo = document.getElementById('d-page-info');

    if (!tableBody) return;

    if (allConnectionsData.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="8" class="loading-cell">No active connections found</td></tr>';
        if (pageInfo) pageInfo.textContent = 'Page 1 of 1';
        updatePaginationControls(1);
        return;
    }

    const totalPages = Math.ceil(allConnectionsData.length / ITEMS_PER_PAGE);
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const start = (currentPage - 1) * ITEMS_PER_PAGE;
    const end = start + ITEMS_PER_PAGE;
    const paginatedData = allConnectionsData.slice(start, end);

    tableBody.innerHTML = '';

    paginatedData.forEach(conn => {
        const row = `
            <tr>
                <td>${conn.ip}</td>
                <td>${conn.hostname}</td>
                <td>${conn.country}</td>
                <td>${conn.local_port} <span style="color:var(--text-secondary)">/</span> ${conn.remote_port}</td>
                <td>${conn.pid}</td>
                <td>${createRiskBadge(conn.risk_level)}</td>
                <td>${conn.abuse_score}</td>
                <td>${formatDate(conn.last_scanned)}</td>
            </tr>
        `;
        tableBody.innerHTML += row;
    });

    if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages || 1}`;
    updatePaginationControls(totalPages);
}

function updatePaginationControls(totalPages) {
    const btnFirst = document.getElementById('d-first-btn');
    const btnPrev = document.getElementById('d-prev-btn');
    const btnNext = document.getElementById('d-next-btn');
    const btnLast = document.getElementById('d-last-btn');

    if (btnFirst) btnFirst.disabled = currentPage === 1;
    if (btnPrev) btnPrev.disabled = currentPage === 1;
    if (btnNext) btnNext.disabled = currentPage >= totalPages;
    if (btnLast) btnLast.disabled = currentPage >= totalPages;
}

function changePage(action) {
    const totalPages = Math.ceil(allConnectionsData.length / ITEMS_PER_PAGE);

    switch (action) {
        case 'first': currentPage = 1; break;
        case 'prev': if (currentPage > 1) currentPage--; break;
        case 'next': if (currentPage < totalPages) currentPage++; break;
        case 'last': currentPage = totalPages; break;
    }
    renderDashboardTable();
}

// Fetch History Data
async function fetchHistory() {
    const tableBody = document.getElementById('history-table-body');

    try {
        const response = await fetch('/api/history');
        allHistoryData = await response.json();

        // Sort: Active first
        allHistoryData.sort((a, b) => {
            if (a.is_active === b.is_active) return 0;
            return a.is_active ? -1 : 1;
        });

        renderHistory(allHistoryData);

        // Init Filters
        setupFilters();

    } catch (error) {
        console.error('Error fetching history:', error);
        if (tableBody) tableBody.innerHTML = '<tr><td colspan="7" class="loading-cell" style="color:var(--malicious-color)">Error connecting to server</td></tr>';
    }
}

function renderHistory(data) {
    const tableBody = document.getElementById('history-table-body');
    if (!tableBody) return;

    tableBody.innerHTML = '';

    if (data.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="loading-cell">No history found</td></tr>';
        return;
    }

    data.forEach(item => {
        const dotColor = item.is_active ? 'var(--safe-color)' : 'var(--malicious-color)';
        const row = `
            <tr>
                <td>
                    <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background-color:${dotColor}; margin-right:8px;" title="${item.is_active ? 'Active' : 'Not Active'}"></span>
                    ${item.ip}
                </td>
                <td>${item.hostname}</td>
                <td>${item.country}</td>
                <td>${createRiskBadge(item.risk_level)}</td>
                <td>${formatDate(item.first_seen)}</td>
                <td>${formatDate(item.last_seen)}</td>
                <td>${item.times_seen}</td>
            </tr>
        `;
        tableBody.innerHTML += row;
    });
}

function setupFilters() {
    const searchInput = document.getElementById('history-search');
    const filterSelect = document.getElementById('history-filter');

    if (!searchInput || !filterSelect) return;

    function filterData() {
        const searchTerm = searchInput.value.toLowerCase();
        const riskFilter = filterSelect.value;

        const filtered = allHistoryData.filter(item => {
            const matchesSearch = item.ip.toLowerCase().includes(searchTerm) ||
                item.hostname.toLowerCase().includes(searchTerm);
            const matchesRisk = riskFilter === 'all' || item.risk_level === riskFilter;

            return matchesSearch && matchesRisk;
        });

        renderHistory(filtered);
    }

    searchInput.addEventListener('input', filterData);
    filterSelect.addEventListener('change', filterData);
}

// Redirect on Stat Card Click (Dashboard)
document.addEventListener('DOMContentLoaded', () => {
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach(card => {
        card.addEventListener('click', () => {
            const category = card.dataset.category;
            window.location.href = `/history?filter=${category}`;
        });
    });

    // Handle Query Params on History Page
    if (window.location.pathname === '/history') {
        const urlParams = new URLSearchParams(window.location.search);
        const filterParam = urlParams.get('filter');
        const filterSelect = document.getElementById('history-filter');

        if (filterParam && filterSelect) {
            setTimeout(() => {
                const option = filterSelect.querySelector(`option[value="${filterParam.toUpperCase()}"]`);
                if (option || filterParam === 'all') {
                    filterSelect.value = filterParam === 'all' ? 'all' : filterParam.toUpperCase();
                    // Manually trigger change event if we had data loaded
                    filterSelect.dispatchEvent(new Event('change'));
                }
            }, 500);
        }
    }
});
