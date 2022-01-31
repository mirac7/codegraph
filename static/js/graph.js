const vertexTypeLabels = {
    "python-package": "Python package",
    "repository": "Repository",
}
const defaultNodeStyle = {
    shape: 'box', vadjust: 2, font: {
        multi: 'html', color: '#fff', size: 14, pxface: 'arial', align: 'left',
        bold: {color: "#fff", size: 18}, italic: {color: '#fff8'}
    },
    color: {border: "#fff", background: '#0f1421', highlight: {border: "#fff", background: '#0f1421'}},
    borderWidth: 2, margin: 16,
    tooltipDelay: 0
};
const defaultCVEStyle = {
    shape: 'box', vadjust: 2,
    borderWidth: 2, margin: 16, widthConstraint: {maximum: 400},
    tooltipDelay: 0,
};
const criticalCVEStyle = {
    color: {border: "#f42", background: '#0f1421', highlight: {border: "#f42", background: '#0f1421'}},
    font: {
        multi: 'html', color: '#f42', size: 14, pxface: 'arial', align: 'left',
        bold: {color: "#f42", size: 18}, italic: {color: '#fff8'}
    },
}
const highCVEStyle = {
    color: {border: "#f92", background: '#0f1421', highlight: {border: "#f92", background: '#0f1421'}},
    font: {
        multi: 'html', color: '#f92', size: 14, pxface: 'arial', align: 'left',
        bold: {color: "#f92", size: 18}, italic: {color: '#fff8'}
    },
}
const lowCVEStyle = {
    color: {border: "#fe2", background: '#0f1421', highlight: {border: "#fe2", background: '#0f1421'}},
    font: {
        multi: 'html', color: '#fe2', size: 14, pxface: 'arial', align: 'left',
        bold: {color: "#fe2", size: 18}, italic: {color: '#fff8'}
    },
}

function escape(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function renderGraph(nodes, edges) {
    const network = new vis.Network(document.getElementById('graph'), {nodes, edges}, {
        edges: {arrows: "middle"},
        physics: {solver: "repulsion", repulsion: {springLength: 200, nodeDistance: 600, damping: 0.09},},
    });
    network.on('doubleClick', function(properties) {
        if (properties.nodes && properties.nodes.length) {
            console.log(properties.nodes[0]);
        }
    });
}

async function fetchGraph(url, pruned) {
    const response = await fetch(`/get_repo_insights?query=${encodeURIComponent(url)}`);
    const {found, report} = await response.json()
    if (found) buildGraph(report, pruned);
    else window.location.href = `/?query=${encodeURIComponent(url)}`;
}

function buildGraph(report, pruned=false) {
    let {vertices, edges, meta} = report;

    if (pruned) {
        while (true) {
            const prunedVertices = new Set([
                ...edges.map(e => e.from),
                ...vertices.filter(v => v.type === "CVE").map(({name}) => name)
            ]);
            if (prunedVertices.size < vertices.length) {
                vertices = vertices.filter(({name, type}) => prunedVertices.has(name) || type === "CVE");
                edges = edges.filter(({from, to}) => prunedVertices.has(from) && prunedVertices.has(to));
            }
            else break;
        }
    }

    const graphNodes = vertices.map((vertex) => {
        const {name, type} = vertex;

        let text = `<b>${escape(name)}</b>\n`;
        let nodeStyle;

        if (type === "package") {
            text += `<i>${vertexTypeLabels[vertex.package_type]}</i>`;
            nodeStyle = defaultNodeStyle;
        } else {
            const {description, cvss_v2_score, cvss_v3_score, publish_date} = vertex;
            text += `<i>${description}</i>\n\nCVSS v2 score: ${cvss_v2_score}\nCVSS v3 score: ${cvss_v3_score}\nPublished: ${publish_date}\n`;

            let severity = Number(cvss_v3_score);
            if (isNaN(severity)) severity = Number(cvss_v2_score);

            if (isNaN(severity) || severity < 4) nodeStyle = {...defaultCVEStyle, ...lowCVEStyle};
            else if (severity < 8) nodeStyle = {...defaultCVEStyle, ...highCVEStyle};
            else nodeStyle = {...defaultCVEStyle, ...criticalCVEStyle};
        }
        return {id: name, label: text, ...nodeStyle};
    });

    const graphEdges = edges.map(({from, to, type, version, affected_version}) => {
        let title;
        if (type === "dependency") {
            title = `${from} &rarr; ${to}<br><br>`;
            if (version === "") title += `<span class="version">Version unconstrained</span>`;
            else title += `<span class="version">Version constraint:<br>${version.split(",").map(x => `${escape(x.replace(/:/, ' '))}`).join('<br>')}</span>`
        } else {
            title = `Vulnerability<br>Affected versions: ${affected_version}`;
        }
        return {from, to, color: {dependency: "#fff", vulnerability: "#f00"}[type], title}
    });

    populateGraphSummary(vertices, edges, meta, pruned);
    renderGraph(graphNodes, graphEdges);
}
function populateGraphSummary(vertices, edges, meta, pruned) {
    let html = `<h1>Graph for ${escape(query)}</h1>`;

    const all_vulnerabilities = new Set();
    for (const {name, type} of vertices) {
        if (type !== "CVE") continue;
        all_vulnerabilities.add(name);
    }
    if (all_vulnerabilities.size) {
        html += `<p class='vulnerabilities'> Found ${all_vulnerabilities.size} vulnerabilities: `;
        html += [...all_vulnerabilities].map(
            cve => `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank">${cve}</a>`
        ).join(", ");

        html += "</p>"
    } else html += "<p class='no-vulnerabilities'>No vulnerabilities found!</p>";

    const {created} = meta;
    html += `<p class='meta'>
        ${vertices.length} vertices, ${edges.length} edges<br>
        Generated on ${created}<br>
    </p>`;

    if (pruned) html += `<p class='meta'>
        This graph has been pruned of dependencies with no found vulnerabilities. <a href="?query=${encodeURIComponent(query)}&skip_prune=1">Click here</a> to display entire graph <a href="?query=${encodeURIComponent(query)}">check another repository</a> for common vulnerabilities or exploits.
    </p>`;
    else html += `<p class='meta'>
        <a href="?query=${encodeURIComponent(query)}">Click here</a> to prune dependencies with no found vulnerabilities or <a href="?query=${encodeURIComponent(query)}">check another repository</a> for common vulnerabilities or exploits.
    </p>`;

    document.getElementById("summary").innerHTML = html;
}

const searchParams = new URL(window.location).searchParams
const query = searchParams.get("query");
const pruneGraph = !searchParams.get("skip_prune");
fetchGraph(query, pruneGraph);
