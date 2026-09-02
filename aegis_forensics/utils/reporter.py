import os
import json
import csv
from typing import Dict, Any, List
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisForensics Investigation Report</title>
    <style>
        :root {
            --primary-color: #1e293b;
            --secondary-color: #3b82f6;
            --accent-color: #ef4444;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #334155;
            --border-color: #e2e8f0;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 2rem;
            text-align: center;
            border-bottom: 4px solid var(--secondary-color);
        }
        header h1 {
            margin: 0;
            font-size: 2rem;
        }
        header p {
            margin: 0.5rem 0 0 0;
            color: #94a3b8;
        }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background-color: var(--card-bg);
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            border-left: 5px solid var(--secondary-color);
        }
        .card.danger {
            border-left-color: var(--accent-color);
        }
        .card h3 {
            margin: 0;
            font-size: 0.9rem;
            text-transform: uppercase;
            color: #64748b;
        }
        .card .value {
            font-size: 1.8rem;
            font-weight: bold;
            margin-top: 0.5rem;
            color: var(--primary-color);
        }
        .section {
            background-color: var(--card-bg);
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            margin-bottom: 2rem;
        }
        .section h2 {
            margin-top: 0;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 0.5rem;
            color: var(--primary-color);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: #f1f5f9;
            color: var(--primary-color);
            font-weight: 600;
        }
        tr:hover {
            background-color: #f8fafc;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge.success { background-color: #dcfce7; color: #15803d; }
        .badge.danger { background-color: #fee2e2; color: #b91c1c; }
        .badge.warning { background-color: #fef9c3; color: #a16207; }
        .search-box {
            width: 100%;
            padding: 0.5rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 1rem;
        }
    </style>
</head>
<body>
    <header>
        <h1>AegisForensics Forensic Report</h1>
        <p>Target: {{ data.target }} | Generated: {{ generated_time }}</p>
    </header>
    
    <div class="container">
        <div class="summary-cards">
            <div class="card">
                <h3>Logon Events</h3>
                <div class="value">{{ data.event_logs.logon_events | length if data.event_logs else 0 }}</div>
            </div>
            <div class="card danger">
                <h3>Cleared Audit Logs</h3>
                <div class="value">{{ data.event_logs.cleared_logs | length if data.event_logs else 0 }}</div>
            </div>
            <div class="card">
                <h3>Recovered Files</h3>
                <div class="value">{{ data.recovered_files | length }}</div>
            </div>
            <div class="card">
                <h3>Saved Passwords</h3>
                <div class="value">{{ data.browser_data.passwords | length if data.browser_data else 0 }}</div>
            </div>
        </div>
        
        <!-- System Info -->
        {% if data.system_info and data.system_info.os_info %}
        <div class="section">
            <h2>System Metadata</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                {% for key, val in data.system_info.os_info.items() %}
                <tr><td><strong>{{ key | title }}</strong></td><td>{{ val }}</td></tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        <!-- Cleared Logs Alert -->
        {% if data.event_logs and data.event_logs.cleared_logs %}
        <div class="section">
            <h2 style="color: var(--accent-color);">Anti-Forensic Alerts (Cleared Logs)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event ID</th>
                        <th>Computer</th>
                        <th>User</th>
                        <th>Provider</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in data.event_logs.cleared_logs %}
                    <tr>
                        <td>{{ log.timestamp }}</td>
                        <td><span class="badge danger">{{ log.event_id }}</span></td>
                        <td>{{ log.computer }}</td>
                        <td>{{ log.user }}</td>
                        <td>{{ log.provider }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Browser Passwords -->
        {% if data.browser_data and data.browser_data.passwords %}
        <div class="section">
            <h2>Decrypted Browser Credentials</h2>
            <input type="text" class="search-box" id="passwordsSearch" placeholder="Search passwords..." onkeyup="filterTable('passwordsSearch', 'passwordsTable')">
            <table id="passwordsTable">
                <thead>
                    <tr>
                        <th>Browser</th>
                        <th>URL</th>
                        <th>Username</th>
                        <th>Decrypted Password</th>
                    </tr>
                </thead>
                <tbody>
                    {% for pwd in data.browser_data.passwords %}
                    <tr>
                        <td>{{ pwd.browser }}</td>
                        <td><a href="{{ pwd.origin_url }}" target="_blank">{{ pwd.origin_url }}</a></td>
                        <td>{{ pwd.username }}</td>
                        <td><code>{{ pwd.password }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Logon Events -->
        {% if data.event_logs and data.event_logs.logon_events %}
        <div class="section">
            <h2>Login Audits</h2>
            <input type="text" class="search-box" id="logonSearch" placeholder="Search logons..." onkeyup="filterTable('logonSearch', 'logonTable')">
            <table id="logonTable">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Status</th>
                        <th>Username</th>
                        <th>Logon Type</th>
                        <th>IP Address</th>
                        <th>Computer</th>
                    </tr>
                </thead>
                <tbody>
                    {% for logon in data.event_logs.logon_events %}
                    <tr>
                        <td>{{ logon.timestamp }}</td>
                        <td>
                            <span class="badge {% if logon.status == 'Success' %}success{% else %}danger{% endif %}">
                                {{ logon.status }}
                            </span>
                        </td>
                        <td>{{ logon.username }}</td>
                        <td>{{ logon.logon_type }}</td>
                        <td>{{ logon.ip_address }}</td>
                        <td>{{ logon.computer }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Recovered Files -->
        {% if data.recovered_files %}
        <div class="section">
            <h2>Recycle Bin Recovered Files</h2>
            <input type="text" class="search-box" id="recoverySearch" placeholder="Search files..." onkeyup="filterTable('recoverySearch', 'recoveryTable')">
            <table id="recoveryTable">
                <thead>
                    <tr>
                        <th>Original Name</th>
                        <th>Original Path</th>
                        <th>Deletion Time</th>
                        <th>Size (Bytes)</th>
                        <th>Recoverable</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file in data.recovered_files %}
                    <tr>
                        <td>{{ file.original_name }}</td>
                        <td>{{ file.original_path }}</td>
                        <td>{{ file.deletion_time }}</td>
                        <td>{{ file.file_size }}</td>
                        <td>
                            {% if file.r_file_exists %}
                            <span class="badge success">Yes (Payload Intact)</span>
                            {% else %}
                            <span class="badge danger">No (Payload Overwritten)</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <!-- Persistence -->
        {% if data.system_info and data.system_info.persistence_keys %}
        <div class="section">
            <h2>Registry Autostart Run Keys (Persistence)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hive/Category</th>
                        <th>Name</th>
                        <th>Value / Command</th>
                    </tr>
                </thead>
                <tbody>
                    {% for run in data.system_info.persistence_keys %}
                    <tr>
                        <td><span class="badge warning">{{ run.category }}</span></td>
                        <td><strong>{{ run.name }}</strong></td>
                        <td><code>{{ run.value }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- USB History -->
        {% if data.system_info and data.system_info.usb_history %}
        <div class="section">
            <h2>USB Connection History</h2>
            <table>
                <thead>
                    <tr>
                        <th>Friendly Name</th>
                        <th>Device ID</th>
                        <th>Serial</th>
                    </tr>
                </thead>
                <tbody>
                    {% for usb in data.system_info.usb_history %}
                    <tr>
                        <td><strong>{{ usb.friendly_name }}</strong></td>
                        <td><code>{{ usb.device_id }}</code></td>
                        <td><code>{{ usb.serial }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
    </div>
    
    <script>
        function filterTable(inputId, tableId) {
            var input, filter, table, tr, td, i, j, txtValue, match;
            input = document.getElementById(inputId);
            filter = input.value.toUpperCase();
            table = document.getElementById(tableId);
            tr = table.getElementsByTagName("tr");
            
            for (i = 1; i < tr.length; i++) {
                tr[i].style.display = "none";
                td = tr[i].getElementsByTagName("td");
                match = false;
                for (j = 0; j < td.length; j++) {
                    if (td[j]) {
                        txtValue = td[j].textContent || td[j].innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            match = true;
                            break;
                        }
                    }
                }
                if (match) {
                    tr[i].style.display = "";
                }
            }
        }
    </script>
</body>
</html>
"""


def generate_html_report(results_data: Dict[str, Any], output_path: str):
    """
    Generates a beautiful self-contained HTML forensic report using Jinja2.
    """
    from datetime import datetime
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    template = Template(HTML_TEMPLATE)
    html_content = template.render(data=results_data, generated_time=generated_time)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_json_report(results_data: Dict[str, Any], output_path: str):
    """
    Generates a JSON dump of the forensic results.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=4, default=str)


def export_to_csv(data_list: List[Dict[str, Any]], output_path: str):
    """
    Helper to export list of flat dicts to CSV.
    """
    if not data_list:
        return
        
    keys = data_list[0].keys()
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data_list)
