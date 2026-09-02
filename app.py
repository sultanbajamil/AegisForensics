import os
import streamlit as st
import pandas as pd
import plotly.express as px
from aegis_forensics.core.engine import ForensicEngine
from aegis_forensics.core.memory import carve_memory_generator
from aegis_forensics.utils.reporter import generate_html_report
from aegis_forensics.plugins.file_recovery import recover_file

# Set up Streamlit page config
st.set_page_config(
    page_title="AegisForensics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# App Styling
st.markdown("""
<style>
    .reportview-container {
        background: #f8fafc;
    }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        border-left: 5px solid #3b82f6;
        margin-bottom: 10px;
    }
    .metric-title {
        font-size: 14px;
        color: #64748b;
        text-transform: uppercase;
        font-weight: 600;
    }
    .metric-value {
        font-size: 28px;
        font-weight: bold;
        color: #1e293b;
        margin-top: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Main Title
st.title("🛡️ AegisForensics Investigation Dashboard")
st.caption("Digital Forensics & Incident Response (DFIR) Analysis Suite")

# Sidebar Configuration
st.sidebar.header("🔍 Analysis Scope")
mode = st.sidebar.selectbox(
    "Ingestion Mode",
    ["Live System Analysis", "Offline Folder / Disk Mount", "Memory Dump Carver"]
)

# Initialize Session States
if "results" not in st.session_state:
    st.session_state.results = None
if "memory_results" not in st.session_state:
    st.session_state.memory_results = None

# Configure based on Mode
if mode == "Live System Analysis":
    st.sidebar.info("👉 This will scan the host computer. Requires elevated/Administrator privileges to access System Event Logs.")
    collect_system = st.sidebar.checkbox("System Metadata & USB History", value=True)
    collect_browsers = st.sidebar.checkbox("Browser History & Credentials", value=True)
    collect_logs = st.sidebar.checkbox("Windows Event Logs", value=True)
    collect_recovery = st.sidebar.checkbox("Recycle Bin File Recovery", value=True)
    max_logs = st.sidebar.number_input("Max logs to parse per file", min_value=100, max_value=50000, value=5000, step=500)
    
    if st.sidebar.button("Run Live Investigation", type="primary"):
        with st.spinner("Analyzing host system..."):
            engine = ForensicEngine()
            st.session_state.results = engine.run_live_or_offline_analysis(
                collect_system=collect_system,
                collect_browsers=collect_browsers,
                collect_logs=collect_logs,
                collect_recovery=collect_recovery,
                max_log_records=max_logs
            )
            st.success("Investigation complete!")

elif mode == "Offline Folder / Disk Mount":
    offline_path = st.sidebar.text_input("Target Directory Path (e.g. D:\\ or E:\\)", value="")
    collect_system = st.sidebar.checkbox("System Metadata & USB History", value=True)
    collect_browsers = st.sidebar.checkbox("Browser History & Credentials", value=True)
    collect_logs = st.sidebar.checkbox("Windows Event Logs", value=True)
    collect_recovery = st.sidebar.checkbox("Recycle Bin File Recovery", value=True)
    max_logs = st.sidebar.number_input("Max logs to parse per file", min_value=100, max_value=50000, value=5000, step=500)
    
    if st.sidebar.button("Run Offline Investigation", type="primary"):
        if not offline_path or not os.path.exists(offline_path):
            st.sidebar.error("Please enter a valid offline path.")
        else:
            with st.spinner(f"Analyzing directory {offline_path}..."):
                engine = ForensicEngine(system_root=offline_path)
                st.session_state.results = engine.run_live_or_offline_analysis(
                    collect_system=collect_system,
                    collect_browsers=collect_browsers,
                    collect_logs=collect_logs,
                    collect_recovery=collect_recovery,
                    max_log_records=max_logs
                )
                st.success("Investigation complete!")

elif mode == "Memory Dump Carver":
    mem_file_path = st.sidebar.text_input("Memory Dump File Path (.raw/.dmp)", value="")
    
    if st.sidebar.button("Start Memory Carving", type="primary"):
        if not mem_file_path or not os.path.exists(mem_file_path):
            st.sidebar.error("Please provide a valid memory dump file path.")
        else:
            progress_bar = st.sidebar.progress(0.0)
            status_text = st.sidebar.empty()
            
            # Setup container for realtime metrics
            st.info("Scanning memory dump. Metrics will update in real time below.")
            metrics_container = st.empty()
            
            carver = carve_memory_generator(mem_file_path)
            for update in carver:
                if update["status"] == "start":
                    status_text.text(f"Scanning memory dump ({update['file_size'] / (1024*1024):.2f} MB)...")
                elif update["status"] == "progress":
                    progress_bar.progress(update["progress"] / 100.0)
                    status_text.text(f"Scanning progress: {update['progress']:.1f}%")
                    
                    # Update real time metrics
                    c = update["counts"]
                    metrics_container.markdown(f"""
                    ### Current Carved Artifact Counts:
                    - **IP Addresses Found:** `{c['ips']}`
                    - **Email Addresses Found:** `{c['emails']}`
                    - **URLs Extracted:** `{c['urls']}`
                    - **AWS Access Keys Extracted:** `{c['aws_keys']}`
                    - **Private Keys Headers:** `{c['private_keys']}`
                    """)
                elif update["status"] == "complete":
                    st.session_state.memory_results = update["results"]
                    progress_bar.progress(1.0)
                    status_text.text("Carving complete!")
                    st.success("Memory carving operation completed successfully.")
                elif update["status"] == "error":
                    st.sidebar.error(update["message"])

# Present Data UI
if mode in ["Live System Analysis", "Offline Folder / Disk Mount"]:
    res = st.session_state.results
    
    if res is not None:
        # Display errors/warnings if any
        if res.get("errors"):
            with st.expander("⚠️ Collection Warnings & Errors"):
                for err in res["errors"]:
                    st.warning(err)
                    
        # Summary Row
        col1, col2, col3, col4 = st.columns(4)
        
        # Count elements
        browser_data = res.get("browser_data", {})
        history_cnt = len(browser_data.get("history", []))
        pass_cnt = len(browser_data.get("passwords", []))
        
        event_logs = res.get("event_logs", {})
        logon_cnt = len(event_logs.get("logon_events", []))
        cleared_cnt = len(event_logs.get("cleared_logs", []))
        
        rec_cnt = len(res.get("recovered_files", []))
        
        with col1:
            st.markdown(f"""<div class="metric-card"><div class="metric-title">Logon Audits</div><div class="metric-value">{logon_cnt}</div></div>""", unsafe_allow_html=True)
        with col2:
            # Danger border color for anti-forensic events
            st.markdown(f"""<div class="metric-card" style="border-left-color: #ef4444;"><div class="metric-title">Cleared Audit Logs</div><div class="metric-value" style="color: #ef4444;">{cleared_cnt}</div></div>""", unsafe_allow_html=True)
        with col3:
            st.markdown(f"""<div class="metric-card" style="border-left-color: #10b981;"><div class="metric-title">Recoverable Files</div><div class="metric-value" style="color: #10b981;">{rec_cnt}</div></div>""", unsafe_allow_html=True)
        with col4:
            st.markdown(f"""<div class="metric-card" style="border-left-color: #8b5cf6;"><div class="metric-title">Saved Credentials</div><div class="metric-value" style="color: #8b5cf6;">{pass_cnt}</div></div>""", unsafe_allow_html=True)
            
        # Create Tabs
        tab_dashboard, tab_system, tab_browsers, tab_events, tab_files, tab_report = st.tabs([
            "📊 Dashboard", "🖥️ System & USBs", "🌐 Browser Forensics", "📝 Event Log Analyzer", "🗑️ Recycle Bin Recovery", "📁 Report Export"
        ])
        
        # 1. DASHBOARD TAB
        with tab_dashboard:
            st.subheader("Security Timeline & Threat Overview")
            
            # Plot logon events timeline if available
            logons = event_logs.get("logon_events", [])
            if logons:
                df_logon = pd.DataFrame(logons)
                # Convert system system time string to pandas datetime
                df_logon["timestamp"] = pd.to_datetime(df_logon["timestamp"])
                df_logon["Date"] = df_logon["timestamp"].dt.date
                
                # Count logons by date and status
                df_grouped = df_logon.groupby(["Date", "status"]).size().reset_index(name="Count")
                
                fig = px.bar(
                    df_grouped, x="Date", y="Count", color="status",
                    title="Logon Success vs Failure Timeline",
                    labels={"status": "Authentication Status", "Count": "Number of Events"},
                    color_discrete_map={"Success": "#3b82f6", "Failure": "#ef4444"}
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No logon events available to render timeline.")
                
            # Process overview
            sys_info = res.get("system_info", {})
            procs = sys_info.get("running_processes", [])
            if procs:
                df_procs = pd.DataFrame(procs)
                st.subheader(f"Running Processes ({len(df_procs)} total)")
                
                # Group by image name to find highest count processes
                proc_counts = df_procs["name"].value_counts().reset_index()
                proc_counts.columns = ["Process Name", "Instances"]
                
                col_chart, col_table = st.columns([2, 1])
                with col_chart:
                    fig_proc = px.bar(
                        proc_counts.head(15), x="Process Name", y="Instances",
                        title="Top Running Processes (by Instance Count)"
                    )
                    st.plotly_chart(fig_proc, use_container_width=True)
                with col_table:
                    st.dataframe(proc_counts.head(15), use_container_width=True)
            else:
                st.info("No process metrics available.")

        # 2. SYSTEM INFO & USB TAB
        with tab_system:
            sys_info = res.get("system_info", {})
            
            # OS Details
            st.subheader("OS Configuration Details")
            if sys_info.get("os_info"):
                st.json(sys_info["os_info"])
                
            # Persistence Autostart Keys
            st.subheader("Autostart Run Keys (Persistence Vectors)")
            run_keys = sys_info.get("persistence_keys", [])
            if run_keys:
                df_run = pd.DataFrame(run_keys)
                st.dataframe(df_run, use_container_width=True)
            else:
                st.info("No persistence keys detected in standard Run locations.")
                
            # USB History
            st.subheader("USB Device Connection History")
            usb_hist = sys_info.get("usb_history", [])
            if usb_hist:
                df_usb = pd.DataFrame(usb_hist)
                st.dataframe(df_usb, use_container_width=True)
            else:
                st.info("No USB connection history found in USBSTOR.")
                
            # Active Connections
            st.subheader("Active Socket Connections")
            conn_list = sys_info.get("network_connections", [])
            if conn_list:
                df_conn = pd.DataFrame(conn_list)
                st.dataframe(df_conn, use_container_width=True)
            else:
                st.info("No active network connections found.")

        # 3. BROWSER FORENSICS TAB
        with tab_browsers:
            st.subheader("Saved Browser Credentials")
            passwords = browser_data.get("passwords", [])
            if passwords:
                df_pass = pd.DataFrame(passwords)
                st.dataframe(df_pass, use_container_width=True)
            else:
                st.info("No browser passwords extracted or decrypted (may require DPAPI permission).")
                
            st.subheader("Web Browsing History (Searchable)")
            history = browser_data.get("history", [])
            if history:
                df_hist = pd.DataFrame(history)
                search_query = st.text_input("Filter Browser History (e.g. search keyword or domain)", "")
                if search_query:
                    # Filter across url and title columns
                    df_filtered = df_hist[
                        df_hist["url"].str.contains(search_query, case=False, na=False) |
                        df_hist["title"].str.contains(search_query, case=False, na=False)
                    ]
                else:
                    df_filtered = df_hist
                st.dataframe(df_filtered.head(1000), use_container_width=True)
            else:
                st.info("No browser history entries found.")

        # 4. EVENT LOG ANALYZER TAB
        with tab_events:
            st.subheader("Anti-Forensic Events (Audit Log Cleared)")
            cleared = event_logs.get("cleared_logs", [])
            if cleared:
                st.warning(f"🚨 Detected {len(cleared)} logs cleared events! This represents active anti-forensics behavior.")
                df_cleared = pd.DataFrame(cleared)
                st.dataframe(df_cleared, use_container_width=True)
            else:
                st.success("No audit log clearing events found.")
                
            st.subheader("Logon Audits (ID 4624 / 4625)")
            logons = event_logs.get("logon_events", [])
            if logons:
                df_logon = pd.DataFrame(logons)
                st.dataframe(df_logon, use_container_width=True)
            else:
                st.info("No logon events extracted.")
                
            st.subheader("Process Creation Events (ID 4688 / Sysmon 1)")
            creations = event_logs.get("process_creations", [])
            if creations:
                df_creations = pd.DataFrame(creations)
                st.dataframe(df_creations, use_container_width=True)
            else:
                st.info("No process execution logs parsed.")
                
            st.subheader("New Windows Services (Persistence)")
            services = event_logs.get("services_installed", [])
            if services:
                df_services = pd.DataFrame(services)
                st.dataframe(df_services, use_container_width=True)
            else:
                st.info("No new service installation logs found.")

        # 5. RECYCLE BIN FILE RECOVERY TAB
        with tab_files:
            st.subheader("Recycle Bin File Recoverer")
            st.write("Below is a catalog of files deleted to the Recycle Bin. If the payload is intact, you can recover the file contents directly.")
            
            recovered_files = res.get("recovered_files", [])
            if recovered_files:
                df_files = pd.DataFrame(recovered_files)
                # Drop details column for clean dataframe presentation
                cols_to_show = ["original_name", "original_path", "deletion_time", "file_size", "r_file_exists", "r_file_path"]
                st.dataframe(df_files[cols_to_show], use_container_width=True)
                
                # Restore Panel
                st.markdown("### 📥 Recover File Payload")
                recoverable_options = [f for f in recovered_files if f["r_file_exists"]]
                
                if recoverable_options:
                    selected_file_desc = st.selectbox(
                        "Select file to restore",
                        options=[f["original_name"] + " | " + f["deletion_time"] for f in recoverable_options]
                    )
                    
                    # Resolve which file object matches selection
                    selected_idx = [f["original_name"] + " | " + f["deletion_time"] for f in recoverable_options].index(selected_file_desc)
                    selected_file = recoverable_options[selected_idx]
                    
                    dest_dir = st.text_input("Recovery Destination Directory", value=os.path.join(os.path.expanduser("~"), "Desktop", "Recovered_Files"))
                    if st.button("Recover Selected File"):
                        result = recover_file(
                            selected_file["r_file_path"],
                            dest_dir,
                            selected_file["original_name"]
                        )
                        if result.startswith("Failed") or result.startswith("Source"):
                            st.error(result)
                        else:
                            st.success(f"File successfully recovered to: {result}")
                else:
                    st.info("No files currently have their content payloads intact. Only metadata is available.")
            else:
                st.info("No deleted files found in the Recycle Bin.")

        # 6. REPORT EXPORT TAB
        with tab_report:
            st.subheader("Generate Forensic Investigation Reports")
            st.write("Export collected results into standardized forensic file formats.")
            
            report_name = st.text_input("Report Filename Prefix", value="aegis_forensic_report")
            
            col_html, col_json = st.columns(2)
            with col_html:
                st.markdown("#### HTML Investigation Report")
                st.write("Generates a highly stylized, interactive HTML file with timelines, search filters, and summaries.")
                if st.button("Generate HTML Report"):
                    filename = f"{report_name}.html"
                    try:
                        generate_html_report(res, filename)
                        st.success(f"Report written to local project folder: `{filename}`")
                    except Exception as e:
                        st.error(f"Failed to generate report: {e}")
            with col_json:
                st.markdown("#### Raw JSON Results")
                st.write("Generates a structured JSON file containing all parsed schemas, ready to feed into SIEMs or scripts.")
                if st.button("Generate JSON Report"):
                    filename = f"{report_name}.json"
                    try:
                        import json
                        with open(filename, "w", encoding="utf-8") as f:
                            json.dump(res, f, indent=4, default=str)
                        st.success(f"JSON results written to local folder: `{filename}`")
                    except Exception as e:
                        st.error(f"Failed to generate JSON: {e}")

    else:
        st.info("👈 Set your analysis scope and click 'Run Live Investigation' in the sidebar to start.")

# Present Memory Carver UI
elif mode == "Memory Dump Carver":
    mem_res = st.session_state.memory_results
    
    if mem_res is not None:
        st.subheader("Memory Carving Search Dashboard")
        
        # Tabs for memory findings
        tab_ips, tab_emails, tab_urls, tab_keys = st.tabs([
            "🌐 Carved IP Addresses", "📧 Carved Emails", "🔗 Carved URLs", "🔑 Carved API Keys & Secrets"
        ])
        
        with tab_ips:
            ips = mem_res.get("ips", [])
            st.write(f"**Total IPs Extracted:** `{len(ips)}`")
            if ips:
                st.dataframe(pd.DataFrame(ips, columns=["IP Address"]), use_container_width=True)
            else:
                st.info("No valid IP addresses identified.")
                
        with tab_emails:
            emails = mem_res.get("emails", [])
            st.write(f"**Total Emails Extracted:** `{len(emails)}`")
            if emails:
                st.dataframe(pd.DataFrame(emails, columns=["Email Address"]), use_container_width=True)
            else:
                st.info("No email addresses identified.")
                
        with tab_urls:
            urls = mem_res.get("urls", [])
            st.write(f"**Total URLs Extracted:** `{len(urls)}`")
            if urls:
                df_urls = pd.DataFrame(urls, columns=["URL"])
                search_url = st.text_input("Filter URLs (e.g. login, .exe, C2 domain)", "")
                if search_url:
                    df_filtered_urls = df_urls[df_urls["URL"].str.contains(search_url, case=False, na=False)]
                else:
                    df_filtered_urls = df_urls
                st.dataframe(df_filtered_urls, use_container_width=True)
            else:
                st.info("No URLs identified.")
                
        with tab_keys:
            aws_keys = mem_res.get("aws_keys", [])
            priv_keys = mem_res.get("private_keys", [])
            
            st.markdown("#### ☁️ AWS Keys (AKIA)")
            if aws_keys:
                st.dataframe(pd.DataFrame(aws_keys, columns=["AWS Key"]), use_container_width=True)
            else:
                st.info("No AWS Access Keys found.")
                
            st.markdown("#### 🔒 RSA/Private Keys Headers")
            if priv_keys:
                st.dataframe(pd.DataFrame(priv_keys, columns=["Header Signature"]), use_container_width=True)
            else:
                st.info("No PEM/Private key signatures found.")
    else:
        st.info("👈 Enter the path to your RAM dump file (.raw or .dmp) and click 'Start Memory Carving' to begin.")
