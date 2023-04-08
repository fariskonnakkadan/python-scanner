from flask import Flask, request, render_template
import nmap
from threading import Thread

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the list of IP addresses from the form input
        ip_addresses = request.form['ip_addresses'].split(',')
        # Get the selected tool(s)
        selected_tools = []
        if 'nmap' in request.form:
            selected_tools.append('nmap')
        if 'nikto' in request.form:
            selected_tools.append('nikto')
        if 'zap' in request.form:
            selected_tools.append('zap')
        if 'nuclei' in request.form:
            selected_tools.append('nuclei')
        # Call scan_all_ports function with selected tool(s)
        scan_results = scan(ip_addresses, selected_tools)
        # Render the results template with the scan results
        return render_template('results.html', results=scan_results)
    # Render the form template if no IP addresses were provided.
    return render_template('index.html')

def scan(ip_addresses, selected_tools):
    scan_results = {}
    for tool in selected_tools:
        # Call the appropriate scan function and store the results in the dictionary
        if tool == 'nmap':
            scan_results['nmap'] = scan_nmap(ip_addresses)
        elif tool == 'nikto':
            scan_results['nikto'] = scan_nikto(ip_addresses)
        elif tool == 'zap':
            scan_results['zap'] = scan_zap(ip_addresses)
        elif tool == 'nuclei':
            scan_results['nuclei'] = scan_nuclei(ip_addresses)
    return scan_results



def scan_nikto(ip_addresses):
    # TODO: Implement nikto scanning function
    pass

def scan_zap(ip_addresses):
    # TODO: Implement zap scanning function
    pass

def scan_nuclei(ip_addresses):
    # TODO: Implement nuclei scanning function
    pass

def scan_nmap(ip_addresses):
    nmap_results = {}
    nm = nmap.PortScanner()
    for ip in ip_addresses:
        nm.scan(ip, arguments='-p0-65535 -T4 -sS')
        nmap_results[ip] = []
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                nmap_results[ip].append(port)
    print(nmap_results)
    return nmap_results




if __name__ == '__main__':
    app.run(debug=True)
