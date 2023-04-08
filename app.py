from flask import Flask, request, render_template
import nmap
from threading import Thread

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the list of IP addresses from the form input
        ip_addresses = request.form['ip_addresses'].split(',')
        # Call scan_all_ports function
        scan_results = scan_all_ports(ip_addresses)
        # Render the results template with the scan results
        return render_template('results.html', results=scan_results)
    # Render the form template if no IP addresses were provided.
    return render_template('index.html')


def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p0-65535 -T4 -sS')
    open_ports = []
    for port in nm[ip]['tcp']:
        if nm[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

def scan_all_ports(ip_addresses):
    # Call scan function for each IP address using threading
    threads = []
    scan_results = []
    for ip_address in ip_addresses:
        t = Thread(target=scan_ports, args=(ip_address.strip(),))
        threads.append(t)
        t.start()
    # Wait for all threads to finish
    for t in threads:
        t.join()
    # Build scan_results list from the results of each thread
    for ip_address in ip_addresses:
        scan_result = {'ip_address': ip_address.strip(), 'open_ports': scan_ports(ip_address.strip())}
        scan_results.append(scan_result)
    return scan_results

if __name__ == '__main__':
    app.run(debug=True)
