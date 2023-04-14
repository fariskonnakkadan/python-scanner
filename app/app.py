from flask import Flask, request, render_template
import nmap
from threading import Thread
import subprocess, re, socket

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the list of IP addresses from the form input
        ip_addresses = re.split(',|\n|\s', request.form['ip_addresses'])
        print(ip_addresses)
        # Get the selected tool(s)
        selected_tools = []
        if 'nmap' in request.form:
            selected_tools.append('nmap')
        if 'nikto' in request.form:
            selected_tools.append('nikto')
        if 'zap' in request.form:
            selected_tools.append('sslscan')
        if 'nuclei' in request.form:
            selected_tools.append('nuclei')
        # Call scan_all_ports function with selected tool(s)
        scan_results = scan(ip_addresses, selected_tools)

        print(scan_results)
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
        elif tool == 'sslscan':
            scan_results['sslscan'] = scan_ssl(ip_addresses)
        elif tool == 'nuclei':
            scan_results['nuclei'] = scan_nuclei(ip_addresses)
    return scan_results


def scan_nikto(ip_addresses):
    nikto_results = {}
    for ip in ip_addresses:
        try:
            process = subprocess.Popen(['nikto', '-h', ip], stdout=subprocess.PIPE)
            stdout, _ = process.communicate()
            stdout = stdout.decode().strip()
            # Insert newline before each '+' sign
            nikto_results[ip] = stdout
        except subprocess.CalledProcessError:
            print(f"Error running nikto scan on IP address: {ip}")
    print(nikto_results)
    return nikto_results


def scan_nmap(ip_addresses):
    nmap_results = {}
    nm = nmap.PortScanner()
    for ip in ip_addresses:
        # Remove port number from input
        ip = re.sub(':[0-9]+', '', ip)
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            # Input is IP address
            nm.scan(ip, arguments='-p0-65535 -T4 -sS')
            nmap_results[ip] = []
            for port in nm[ip]['tcp']:
                if nm[ip]['tcp'][port]['state'] == 'open':
                    nmap_results[ip].append(port)
        else:
            # Input is domain name
            try:
                ip_address = socket.gethostbyname(ip)
                nm.scan(ip_address, arguments='-p0-65535 -T4 -sS')
                nmap_results[ip_address] = []
                for port in nm[ip_address]['tcp']:
                    if nm[ip_address]['tcp'][port]['state'] == 'open':
                        nmap_results[ip_address].append(port)
            except socket.gaierror:
                print(f"Could not resolve hostname: {ip}")
    print(nmap_results)
    return nmap_results


def scan_ssl(ip_addresses):
    ssl_results = {}
    for ip in ip_addresses:
        command = f"sslscan --no-colour {ip} "
        # Execute the command and capture the output
        try:
            output = subprocess.check_output(command, shell=True)
            ssl_results[ip] = output.decode().strip()
        except subprocess.CalledProcessError as e:
            print(f"Error running SSLScan command for {ip}: {e}")

    return ssl_results



def scan_nuclei(ip_addresses):
    nuclei_results = {}
    for ip in ip_addresses:
        command = f"nuclei -target {ip} -s low,medium,high,critical"
        # Execute the command and capture the output
        try:
            output = subprocess.check_output(command, shell=True)
            nuclei_results[ip] = output.decode().strip()
        except subprocess.CalledProcessError as e:
            print(f"Error running Nuclei command for {ip}: {e}")

    return nuclei_results







if __name__ == '__main__':
    app.run(debug=True)
