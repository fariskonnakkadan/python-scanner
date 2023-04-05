from flask import Flask, request, render_template
import nmap

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
@app.route('/trace', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the IP address from the form input
        ip_address = request.form['ip_address']

        # Call scan function
        scan_results = scan_ports(ip_address)

        # Render the results template with the scan results
        return render_template('results.html', results=scan_results)

    # Render the form template if no IP address was provided.
    return render_template('form.html')




def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p-')
    open_ports = []
    for port in nm[ip]['tcp']:
        if nm[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

if __name__ == '__main__':
    app.run(debug=True)
