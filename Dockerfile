# Use the official Ubuntu image as the base image
FROM ubuntu

# Copy the "app" folder to the Docker image
COPY app /app

# Install Go
RUN apt-get update && \
    apt-get install -y curl && \
    curl -O https://dl.google.com/go/go1.17.6.linux-amd64.tar.gz && \
    tar -xvf go1.17.6.linux-amd64.tar.gz && \
    mv go /usr/bin && \
    rm go1.17.6.linux-amd64.tar.gz && \
    export PATH=$PATH:/usr/bin && \
    echo "export PATH=$PATH:/usr/bin" >> ~/.bashrc


# Install Nuclei
RUN apt-get install git -y
RUN apt-get install unzip -y
RUN apt-get install wget -y
# Download the nuclei binary from GitHub
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.1/nuclei_2.9.1_linux_amd64.zip

# Extract the binary
RUN unzip nuclei_2.9.1_linux_amd64.zip && \
mv nuclei /usr/bin && \
chmod +x /usr/bin/nuclei


# Install Nikto
RUN apt-get install -y nikto

# Install Python 3 and pip
RUN apt-get install -y python3 python3-pip

# Install required Python packages
RUN pip3 install python-nmap flask requests

# Set the working directory to /app
WORKDIR /app

# Start the Flask app
CMD ["python3", "app.py"]
