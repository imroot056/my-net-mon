# Use an official Ubuntu image as the base
FROM ubuntu:latest

# Set environment variable to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update the package repository and install necessary packages
RUN apt-get update && \
    apt-get install -y git && \
    apt-get install -y python3 python3-pip python3-scapy && \
    apt-get clean && \
    apt-get install scapy && \
    apt install figlet && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages using pip
RUN pip3 install getmac

#Downloading the code from github
RUN git clone https://github.com/imroot056/my-net-mon.git

#Copy the application file to the container
RUN cp /my-net-mon/python-file/my-net-mon.py /opt/

# Create a directory for your application
WORKDIR /opt/
RUN mkdir logfiles

# Set the entry point and default command
ENTRYPOINT ["python3", "my-net-mon.py"]

CMD ["-w"]
