# ReconMatrix

ReconMatrix is a Python-based tool for performing reconnaissance on target domains. It provides functionalities such as subdomain enumeration, WHOIS lookup, directory scanning, and Nmap port scanning.

## Features

- Subdomain enumeration: Discover subdomains associated with a target domain.
- WHOIS lookup: Retrieve WHOIS information for a domain, including registrar, creation date, expiration date, and more.
- Directory scanning: Find directories on a web server using a provided wordlist.
- Nmap port scanning: Perform a comprehensive port scan using Nmap.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/ashish00021/ReconMatrix.git
    ```

2. Install the required dependencies using pip and the provided requirements file:

    ```bash
    pip install -r requirements.txt
    or
    pip3 install -r requirements.txt
    ```

    This command will install all the necessary Python packages specified in the `requirements.txt` file.

## Usage

```bash
python reconmatrix.py --domain example.com [--whois] [--onlysub] [--nmap] [--direc]
```

