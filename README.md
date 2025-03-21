# Cert-Checker

Cert-Checker is a Python tool designed to check the validity and expiration dates of SSL/TLS certificates. It provides both a command-line interface and a web-based dashboard for managing and monitoring certificates.

## Features

- Check the expiration date of SSL/TLS certificates.
- Validate the certificate chain.
- Alert on certificates that are about to expire.
- Support for multiple domains.
- Web-based dashboard for easy management and monitoring.
- Schedule recurring scans.

## Installation

To install Cert-Checker, follow these steps:

1. **Clone the Repository**

   First, clone the repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/cert-checker.git
   cd cert-checker
   ```

2. **Set Up a Virtual Environment (Optional but Recommended)**

   It's a good practice to use a virtual environment to manage dependencies. You can set one up using `venv`:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   Install the required Python packages using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

## Running the Web Application

To start the Flask web application, run the following command:

```bash
python app.py
```

This will start the web server, and you can access the dashboard by navigating to `http://localhost:5000` in your web browser.

### Dashboard Overview

The dashboard provides a user-friendly interface for managing SSL/TLS certificates. It includes the following tabs:

- **Site Cert Scanner**: Allows you to manually input domains or upload a file with domains to scan for certificate information.
- **Public CTL Checker**: Enables querying of Certificate Transparency Logs for public certificates associated with the domains.
- **Scheduled Scans**: Manage and view scheduled scans, allowing you to automate regular checks of your certificates.

### Using the Dashboard

1. **Site Cert Scanner**: Enter domains manually or upload a file to scan for certificates. The results will show the status of each certificate, including whether it is valid, expiring soon, or expired.

2. **Public CTL Checker**: Query the Certificate Transparency Logs to find public certificates for the entered domains. This tab provides a detailed view of the certificates found in public logs.

3. **Scheduled Scans**: Set up recurring scans to automatically check your certificates at specified intervals. You can view, edit, or delete scheduled tasks from this tab.

## Usage

To use Cert-Checker, run the following command:

```bash
python crt_checker.py --domain example.com
```

Replace `example.com` with the domain you want to check.

### Command-Line Options

- `--domain`: Specify the domain to check.
- `--alert-days`: Set the number of days before expiration to trigger an alert (default is 30 days).

Example:

```bash
python crt_checker.py --domain example.com --alert-days 15
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please open an issue on the GitHub repository or contact the maintainer at [your-email@example.com].