# XScanner

**XScanner** is an advanced tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. By utilizing sophisticated crawling techniques and a wide array of payloads and obfuscation methods, XScanner identifies potential security risks effectively.

## Features

- **Crawling**: Recursively explores all links within the base URL to discover forms and parameters.
- **Payloads**: Uses a variety of payloads, including obfuscation techniques to bypass common security filters.
- **Heuristic Analysis**: Implements heuristic methods to detect XSS vulnerabilities by analyzing the context and behavior of the payload in the response.
- **Scanning**: Utilizes multi-threading for efficient and fast scanning with customizable concurrency settings.
- **Error Handling**: Provides detailed error logging and manages various exceptions gracefully.
- **Reporting**: Exports discovered vulnerabilities to JSON and CSV formats for easy analysis and reporting.


## Installation

To use **XScanner**, clone the repository and install the required dependencies:

```bash
git clone https://github.com/SHAYKHUL/XScanner.git
cd XScanner
pip install -r requirements.txt
```

## Usage

To run the scanner, use the following command:

```bash
python xscanner.py
```

You will be prompted to enter the base URL to scan. The scanner will then initiate the crawling and testing process.

## Example

Here's an example of how to use the scanner:

```python
if __name__ == "__main__":
    base_url = input("Enter the base URL to scan: ").strip()
    scanner = XScanner(base_url)
    scanner.scan()
```

## Configuration

- **User Agents**: The scanner randomly selects a user agent from a predefined list to simulate different browsers.
- **Payloads**: The payloads used for testing are generated using various obfuscation techniques to evade basic security filters.
- **Concurrency**: The number of concurrent workers can be customized to balance between performance and server load.
- **Timeout**: The timeout value for HTTP requests can be adjusted to handle different server response times.

## Reporting

After the scan is complete, the vulnerabilities are exported to both JSON and CSV files for further analysis:

- `vulnerabilities.json`
- `vulnerabilities.csv`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your improvements.

## Contact

For any questions or suggestions, feel free to open an issue or contact me. shaykhul2004@gmail.com
