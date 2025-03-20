# BURP IDOR

A powerful Python tool for identifying Insecure Direct Object Reference (IDOR) vulnerabilities in Burp Suite traffic exports. Combines heuristic analysis, local AI models, and dynamic testing to find and verify potential IDOR issues.

## Features

- **Heuristic Detection** - Identifies IDOR-prone parameters (id, user_id, etc.) with numeric or sequential values
- **Local AI Analysis** - Uses Hugging Face's transformer models for offline, context-aware vulnerability scoring
- **Dynamic Testing** - Sends test requests (incrementing IDs) to verify vulnerabilities asynchronously
- **False Positive Reduction** - Filters authenticated requests by detecting session headers
- **Rich CLI Interface** - Displays results in colorful, well-formatted tables
- **Multi-Format Support** - Works with both XML and JSON Burp Suite exports
- **Highly Configurable** - Customize detection patterns, keywords, and testing via YAML

## Installation

```bash
# Clone the repository
git clone https://github.com/geeknik/burp-idor.git
cd burp-idor

# Install dependencies
pip install beautifulsoup4 requests pyyaml transformers torch rich aiohttp
```

## Usage

### Export traffic from Burp Suite:
1. In Burp Suite, go to Proxy > HTTP history
2. Select requests, right-click, and choose "Save items" as XML or JSON

### Run the tool:

```bash
# Basic usage
python burp_idor.py burp_file.xml

# With custom config and output file
python burp_idor.py burp_file.xml --config config.yaml --output report.txt

# With dynamic testing to verify vulnerabilities
python burp_idor.py burp_file.xml --test
```

### Configuration

Create a `config.yaml` file to customize detection:

```yaml
idor_patterns:
  - id
  - user_id
  - account_id
sensitive_keywords:
  - user
  - email
  - profile
session_headers:
  - Cookie
  - Authorization
max_threads: 8
response_status:
  - "200 OK"
test_increment: 1
hf_model: "distilbert-base-uncased"
```

## How It Works

1. **Parsing** - Reads Burp Suite files and extracts HTTP requests/responses
2. **Analysis** - Examines parameters for IDOR patterns and scores findings with AI
3. **Testing (optional)** - Sends requests with modified parameters to verify vulnerabilities
4. **Reporting** - Presents findings in a formatted table

## Example Output

```
┌───────────────────────────── Potential IDOR Vulnerabilities ─────────────────────────────┐
│ ID  │ URL                       │ Method │ Parameter     │ Reason                        │ AI Analysis │ Test Result              │
├─────┼───────────────────────────┼────────┼───────────────┼───────────────────────────────┼─────────────┼──────────────────────────┤
│ 1   │ https://example.com/user?id=123 │ GET    │ id=123        │ Suspicious identifier 'id=123' with sensitive response │ Likely IDOR │ Status: 200, Verified: True │
└─────┴───────────────────────────┴────────┴───────────────┴───────────────────────────────┴─────────────┴──────────────────────────┘
```

## Warning

The `--test` flag sends live HTTP requests to target systems. Only test systems you have explicit permission to probe. Unauthorized testing may violate laws or terms of service.

## Contributing

Contributions welcome! Fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
