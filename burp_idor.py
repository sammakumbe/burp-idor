import base64
import json
import re
from typing import List, Dict, Optional, Union
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import sys
import logging
import yaml
from pathlib import Path
import concurrent.futures
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm
from transformers import pipeline
import torch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

console = Console()

class Config:
    DEFAULT_CONFIG = {
        'idor_patterns': ['id', 'user', 'account', 'uid', 'pid', 'profile', 'order', 'item'],
        'sensitive_keywords': ['user', 'email', 'password', 'account', 'private', 'confidential'],
        'max_threads': 4,
        'response_status': ['200 OK'],
        'session_headers': ['Cookie', 'Authorization'],  # Headers to check for session context
        'test_increment': 1,  # Increment for dynamic testing
        'hf_model': 'distilbert-base-uncased'  # Hugging Face model for AI
    }

    def __init__(self, config_file: Optional[str] = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file and Path(config_file).is_file():
            with open(config_file, 'r') as f:
                self.config.update(yaml.safe_load(f))
        self.idor_regex = re.compile('|'.join(self.config['idor_patterns']), re.IGNORECASE)

    def get(self, key: str) -> Union[list, int, str]:
        return self.config.get(key)

class BurpParser:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.format = self._detect_format()

    def _detect_format(self) -> str:
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        with open(self.file_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            if first_line.startswith('<?xml') or first_line.startswith('<items'):
                return 'xml'
            elif first_line.startswith('{') or first_line.startswith('['):
                return 'json'
            raise ValueError("Unsupported file format. Expected XML or JSON.")

    def parse(self) -> List[Dict]:
        if self.format == 'xml':
            return self._parse_xml()
        return self._parse_json()

    def _parse_xml(self) -> List[Dict]:
        with open(self.file_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'xml')
        requests = []
        for item in soup.find_all('item'):
            requests.append({
                'method': item.method.text if item.method else 'GET',
                'url': item.url.text if item.url else '',
                'request': self._decode_base64(item.request.text, item.request.get('base64')),
                'response': self._decode_base64(item.response.text, item.response.get('base64'))
            })
        return requests

    def _parse_json(self) -> List[Dict]:
        with open(self.file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get('items', [])
        return [{
            'method': item.get('method', 'GET'),
            'url': item.get('url', ''),
            'request': self._decode_base64(item.get('request', ''), item.get('request_base64')),
            'response': self._decode_base64(item.get('response', ''), item.get('response_base64'))
        } for item in data]

    @staticmethod
    def _decode_base64(data: str, is_base64: Optional[str]) -> str:
        if is_base64 == 'true':
            try:
                return base64.b64decode(data).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Failed to decode base64: {e}")
        return data

class IDORAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        self.potential_idors: List[Dict] = []
        self.ai_classifier = pipeline("text-classification", model=config.get('hf_model'))
        self.session_headers = config.get('session_headers')

    def analyze(self, requests: List[Dict]) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get('max_threads')) as executor:
            futures = [executor.submit(self._analyze_request, req) for req in requests]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.potential_idors.append(result)

    def _analyze_request(self, req: Dict) -> Optional[Dict]:
        url, method, request_body, response = req['url'], req['method'], req['request'], req['response']
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        potential_params = {k: v for k, v in query_params.items() if self.config.idor_regex.search(k)}
        if method in ['POST', 'PUT'] and request_body:
            body_params = self._parse_body(request_body)
            potential_params.update({k: v for k, v in body_params.items() if self.config.idor_regex.search(k)})

        for param, values in potential_params.items():
            for value in values:
                if (self._is_suspicious_value(value) and 
                    self._is_sensitive_response(response) and 
                    not self._has_session_context(request_body)):
                    idor_info = {
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'value': value,
                        'reason': f"Suspicious identifier '{param}={value}' with sensitive response",
                        'request_body': request_body,
                        'response': response
                    }
                    self._enhance_with_ai(idor_info)
                    return idor_info
        return None

    def _parse_body(self, body: str) -> Dict[str, List[str]]:
        params = {}
        try:
            if 'application/x-www-form-urlencoded' in body.lower():
                body = body.split('\r\n\r\n')[-1]
                for pair in body.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = [v]
            elif 'application/json' in body.lower():
                body = body.split('\r\n\r\n')[-1]
                data = json.loads(body)
                params = {k: [str(v)] for k, v in data.items()}
        except Exception as e:
            logger.debug(f"Failed to parse body: {e}")
        return params

    def _is_suspicious_value(self, value: str) -> bool:
        return value.isdigit() or re.match(r'^\d+[-_]\d+$', value)

    def _is_sensitive_response(self, response: str) -> bool:
        return (any(status in response for status in self.config.get('response_status')) and
                any(keyword in response.lower() for keyword in self.config.get('sensitive_keywords')))

    def _has_session_context(self, request: str) -> bool:
        """Reduce false positives by checking for session headers."""
        return any(header in request for header in self.session_headers)

    def _enhance_with_ai(self, idor_info: Dict) -> None:
        """Use local Hugging Face model for analysis."""
        try:
            prompt = f"Is this an IDOR? URL: {idor_info['url']}, Param: {idor_info['parameter']}={idor_info['value']}, Response: {idor_info['response'][:200]}"
            result = self.ai_classifier(prompt)
            idor_info['ai_score'] = result[0]['score'] if result[0]['label'] == 'POSITIVE' else 1 - result[0]['score']
            idor_info['ai_analysis'] = "Likely IDOR" if idor_info['ai_score'] > 0.7 else "Uncertain"
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
            idor_info['ai_analysis'] = "AI analysis unavailable"

class DynamicTester:
    """Perform dynamic tests to verify IDORs."""
    def __init__(self, config: Config):
        self.config = config

    async def test_idor(self, idor: Dict) -> Dict:
        """Test an IDOR by incrementing the parameter value."""
        async with aiohttp.ClientSession() as session:
            original_url = idor['url']
            param = idor['parameter']
            value = idor['value']
            headers = self._extract_headers(idor['request_body'])

            # Construct test URL with incremented value
            test_value = str(int(value) + self.config.get('test_increment')) if value.isdigit() else value + "_test"
            test_url = original_url.replace(f"{param}={value}", f"{param}={test_value}")

            try:
                async with session.request(idor['method'], test_url, headers=headers) as resp:
                    status = resp.status
                    text = await resp.text()
                    idor['test_result'] = {
                        'status': status,
                        'response': text[:200],
                        'verified': status == 200 and any(kw in text.lower() for kw in self.config.get('sensitive_keywords'))
                    }
            except Exception as e:
                idor['test_result'] = {'error': str(e)}
        return idor

    def _extract_headers(self, request: str) -> Dict[str, str]:
        """Extract headers from the request for testing."""
        headers = {}
        for line in request.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                if key.strip() in self.config.get('session_headers'):
                    headers[key.strip()] = value.strip()
        return headers

    async def run_tests(self, idors: List[Dict]) -> List[Dict]:
        tasks = [self.test_idor(idor) for idor in idors]
        return await asyncio.gather(*tasks)

class Reporter:
    @staticmethod
    def report(idors: List[Dict], output_file: Optional[str] = None) -> None:
        if not idors:
            console.print("[green]No potential IDOR vulnerabilities detected.[/green]")
            return

        table = Table(title="Potential IDOR Vulnerabilities", show_lines=True)
        table.add_column("ID", style="cyan")
        table.add_column("URL", style="magenta")
        table.add_column("Method", style="blue")
        table.add_column("Parameter", style="yellow")
        table.add_column("Reason", style="green")
        table.add_column("AI Analysis", style="red")
        table.add_column("Test Result", style="white")

        for i, idor in enumerate(idors, 1):
            test_result = idor.get('test_result', {})
            test_str = (f"Status: {test_result.get('status', 'N/A')}, "
                       f"Verified: {test_result.get('verified', 'N/A')}" if test_result else "Not tested")
            table.add_row(
                str(i),
                idor['url'],
                idor['method'],
                f"{idor['parameter']}={idor['value']}",
                idor['reason'],
                idor.get('ai_analysis', 'N/A'),
                test_str
            )

        console.print(table)
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(str(table))

def main():
    parser = argparse.ArgumentParser(description="Advanced IDOR detection tool for Burp Suite files.")
    parser.add_argument('burp_file', help="Path to Burp Suite file (XML or JSON)")
    parser.add_argument('--config', help="Path to custom config YAML file", default=None)
    parser.add_argument('--output', help="Path to save report", default=None)
    parser.add_argument('--test', action='store_true', help="Run dynamic tests to verify IDORs")
    args = parser.parse_args()

    try:
        config = Config(args.config)
        parser = BurpParser(args.burp_file)
        requests = parser.parse()
        analyzer = IDORAnalyzer(config)
        analyzer.analyze(requests)

        idors = analyzer.potential_idors
        if args.test and idors and Confirm.ask("Run dynamic tests to verify IDORs?", console=console):
            tester = DynamicTester(config)
            idors = asyncio.run(tester.run_tests(idors))

        Reporter.report(idors, args.output)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
