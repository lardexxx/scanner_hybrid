import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from config import ScannerConfig
from core import ScannerCore


def save_json_report(result, output_dir: str) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%d.%M.%Y_%H.%M.%S")
    filename = out / f"scan_report_{timestamp}.json"

    data = asdict(result)
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)

    return str(filename)


def print_short(result):
    short = result.short()
    print("\n========== SCAN short ==========")
    print(f"Target:        {short['target']}")
    print(f"Pages scanned: {short['pages_scanned']}")
    print(f"SQLi findings: {short['sqli_count']}")
    print("==================================\n")


def print_findings(result, show_evidence: bool = False):
    if not result.sqli_findings:
        return

    print("---- SQLi ----")
    for finding in result.sqli_findings:
        print(
            f"[{finding.confidence}/{getattr(finding, 'proof_status', 'n/a')}] "
            f"{finding.method} {finding.url} param={finding.param} "
            f"tech={finding.technique} payload={repr(finding.payload)}"
        )
        if show_evidence and finding.evidence:
            print(f"  evidence: {finding.evidence[:200]}")
    print()


def build_config_from_args(args) -> ScannerConfig:
    config = ScannerConfig(
        target_url=args.url,
        use_browser=not args.no_browser,
    )

    config.crawler.max_depth = args.depth
    config.crawler.max_pages = args.max_pages
    config.crawler.follow_external = args.follow_external

    config.browser.headless = not args.show_browser
    config.request.timeout = args.timeout
    config.request.verify_ssl = not args.insecure

    config.sqli.enabled = not args.no_sqli
    config.sqli.time_based_delay = args.sqli_delay
    return config


def main():
    parser = argparse.ArgumentParser(description="Hybrid SQLi Proof Scanner (requests + Playwright)")
    parser.add_argument("url", help="Target URL, e.g. http://127.0.0.1:8080/")
    parser.add_argument("--depth", type=int, default=2, help="Crawler max depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=100, help="Crawler max pages (default: 100)")
    parser.add_argument("--follow-external", action="store_true", help="Follow external domains")

    parser.add_argument("--no-browser", action="store_true", help="Disable Playwright (dynamic crawl off)")
    parser.add_argument("--show-browser", action="store_true", help="Run browser in headed mode (not headless)")

    parser.add_argument("--no-sqli", action="store_true", help="Disable SQLi scanning")
    parser.add_argument("--sqli-delay", type=int, default=5, help="Time-based SQLi delay seconds (default: 5)")

    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--report-dir", default="reports", help="Directory to save JSON reports (default: reports/)")
    parser.add_argument("--show-evidence", action="store_true", help="Print evidence snippets in console")

    args = parser.parse_args()
    config = build_config_from_args(args)
    scanner = ScannerCore(config)

    try:
        result = scanner.run()
        print_short(result)
        print_findings(result, show_evidence=args.show_evidence)

        report_path = save_json_report(result, args.report_dir)
        print(f"[+] JSON report saved to: {report_path}")
    finally:
        scanner.shutdown()


if __name__ == "__main__":
    main()
