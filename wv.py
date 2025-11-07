#!/usr/bin/env python3
"""
WebVectors - Command Line Interface
A comprehensive command-line security scanner that generates HTML reports
"""

import argparse
import sys
import json
import os
from datetime import datetime
from pathlib import Path
import uuid
from security_scanner import SecurityScanner
from jinja2 import Environment, FileSystemLoader
import webbrowser

class SecurityScannerCLI:
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.output_dir = Path(".")  # Save to current directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
    
    def scan_website(self, url, output_file=None, open_browser=False, format='html', verbose=False):
        """Perform comprehensive security scan and generate report"""
        
        if verbose:
            print(f"🔍 Starting security scan of: {url}")
            print("=" * 60)
        
        # Initialize scanner
        scanner = SecurityScanner(url)
        
        # Perform all security checks
        if verbose:
            print("📊 Gathering basic information...")
        
        results = {
            'target_url': url,
            'domain': scanner.domain,
            'timestamp': datetime.now().isoformat(),
            'scan_id': str(uuid.uuid4()),
            'scan_metadata': {
                'scan_id': str(uuid.uuid4()),
                'start_time': datetime.now().isoformat(),
                'total_checks': 0,
                'critical_issues': 0,
                'high_issues': 0,
                'medium_issues': 0,
                'low_issues': 0
            },
            'scans': {}
        }
        
        # Define scan functions and their verbose names
        scan_functions = {
            'ssl_tls_analysis': ('🔐 SSL/TLS Analysis', scanner.check_ssl_tls_comprehensive),
            'security_headers': ('🛡️ Security Headers', scanner.check_security_headers_comprehensive),
            'port_scanning': ('🌐 Port Scanning', scanner.scan_common_ports),
            'dns_information': ('🔍 DNS Information', scanner.get_dns_info),
            'server_analysis': ('🖥️ Server Analysis', scanner.get_server_info),
            'web_technologies': ('⚙️ Web Technologies', scanner.detect_web_technologies),
            'vulnerability_testing': ('🐛 Vulnerability Testing', scanner.check_vulnerabilities_comprehensive),
            'content_security': ('📄 Content Security', scanner.analyze_content_security),
            'network_analysis': ('🌍 Network Analysis', scanner.analyze_network_security)
        }
        
        if verbose:
            print(f"🎯 Target URL: {url}")
            print(f"🏢 Domain: {scanner.domain}")
            print("=" * 60)
            print("📋 SCAN PLAN:")
            for i, (scan_key, (scan_name, _)) in enumerate(scan_functions.items(), 1):
                print(f"  {i}. {scan_name}")
            print("=" * 60)
        
        # Execute scans with detailed progress
        scan_count = 0
        total_scans = len(scan_functions)
        
        for scan_key, (scan_name, scan_func) in scan_functions.items():
            scan_count += 1
            
            if verbose:
                print(f"\n[{scan_count}/{total_scans}] {scan_name}")
                print("─" * 50)
            else:
                print(f"[{scan_count}/{total_scans}] {scan_name}...", end=" ", flush=True)
            
            start_time = datetime.now()
            
            try:
                if verbose:
                    print("  📊 Initializing scan...")
                
                result = scan_func()
                results['scans'][scan_key] = result
                
                # Count issues for metadata
                issues = result.get('issues', [])
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0
                
                for issue in issues:
                    severity = issue.get('severity', 'low')
                    if severity == 'critical':
                        results['scan_metadata']['critical_issues'] += 1
                        critical_count += 1
                    elif severity == 'high':
                        results['scan_metadata']['high_issues'] += 1
                        high_count += 1
                    elif severity == 'medium':
                        results['scan_metadata']['medium_issues'] += 1
                        medium_count += 1
                    else:
                        results['scan_metadata']['low_issues'] += 1
                        low_count += 1
                
                results['scan_metadata']['total_checks'] += result.get('checks_performed', 1)
                
                # Calculate scan duration
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                status = result.get('status', 'unknown')
                checks = result.get('checks_performed', 0)
                issues_count = len(result.get('issues', []))
                
                if verbose:
                    print(f"  ✓ Status: {status.upper()}")
                    print(f"  📈 Checks performed: {checks}")
                    print(f"  ⏱️  Duration: {duration:.2f}s")
                    
                    if issues_count > 0:
                        print(f"  ⚠️  Issues found: {issues_count}")
                        if critical_count > 0:
                            print(f"     🔴 Critical: {critical_count}")
                        if high_count > 0:
                            print(f"     🟠 High: {high_count}")
                        if medium_count > 0:
                            print(f"     🟡 Medium: {medium_count}")
                        if low_count > 0:
                            print(f"     🟢 Low: {low_count}")
                        
                        # Show some critical issues immediately
                        critical_issues = [i for i in issues if i.get('severity') == 'critical']
                        if critical_issues:
                            print("  🚨 Critical issues detected:")
                            for issue in critical_issues[:3]:  # Show first 3
                                print(f"     • {issue.get('type', 'Unknown')}: {issue.get('description', 'No description')}")
                            if len(critical_issues) > 3:
                                print(f"     ... and {len(critical_issues) - 3} more critical issues")
                    else:
                        print(f"  ✅ No issues found")
                        
                    # Show specific scan details based on scan type
                    self._show_scan_details(scan_key, result, verbose=True)
                else:
                    # Non-verbose: just show completion status
                    status_icon = "✓" if status not in ['error', 'critical'] else "✗"
                    issues_text = f"{issues_count} issues" if issues_count > 0 else "clean"
                    print(f"{status_icon} ({issues_text})")
                    
            except Exception as e:
                duration = (datetime.now() - start_time).total_seconds()
                
                if verbose:
                    print(f"  ✗ Scan failed after {duration:.2f}s")
                    print(f"  ❌ Error: {str(e)}")
                else:
                    print("✗ (failed)")
                    
                results['scans'][scan_key] = {
                    'error': str(e),
                    'status': 'error',
                    'checks_performed': 0,
                    'issues': []
                }
        
        # Finalize metadata
        results['scan_metadata']['end_time'] = datetime.now().isoformat()
        results['timestamp'] = datetime.now().isoformat()
        
        # Calculate total scan time
        start_time_dt = datetime.fromisoformat(results['scan_metadata']['start_time'].replace('Z', '+00:00'))
        end_time_dt = datetime.fromisoformat(results['scan_metadata']['end_time'].replace('Z', '+00:00'))
        total_duration = (end_time_dt - start_time_dt).total_seconds()
        
        if verbose:
            print("\n" + "=" * 60)
            print(f"📈 SCAN SUMMARY")
            print("=" * 60)
            print(f"🎯 Target: {results['target_url']}")
            print(f"⏱️  Total time: {total_duration:.2f} seconds")
            print(f"🔍 Total checks: {results['scan_metadata']['total_checks']}")
            print()
            print("📊 SECURITY ISSUES BREAKDOWN:")
            print(f"   🔴 Critical: {results['scan_metadata']['critical_issues']}")
            print(f"   🟠 High:     {results['scan_metadata']['high_issues']}")
            print(f"   🟡 Medium:   {results['scan_metadata']['medium_issues']}")
            print(f"   🟢 Low:      {results['scan_metadata']['low_issues']}")
            
            total_issues = (results['scan_metadata']['critical_issues'] + 
                          results['scan_metadata']['high_issues'] + 
                          results['scan_metadata']['medium_issues'] + 
                          results['scan_metadata']['low_issues'])
            
            print(f"   📋 Total:    {total_issues}")
            
            # Security assessment
            if results['scan_metadata']['critical_issues'] > 0:
                print("\n🚨 SECURITY ASSESSMENT: CRITICAL ISSUES DETECTED!")
                print("   Immediate action required to address critical security vulnerabilities.")
            elif results['scan_metadata']['high_issues'] > 3:
                print("\n⚠️  SECURITY ASSESSMENT: HIGH RISK")
                print("   Multiple high-priority security issues need attention.")
            elif results['scan_metadata']['high_issues'] > 0 or results['scan_metadata']['medium_issues'] > 5:
                print("\n⚠️  SECURITY ASSESSMENT: MODERATE RISK")
                print("   Several security improvements recommended.")
            elif total_issues == 0:
                print("\n✅ SECURITY ASSESSMENT: EXCELLENT!")
                print("   No security issues detected. Great job!")
            else:
                print("\n👍 SECURITY ASSESSMENT: GOOD")
                print("   Minor security improvements available.")
            print()
        else:
            # Brief summary for non-verbose mode
            total_issues = (results['scan_metadata']['critical_issues'] + 
                          results['scan_metadata']['high_issues'] + 
                          results['scan_metadata']['medium_issues'] + 
                          results['scan_metadata']['low_issues'])
            print(f"\nScan completed: {total_issues} total issues found ({total_duration:.1f}s)")
        
        # Generate output
        if format == 'html':
            if verbose:
                print("📄 Generating HTML report...")
            output_path = self.generate_html_report(results, output_file)
            if verbose:
                print(f"✅ HTML report generated: {output_path}")
            
            if open_browser:
                if verbose:
                    print("🌐 Opening report in browser...")
                webbrowser.open(f'file://{output_path.absolute()}')
                if verbose:
                    print("✅ Report opened in browser")
                    
        elif format == 'json':
            if verbose:
                print("📄 Generating JSON report...")
            output_path = self.generate_json_report(results, output_file)
            if verbose:
                print(f"✅ JSON report generated: {output_path}")
        
        return output_path
    
    def _show_scan_details(self, scan_key: str, result: dict, verbose: bool = False):
        """Show specific details for each scan type"""
        if not verbose:
            return
            
        if scan_key == 'ssl_tls_analysis' and result.get('certificate_info'):
            cert_info = result['certificate_info']
            print(f"  📜 Certificate: {cert_info.get('subject', {}).get('commonName', 'Unknown')}")
            print(f"  🏢 Issuer: {cert_info.get('issuer', {}).get('organizationName', 'Unknown')}")
            if 'expiry_days' in cert_info:
                days = cert_info['expiry_days']
                if days < 0:
                    print(f"  ⚠️  Certificate EXPIRED {abs(days)} days ago!")
                elif days < 30:
                    print(f"  ⚠️  Certificate expires in {days} days")
                else:
                    print(f"  ✅ Certificate valid for {days} days")
                    
        elif scan_key == 'security_headers' and result.get('headers_present'):
            headers_count = len(result['headers_present'])
            missing_count = len(result.get('headers_missing', []))
            print(f"  🛡️  Security headers: {headers_count} present, {missing_count} missing")
            
        elif scan_key == 'port_scanning' and result.get('open_ports'):
            open_count = len(result['open_ports'])
            if open_count > 0:
                print(f"  🌐 Open ports found: {open_count}")
                risky_ports = [p for p in result['open_ports'] if p['port'] in [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379]]
                if risky_ports:
                    print(f"  ⚠️  Risky ports: {', '.join([str(p['port']) for p in risky_ports])}")
                    
        elif scan_key == 'dns_information' and result.get('security_features'):
            features = result['security_features']
            spf = "✅" if features.get('SPF') == 'Present' else "❌"
            dmarc = "✅" if features.get('DMARC') == 'Present' else "❌"
            dkim = "✅" if features.get('DKIM') == 'Present' else "❌"
            print(f"  📧 Email security: SPF {spf} | DMARC {dmarc} | DKIM {dkim}")
            
        elif scan_key == 'web_technologies' and result.get('technologies'):
            tech_count = len(result['technologies'])
            print(f"  ⚙️  Technologies detected: {tech_count}")
            
        elif scan_key == 'vulnerability_testing' and result.get('vulnerabilities'):
            vuln_count = len(result['vulnerabilities'])
            if vuln_count > 0:
                print(f"  🐛 Vulnerabilities found: {vuln_count}")
                high_severity = [v for v in result['vulnerabilities'] if v.get('severity', '').lower() in ['high', 'critical']]
                if high_severity:
                    print(f"  🚨 High/Critical vulnerabilities: {len(high_severity)}")
                    
        elif scan_key == 'content_security' and result.get('content_issues'):
            issues_count = len(result['content_issues'])
            if issues_count > 0:
                print(f"  📄 Content security issues: {issues_count}")
                
        elif scan_key == 'network_analysis':
            if result.get('status') == 'completed':
                print(f"  🌍 Network analysis completed")

    def generate_html_report(self, results, output_file=None):
        """Generate HTML report using Jinja2 template"""
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = results['domain'].replace('.', '_')
            output_file = f"security_report_{domain}_{timestamp}.html"
        
        output_path = self.output_dir / output_file
        
        # Load and render template
        template = self.jinja_env.get_template('cli_report.html')
        html_content = template.render(results=results)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def generate_json_report(self, results, output_file=None):
        """Generate JSON report"""
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = results['domain'].replace('.', '_')
            output_file = f"security_report_{domain}_{timestamp}.json"
        
        output_path = self.output_dir / output_file
        
        # Write JSON file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        return output_path

def main():
    parser = argparse.ArgumentParser(
        description="WebVectors - Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com -o my_report.html
  %(prog)s https://example.com -v --open
  %(prog)s https://example.com --format json
  %(prog)s https://example.com -o reports/scan.html -v
        """
    )
    
    parser.add_argument(
        'url',
        help='Target URL to scan (must include http:// or https://)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file name (default: auto-generated based on domain and timestamp)'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'json'],
        default='html',
        help='Output format (default: html)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--open',
        action='store_true',
        help='Open the HTML report in browser after generation'
    )
    
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for reports (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("❌ Error: URL must start with http:// or https://")
        sys.exit(1)
    
    try:
        # Initialize CLI scanner
        cli = SecurityScannerCLI()
        cli.output_dir = Path(args.output_dir)
        cli.output_dir.mkdir(exist_ok=True)
        
        if args.verbose:
            print("🚀 WebVectors CLI")
            print("=" * 60)
            print(f"📅 Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"📂 Output directory: {cli.output_dir.absolute()}")
            print(f"📋 Output format: {args.format.upper()}")
            if args.open:
                print("🌐 Will open report in browser after completion")
            print()
        else:
            print(f"🔍 Scanning {args.url}...")
        
        # Perform scan
        output_path = cli.scan_website(
            url=args.url,
            output_file=args.output,
            open_browser=args.open,
            format=args.format,
            verbose=args.verbose
        )
        
        if not args.verbose:
            print(f"✅ Report generated: {output_path}")
        
        if args.verbose:
            print("\n" + "=" * 60)
            print("✅ SCAN COMPLETED SUCCESSFULLY!")
            print(f"📁 Report saved to: {output_path.absolute()}")
            print(f"� Report format: {args.format.upper()}")
            if args.open and args.format == 'html':
                print("🌐 Report should be opening in your browser")
            print("=" * 60)
            
    except KeyboardInterrupt:
        print("\n\n🛑 SCAN INTERRUPTED")
        print("=" * 40)
        print("❌ Scan was cancelled by user (Ctrl+C)")
        print("💡 Tip: Use --verbose flag for detailed progress")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 SCAN FAILED")
        print("=" * 40)
        print(f"❌ Error: {e}")
        print("\n💡 Troubleshooting tips:")
        print("   • Check that the URL is valid and accessible")
        print("   • Ensure you have an internet connection")
        print("   • Try running with --verbose for more details")
        print("   • Check if the target server is blocking requests")
        
        if args.verbose:
            print("\n📋 Full error details:")
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()