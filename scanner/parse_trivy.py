import json

def load_trivy_report(filepath):
    """Load a Trivy JSON report from a file."""
    with open(filepath, 'r') as f:
        return json.load(f)
    
def extract_vulnerabilities(report):
    """Extract and normalize vulnerabilities from Trivy report."""
    vulnerabilities = []

    for result in report.get('Results', []):
        target = result.get('Target', 'unknown')
        pkg_class = result.get('Class', 'unknown')
        vulns = result.get('Vulnerabilities', [])

        if not vulns:
            continue

        for vuln in vulns:
            fixed_version = vuln.get('FixedVersion', None)
            status = vuln.get('Status', 'unknown')

            #Get CVSS v3 score with source tracking
            cvss_data = vuln.get('CVSS', {})
            cvss_v3 = None
            cvss_source = None

            if cvss_data.get('nvd', {}).get('V3Score'):
                cvss_v3 = cvss_data['nvd']['V3Score']
                cvss_source = 'nvd'
            elif cvss_data.get('ghsa', {}).get('V3Score'):
                cvss_v3 = cvss_data['ghsa']['V3Score']
                cvss_source = 'ghsa'
            elif cvss_data.get('redhat', {}).get('V3Score'):
                cvss_v3 = cvss_data['redhat']['V3Score']
                cvss_source = 'redhat'

            # Remediation advice based on class and fixed version
            if pkg_class == 'os-pkgs' and fixed_version:
                remediation = (
                    f'OS package: update {vuln.get("PkgName")} to '
                    f'{fixed_version} via base image rebuild or COPA'
                )
            elif pkg_class == 'os-pkgs' and not fixed_version:
                remediation = (
                    'OS package: no fix available yet - '
                    'monitor distro advisories or accept risk'
                )
            elif pkg_class == 'lang-pkgs' and fixed_version:
                remediation = (
                    f'Update {vuln.get("PkgName")} to '
                    f'version {fixed_version} in requirements or Dockerfile'
                )
            elif pkg_class == 'lang-pkgs' and not fixed_version:
                remediation = (
                    'No fix available yet - '
                    'accept risk or find alternative package'
                )
            else:
                remediation = 'Review manually - unknown package class'

            vulnerabilities.append({
                'cve_id': vuln.get('VulnerabilityID', ''),
                'package': vuln.get('PkgName', ''),
                'version': vuln.get('InstalledVersion', ''),
                'fixed_version': fixed_version,
                'status': status,
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'title': vuln.get('Title', ''),
                'description': vuln.get('Description', ''),
                'cvss_v3': cvss_v3,
                'cvss_source': cvss_source,
                'target': target,
                'class': pkg_class,
                'remediation': remediation,
            })

    return vulnerabilities


if __name__ == '__main__':
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else 'sample-data/python-slim-scan.json'

    report = load_trivy_report(filepath)
    vulnerabilities = extract_vulnerabilities(report)
    

    print(f'Total vulnerabilities found: {len(vulnerabilities)}')
    print(f'\nFirst 3 vulnerabilities:\n')

    for vuln in vulnerabilities[:3]:
        print(f"CVE:        {vuln['cve_id']}")
        print(f"Package:    {vuln['package']} {vuln['version']}")
        print(f"Severity:   {vuln['severity']}")
        print(f"CVSS v3:    {vuln['cvss_v3']} (source: {vuln['cvss_source']})")
        print(f"Class:      {vuln['class']}")
        print(f"Status:     {vuln['status']}")
        print(f"Fixed in:   {vuln['fixed_version']}")
        print(f"Remediation:{vuln['remediation']}")
