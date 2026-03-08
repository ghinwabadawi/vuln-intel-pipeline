import yaml
import requests
import json

def load_asset_context(filepath='asset-context.yaml'):
    """Load asset context from YAML file"""
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def get_kev_list():
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()
    kev_ids = {vuln['cveID'] for vuln in data['vulnerabilities']}
    return kev_ids

def get_epss_scores(cve_ids):
    """Fetch EPSS scores for a list of CVE IDs."""
    if not cve_ids:
        return {}
    
    cve_list = ','.join(cve_ids)
    url = f'https://api.first.org/data/v1/epss?cve={cve_list}'
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()

    epss_map = {}
    for item in data.get('data', []):
        epss_map[item['cve']] = float(item['epss'])
    
    return epss_map

def calculate_priority_score(vuln, epss_map, kev_ids, context):
    """Calculate priority score based on CVSS, EPSS, KEV and asset context."""

    #Start with CVSS base score, default to 5.0 if missing
    base_score = vuln.get('cvss_v3') or 5.0
    score = base_score
    reasons = []

    #EPSS multiplier
    epss = epss_map.get(vuln['cve_id'], 0.0)
    if epss > 0.7:
        score *= 2.0
        reasons.append(f'EPSS {epss:.2f} - high exploitation probability')
    elif epss > 0.3:
        score *= 1.5
        reasons.append(f'EPSS {epss:.2f} - medium exploitation probability')

    #KEV check
    in_kev = vuln['cve_id'] in kev_ids
    if in_kev:
        score *= 2.0
        reasons.append('In CISA KEV - actively exploited in the wild')

    # Asset context multipliers
    if context.get('internet_facing'):
        score *= 1.15
        reasons.append('Internet facing service')

    if context.get('data_classification') in ['PII', 'financial']:
        score *= 1.15
        reasons.append(f"Sensitive data: {context.get('data_classification')}")

    if context.get('blast_radius') == 'high':
        score *= 1.10
        reasons.append('High blast radius')
    elif context.get('blast_radius') == 'medium':
        score *= 1.05
        reasons.append('Medium blast radius')
    
    if context.get('environment') == 'production':
        score *= 1.05
        reasons.append('Production environment')

    # WAF as compensating control
    # Only relevant for internet-facing lang-pkgs (web attack surface)
    # internet_facing multiplier already captures the risk of no WAF
    # WAF presence partially mitigates that risk
    if (context.get('has_waf') and context.get('internet_facing') and vuln.get('class') == 'lang-pkgs'):
        score *= 0.9
        reasons.append('WAF present - partial mitigation for web vulnerabilities')
    
    # Disputed flag - vendor severity disagrees with CVSS score
    severity = vuln.get('severity', 'UNKNOWN').upper()
    disputed = (
        (severity == 'LOW' and (vuln.get('cvss_v3') or 0) >= 7.0) or
        (severity == 'MEDIUM' and (vuln.get('cvss_v3') or 0) >= 9.0)
    )
    
    # Cap at 10  
    score = min(score, 10.0)

    # Force Critical if in KEV regardless of score
    if in_kev:
        score = max(score, 9.0)
    
    # Assign SLA tier
    if score >= 9.0:
        sla = 'Critical - fix within 24 hours'
    elif score >= 7.0:
        sla = 'High - fix within 7 days'
    elif score >= 4.0:
        sla = 'Medium - fix within 30 days'
    else:
        sla = 'Low - fix within 90 days'

    return {
    'priority_score': round(score, 2),
    'sla': sla,
    'epss': epss,
    'in_kev': in_kev,
    'disputed': disputed,
    'reasons': reasons
}
    
def enrich_vulnerabilities(vulnerabilities, asset_context_path='asset-context.yaml'):
    """Enrich vulnerabilities with EPSS, KEV and priority scores."""

    # Load asset context
    asset_data = load_asset_context(asset_context_path)
    context = asset_data.get('context', {})

    # Fetch KEV and EPSS data once
    print('Fetching CISA KEV List...')
    kev_ids = get_kev_list()
    print(f'KEV list loaded: {len(kev_ids)} known exploited CVEs')

    print('Fetching EPSS scores...')
    cve_ids = [v['cve_id'] for v in vulnerabilities]
    epss_map = get_epss_scores(cve_ids)
    print(f'EPSS scores loaded: {len(epss_map)} scores retrieved')

    # Enrich each vulnerability 
    enriched = []
    for vuln in vulnerabilities:
        priority = calculate_priority_score(vuln, epss_map, kev_ids, context)
        enriched_vuln = {**vuln, **priority}
        enriched.append(enriched_vuln)
    
    #Sort by priority score descending
    enriched.sort(key=lambda x: x['priority_score'], reverse=True)

    return enriched

if __name__ == '__main__':
    import sys
    sys.path.append('.')
    from scanner.parse_trivy import load_trivy_report, extract_vulnerabilities

    scan_file = sys.argv[1] if len(sys.argv) > 1 else 'sample-data/python-slim-scan.json'
    print(f'Loading scan file: {scan_file}')
    report = load_trivy_report(scan_file)
    vulnerabilities = extract_vulnerabilities(report)
    print(f'Found {len(vulnerabilities)} vulnerabilities')

    enriched = enrich_vulnerabilities(vulnerabilities)

    print(f'\nTotal of all vulnerabilities: {len(enriched)}\n')
    for vuln in enriched:
        print(f"CVE:            {vuln['cve_id']}")
        print(f"Package:        {vuln['package']} {vuln['version']}")
        print(f"Severity:       {vuln['severity']} (source: {vuln['severity_source']})")
        print(f"CVSS v3:        {vuln['cvss_v3']} (source: {vuln['cvss_source']})")
        print(f"Disputed:       {vuln['disputed']}")
        print(f"In KEV:         {vuln['in_kev']}")
        print(f"Priority Score: {vuln['priority_score']}")
        print(f"SLA:            {vuln['sla']}")
        print(f"Reasons:        {', '.join(vuln['reasons']) if vuln['reasons'] else 'None'}")
        print('-' * 70) 

    print(f'\nSummary by SLA tier:')
    from collections import Counter
    sla_counts = Counter(v['sla'] for v in enriched)
    for sla, count in sorted(sla_counts.items()):
        print(f'  {sla}: {count} vulnerabilities')
    
  
