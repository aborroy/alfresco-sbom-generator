#!/usr/bin/env python3
"""
SBOM HTML Generator

A comprehensive tool that:

* Runs Syft to build a Software Bill of Materials (SBOM)
* Enriches missing license data from Maven Central and GitHub
* Applies heuristics for common packages
* Generates a detailed HTML report with license information
"""

import os
import re
import sys
import time
import subprocess
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
MAVEN_CENTRAL_BASE = "https://repo1.maven.org/maven2"
GITHUB_API_BASE = "https://api.github.com"

# XML namespaces
POM_NAMESPACES = {'m': 'http://maven.apache.org/POM/4.0.0'}

# Rate limiting
RATE_LIMIT_DELAY = 0.5  # seconds between API calls

@dataclass
class License:
    """Represents a software license with name and URL."""
    name: str
    url: Optional[str] = None
    
    def __post_init__(self):
        if not self.url:
            self.url = get_canonical_license_url(self.name)


@dataclass
class Package:
    """Represents a software package with metadata."""
    name: str
    version: str
    purl: str = ""
    licenses: List[License] = None
    license_source: str = "Original"
    
    def __post_init__(self):
        if self.licenses is None:
            self.licenses = []
    
    @property
    def has_licenses(self) -> bool:
        return len(self.licenses) > 0
    
    @property
    def unique_key(self) -> Tuple[str, str]:
        return (self.name, self.version)


class LicenseMapper:
    """Handles mapping of license names to canonical URLs."""
    
    _LICENSE_URLS = {
        # Apache licenses
        'apache-2.0': 'https://www.apache.org/licenses/LICENSE-2.0.txt',
        'apache license, version 2.0': 'https://www.apache.org/licenses/LICENSE-2.0.txt',
        'the apache software license, version 2.0': 'https://www.apache.org/licenses/LICENSE-2.0.txt',
        'the apache software license': 'https://www.apache.org/licenses/LICENSE-2.0.txt',
        'apache license': 'https://www.apache.org/licenses/LICENSE-2.0.txt',
        
        # MIT licenses
        'mit': 'https://opensource.org/licenses/MIT',
        'mit license': 'https://opensource.org/licenses/MIT',
        
        # BSD licenses
        'bsd-3-clause': 'https://opensource.org/licenses/BSD-3-Clause',
        'bsd license': 'https://opensource.org/licenses/BSD-3-Clause',
        'bsd licence': 'https://opensource.org/licenses/BSD-3-Clause',
        
        # GPL licenses
        'gpl-2.0': 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html',
        'gpl-3.0': 'https://www.gnu.org/licenses/gpl-3.0.html',
        'gnu general public license v2': 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt',
        
        # LGPL licenses
        'lgpl-3.0': 'https://www.gnu.org/licenses/lgpl-3.0.html',
        'lgplv3': 'https://www.gnu.org/licenses/lgpl-3.0.html',
        'gnu lesser general public license v3.0 or later': 'https://www.gnu.org/licenses/lgpl-3.0.html',
        
        # Eclipse licenses
        'eclipse public license - v 2.0': 'https://www.eclipse.org/legal/epl-2.0/',
        'eclipse public license, version 1.0': 'https://www.eclipse.org/legal/epl-v10.html',
        
        # Mozilla licenses
        'mpl-2.0': 'https://www.mozilla.org/en-US/MPL/2.0/',
        'mozilla public license version 1.1': 'https://www.mozilla.org/en-US/MPL/1.1/',
        
        # Other common licenses
        'cddl': 'https://opensource.org/licenses/CDDL-1.0',
        'unicode-3.0': 'https://www.unicode.org/license.txt',
        'bouncy castle licence': 'https://www.bouncycastle.org/licence.html',
        'common public license': 'https://opensource.org/licenses/CPL-1.0',
        'cup parser generator copyright notice, license, and disclaimer': 
            'http://www2.cs.tum.edu/projects/cup/licence.php',
        'alfresco component license agreement': 'https://www.alfresco.com/legal/agreements',
    }
    
    @classmethod
    def get_url(cls, license_name: str, context: str = "") -> Optional[str]:
        """Get canonical URL for a license name."""
        normalized_name = license_name.lower().strip().strip('"')
        
        # Direct lookup
        if normalized_name in cls._LICENSE_URLS:
            return cls._LICENSE_URLS[normalized_name]
        
        # Heuristic matching
        return cls._apply_heuristics(normalized_name, context)
    
    @classmethod
    def _apply_heuristics(cls, license_name: str, context: str) -> Optional[str]:
        """Apply heuristic rules to match license names."""
        if 'apache' in license_name and '2.0' in license_name:
            return cls._LICENSE_URLS['apache-2.0']
        
        if license_name.startswith('mit'):
            return cls._LICENSE_URLS['mit']
        
        if 'bsd' in license_name:
            return cls._LICENSE_URLS['bsd-3-clause']
        
        if 'eclipse' in license_name:
            return (cls._LICENSE_URLS['eclipse public license - v 2.0'] 
                   if '2.0' in license_name 
                   else cls._LICENSE_URLS['eclipse public license, version 1.0'])
        
        if 'lgpl' in license_name or 'lesser' in license_name:
            return cls._LICENSE_URLS['lgpl-3.0']
        
        if 'gpl' in license_name:
            return (cls._LICENSE_URLS['gpl-3.0'] if '3' in license_name 
                   else cls._LICENSE_URLS['gpl-2.0'])
        
        if 'mozilla' in license_name or 'mpl' in license_name:
            return (cls._LICENSE_URLS['mpl-2.0'] if '2.0' in license_name 
                   else cls._LICENSE_URLS['mozilla public license version 1.1'])
        
        if 'alfresco' in license_name:
            return cls._LICENSE_URLS['alfresco component license agreement']
        
        if context:
            print(f"Missing URL mapping for license '{license_name}' (context: {context})")
        
        return None


def get_canonical_license_url(license_name: str, context: str = "") -> Optional[str]:
    """Get canonical URL for a license name."""
    return LicenseMapper.get_url(license_name, context)


class SyftRunner:
    """Handles execution of Syft SBOM generation."""
    
    DEFAULT_TEMPLATE = (
        "{{- range .artifacts}}"
        "{{.name}}:{{.version}}:{{.purl}} - {{range .licenses}}{{.value}}{{end}}\n"
        "{{- end}}"
    )
    
    @staticmethod
    def run(image: str, template_file: Optional[str] = None) -> str:
        """Run Syft and return template output."""
        cmd = [
            "syft", image,
            "--exclude", "/lib",
            "--exclude", "/var", 
            "--enrich", "all",
            "-o", "template"
        ]
        
        if template_file and Path(template_file).exists():
            cmd.extend(["-t", template_file])
        else:
            cmd.extend(["-t", SyftRunner.DEFAULT_TEMPLATE])
        
        print(f"🔧 Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Syft failed: {e.stderr}")
            sys.exit(1)
        except FileNotFoundError:
            print("Syft not found. Install from: https://github.com/anchore/syft")
            sys.exit(1)


class MavenCentralClient:
    """Client for fetching license information from Maven Central."""
    
    @staticmethod
    @lru_cache(maxsize=None)
    def fetch_pom(group_id: str, artifact_id: str, version: str) -> Optional[ET.Element]:
        """Fetch and parse POM file from Maven Central."""
        path = f"{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
        url = f"{MAVEN_CENTRAL_BASE}/{path}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return ET.fromstring(response.text)
        except Exception as e:
            print(f"Failed to fetch POM for {group_id}:{artifact_id}:{version} - {e}")
        
        return None
    
    @staticmethod
    def extract_licenses_from_pom(pom: ET.Element) -> List[License]:
        """Extract license information from POM XML."""
        licenses = []
        
        # Try both namespaced and non-namespaced license elements
        license_elements = (pom.findall('.//m:licenses/m:license', POM_NAMESPACES) + 
                          pom.findall('.//license'))
        
        for lic_elem in license_elements:
            name = (lic_elem.findtext('m:name', default='', namespaces=POM_NAMESPACES) or 
                   lic_elem.findtext('name', default='')).strip()
            url = (lic_elem.findtext('m:url', default='', namespaces=POM_NAMESPACES) or 
                  lic_elem.findtext('url', default='')).strip()
            
            if name:
                license_url = url or get_canonical_license_url(name, "Maven POM")
                licenses.append(License(name=name, url=license_url))
        
        if licenses:
            return licenses
        
        # Fallback: try GitHub if no licenses found
        scm_url = (pom.findtext('.//m:scm/m:url', default='', namespaces=POM_NAMESPACES) or 
                  pom.findtext('.//scm/url', default=''))
        
        if scm_url:
            return GitHubClient.get_license_from_repo_url(scm_url)
        
        return []
    
    @staticmethod
    def lookup_license_recursively(group_id: str, artifact_id: str, version: str, 
                                 max_depth: int = 4) -> List[License]:
        """Recursively look up license information, checking parent POMs if necessary."""
        if max_depth == 0:
            return []
        
        pom = MavenCentralClient.fetch_pom(group_id, artifact_id, version)
        if pom is None:
            return []
        
        licenses = MavenCentralClient.extract_licenses_from_pom(pom)
        if licenses:
            return licenses
        
        # Check parent POM
        parent = pom.find('m:parent', POM_NAMESPACES) or pom.find('parent')
        if parent is None:
            return []
        
        parent_group = (parent.findtext('m:groupId', default='', namespaces=POM_NAMESPACES) or 
                       parent.findtext('groupId', default='') or group_id).strip()
        parent_artifact = (parent.findtext('m:artifactId', default='', namespaces=POM_NAMESPACES) or 
                          parent.findtext('artifactId', default='')).strip()
        parent_version = (parent.findtext('m:version', default='', namespaces=POM_NAMESPACES) or 
                         parent.findtext('version', default='')).strip()
        
        if not (parent_artifact and parent_version):
            return []
        
        return MavenCentralClient.lookup_license_recursively(
            parent_group, parent_artifact, parent_version, max_depth - 1
        )


class GitHubClient:
    """Client for fetching license information from GitHub."""
    
    @staticmethod
    def get_license_from_repo_url(repo_url: str) -> List[License]:
        """Extract license information from GitHub repository URL."""
        if "github.com" not in repo_url:
            return []
        
        try:
            # Extract repo path from URL
            repo_path = re.sub(r'\.git$', '', repo_url).split("github.com/")[1]
            api_url = f"{GITHUB_API_BASE}/repos/{repo_path}/license"
            
            response = requests.get(api_url, headers=GITHUB_HEADERS, timeout=10)
            if response.status_code != 200:
                return []
            
            data = response.json()
            spdx_id = data["license"]["spdx_id"]
            license_url = get_canonical_license_url(spdx_id) or data["html_url"]
            
            return [License(name=spdx_id, url=license_url)]
            
        except Exception as e:
            print(f"Failed to fetch GitHub license for {repo_url} - {e}")
            return []


class PackageHeuristics:
    """Applies heuristic rules to determine licenses for common packages."""
    
    HEURISTIC_RULES = {
        'apache_packages': {
            'license': License(name='Apache-2.0', url=get_canonical_license_url('apache-2.0')),
            'conditions': [
                lambda pkg: "org.apache" in pkg.purl,
                lambda pkg: pkg.name.startswith(("tomcat", "tika-", "commons-")),
                lambda pkg: pkg.name in {
                    "catalina", "jasper", "catalina-ha", "catalina-tribes", 
                    "catalina-ssi", "catalina-storeconfig"
                }
            ]
        },
        'jakarta_packages': {
            'license': License(name='EPL-2.0', url=get_canonical_license_url('eclipse public license - v 2.0')),
            'conditions': [lambda pkg: pkg.name.startswith("jakarta")]
        },
        'st4_packages': {
            'license': License(name='BSD-3-Clause', url=get_canonical_license_url('bsd-3-clause')),
            'conditions': [lambda pkg: pkg.name.startswith("st4") or pkg.name == "ST4"]
        },
        'acegi_packages': {
            'license': License(name='Apache-2.0', url=get_canonical_license_url('apache-2.0')),
            'conditions': [lambda pkg: pkg.name.startswith("acegi")]
        }
    }
    
    @classmethod
    def apply_heuristics(cls, package: Package) -> List[License]:
        """Apply heuristic rules to determine license for a package."""
        for rule_name, rule_data in cls.HEURISTIC_RULES.items():
            for condition in rule_data['conditions']:
                if condition(package):
                    print(f"Applied heuristic '{rule_name}' to {package.name}")
                    return [rule_data['license']]
        return []


class SyftOutputParser:
    """Parses Syft template output into Package objects."""
    
    PACKAGE_PATTERN = re.compile(r'^(.+?):(.+?):(.*?) - ?(.*)$')
    
    @staticmethod
    def parse(syft_output: str) -> List[Package]:
        """Parse Syft template output into Package objects."""
        packages = []
        
        for line_num, line in enumerate(syft_output.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
                
            match = SyftOutputParser.PACKAGE_PATTERN.match(line)
            if not match:
                print(f"Could not parse line {line_num}: {line}")
                continue
            
            name, version, purl, license_text = [g.strip() for g in match.groups()]
            
            # Apply Alfresco-specific heuristic
            if name.startswith('alfresco-') and (not license_text or license_text == '-'):
                license_text = 'GNU Lesser General Public License v3.0 or later'
            
            licenses = SyftOutputParser._parse_license_text(license_text)
            
            packages.append(Package(
                name=name,
                version=version,
                purl=purl,
                licenses=licenses,
                license_source='Original'
            ))
        
        return packages
    
    @staticmethod
    def _parse_license_text(license_text: str) -> List[License]:
        """Parse license text into License objects."""
        if not license_text or license_text == '-':
            return []
        
        licenses = []
        # Split on commas, but not within "Version X.X" patterns
        parts = re.split(r',\s*(?![Vv]ersion\b)', license_text)
        
        for part in parts:
            part = part.strip()
            # Remove URLs and trailing semicolons
            clean_name = re.sub(r'https?://\S+', '', part).split(';', 1)[0].strip()
            
            if clean_name:
                licenses.append(License(name=clean_name))
        
        return licenses


class PackageDeduplicator:
    """Handles deduplication of packages with same name and version."""
    
    @staticmethod
    def deduplicate(packages: List[Package]) -> List[Package]:
        """Deduplicate packages by (name, version) key, merging licenses."""
        merged_packages = {}
        
        for package in packages:
            key = package.unique_key
            
            if key not in merged_packages:
                merged_packages[key] = Package(
                    name=package.name,
                    version=package.version,
                    purl=package.purl,
                    licenses=[],
                    license_source=package.license_source
                )
            
            # Merge licenses, avoiding duplicates
            existing_license_names = {lic.name for lic in merged_packages[key].licenses}
            for license_obj in package.licenses:
                if license_obj.name not in existing_license_names:
                    merged_packages[key].licenses.append(license_obj)
                    existing_license_names.add(license_obj.name)
        
        return list(merged_packages.values())


class LicenseEnricher:
    """Enriches packages with missing license information."""
    
    @staticmethod
    def enrich_packages(packages: List[Package]) -> List[Package]:
        """Enrich packages that are missing license information."""
        packages_without_licenses = [pkg for pkg in packages if not pkg.has_licenses]
        
        if not packages_without_licenses:
            print("All packages already have license information")
            return packages
        
        print(f"Enriching {len(packages_without_licenses)} packages from external sources...")
        
        for i, package in enumerate(packages_without_licenses, 1):
            print(f"[{i:3d}/{len(packages_without_licenses)}] {package.name}:{package.version}")
            
            if i > 1:
                time.sleep(RATE_LIMIT_DELAY)  # Rate limiting
            
            licenses = LicenseEnricher._lookup_package_licenses(package)
            
            if licenses:
                package.licenses = licenses
                package.license_source = 'Maven/GitHub/Heuristic'
                print(f"    Found: {', '.join(lic.name for lic in licenses)}")
            else:
                print(f"    No license information found")
        
        return packages
    
    @staticmethod
    def _lookup_package_licenses(package: Package) -> List[License]:
        """Look up license information for a single package."""
        # Try Maven Central first
        maven_coords = LicenseEnricher._extract_maven_coordinates(package.purl)
        if maven_coords:
            licenses = MavenCentralClient.lookup_license_recursively(*maven_coords)
            if licenses:
                return licenses
        
        # Apply heuristics as fallback
        return PackageHeuristics.apply_heuristics(package)
    
    @staticmethod
    def _extract_maven_coordinates(purl: str) -> Optional[Tuple[str, str, str]]:
        """Extract Maven coordinates (groupId, artifactId, version) from PURL."""
        if not purl.startswith("pkg:maven/"):
            return None
        
        try:
            purl_path = purl[len("pkg:maven/"):]
            coordinates, version = purl_path.split("@", 1)
            group_id, artifact_id = coordinates.split("/", 1)
            return group_id, artifact_id, version
        except ValueError:
            return None


class HTMLReportGenerator:
    """Generates HTML reports from package data."""
    
    @staticmethod
    def generate_report(packages: List[Package], image_name: str) -> str:
        """Generate a comprehensive HTML report."""
        stats = HTMLReportGenerator._calculate_statistics(packages)
        package_rows = HTMLReportGenerator._generate_package_rows(packages)
        
        return HTMLReportGenerator._render_html_template(
            image_name=image_name,
            stats=stats,
            package_rows=package_rows
        )
    
    @staticmethod
    def _calculate_statistics(packages: List[Package]) -> Dict:
        """Calculate statistics for the report summary."""
        total_packages = len(packages)
        packages_with_licenses = sum(1 for pkg in packages if pkg.has_licenses)
        packages_without_licenses = total_packages - packages_with_licenses
        
        unique_licenses = set()
        for package in packages:
            for license_obj in package.licenses:
                unique_licenses.add(license_obj.name)
        
        return {
            'total_packages': total_packages,
            'packages_with_licenses': packages_with_licenses,
            'packages_without_licenses': packages_without_licenses,
            'unique_licenses': len(unique_licenses),
            'license_coverage': f"{(packages_with_licenses / total_packages * 100):.1f}%" if total_packages > 0 else "0%"
        }
    
    @staticmethod
    def _generate_package_rows(packages: List[Package]) -> str:
        """Generate HTML table rows for packages."""
        rows = []
        
        # Sort packages by name for better readability
        sorted_packages = sorted(packages, key=lambda p: (p.name.lower(), p.version))
        
        for package in sorted_packages:
            license_links = []
            for license_obj in package.licenses:
                if license_obj.url:
                    license_links.append(
                        f'<a href="{license_obj.url}" target="_blank" title="View license">'
                        f'{license_obj.name}</a>'
                    )
                else:
                    license_links.append(license_obj.name)
            
            license_cell = ', '.join(license_links) if license_links else 'No license specified'
            
            # Add source indicator
            source_indicator = ''
            if package.license_source == 'Maven/GitHub/Heuristic':
                source_indicator = ' <em>(enriched)</em>'
            
            rows.append(
                f'<tr>\n'
                f'  <td>{package.name}</td>\n'
                f'  <td>{package.version}</td>\n'
                f'  <td>{license_cell}{source_indicator}</td>\n'
                f'</tr>\n'
            )
        
        return ''.join(rows)
    
    @staticmethod
    def _render_html_template(image_name: str, stats: Dict, package_rows: str) -> str:
        """Render the complete HTML template."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SBOM Report - {image_name}</title>
</head>
<body>
    <div>
        <h1>Software Bill of Materials (SBOM)</h1>
        
        <h2>Container Image</h2>
        <div>{image_name}</div>
        
        <h2>Summary Statistics</h2>
        <div>
            <div>Total Packages: {stats['total_packages']}</div>
            <div>Packages with Licenses: {stats['packages_with_licenses']}</div>
            <div>Packages without Licenses: {stats['packages_without_licenses']}</div>
            <div>Unique Licenses: {stats['unique_licenses']}</div>
            <div>License Coverage: {stats['license_coverage']}</div>
        </div>
        
        <h2>Package Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Package Name</th>
                    <th>Version</th>
                    <th>Licenses</th>
                </tr>
            </thead>
            <tbody>
                {package_rows}
            </tbody>
        </table>
        
        <div>
            <p>
                Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')} using 
                <a href="https://github.com/anchore/syft" target="_blank">Syft</a>
            </p>
            <p>
                <em>Enriched with license data from Maven Central, GitHub, and intelligent heuristics</em>
            </p>
        </div>
    </div>
</body>
</html>"""


def main() -> None:
    """Main entry point for the SBOM generator."""
    if len(sys.argv) < 2:
        print("Usage: python sbom_generator.py <image> [template] [output]")
        print("\nExamples:")
        print("  python sbom_generator.py ubuntu:latest")
        print("  python sbom_generator.py my-app:v1.0 custom_template.tmpl")
        print("  python sbom_generator.py nginx:alpine - custom_report.html")
        sys.exit(1)

    # Parse command line arguments
    image_name = sys.argv[1]
    template_file = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != '-' else None
    output_file = sys.argv[3] if len(sys.argv) > 3 else "sbom_report.html"

    print(f"Starting SBOM analysis for: {image_name}")
    print("=" * 60)

    try:
        # Step 1: Run Syft to generate SBOM
        print("Running Syft to generate SBOM...")
        syft_output = SyftRunner.run(image_name, template_file)
        
        if not syft_output.strip():
            print("Syft produced no output. Check your image name and template.")
            sys.exit(1)

        # Step 2: Parse Syft output
        print("Parsing Syft output...")
        packages = SyftOutputParser.parse(syft_output)
        
        if not packages:
            print("No packages found in Syft output. Check your template format.")
            sys.exit(1)
        
        print(f"Found {len(packages)} packages")

        # Step 3: Enrich missing license information
        print("\nEnriching license information...")
        packages = LicenseEnricher.enrich_packages(packages)

        # Step 4: Deduplicate packages
        print("Deduplicating packages...")
        original_count = len(packages)
        packages = PackageDeduplicator.deduplicate(packages)
        
        if len(packages) != original_count:
            print(f"Deduplicated: {original_count} → {len(packages)} packages")

        # Step 5: Generate HTML report
        print(f"Generating HTML report: {output_file}")
        html_content = HTMLReportGenerator.generate_report(packages, image_name)
        
        # Write report to file
        output_path = Path(output_file)
        output_path.write_text(html_content, encoding='utf-8')
        
        # Final statistics
        packages_with_licenses = sum(1 for pkg in packages if pkg.has_licenses)
        coverage_percentage = (packages_with_licenses / len(packages) * 100) if packages else 0
        
        print("=" * 60)
        print("SBOM Analysis Complete!")
        print(f"Total packages: {len(packages)}")
        print(f"Packages with licenses: {packages_with_licenses}")
        print(f"License coverage: {coverage_percentage:.1f}%")
        print(f"Report saved to: {output_path.absolute()}")
        
        if coverage_percentage < 80:
            print("Consider adding more heuristics or data sources for better coverage")

    except KeyboardInterrupt:
        print("\n⏹Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()