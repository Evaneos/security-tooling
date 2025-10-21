import json
import sys

def detect_os(data):
    for result in data.get('Results', []):
        if result.get('Class') == 'os-pkgs':
            os_type = result.get('Type', '').lower()
            if 'alpine' in os_type:
                return 'apk'
            elif 'debian' in os_type or 'ubuntu' in os_type:
                return 'apt'
    return None

def get_packages(data):
    packages = set()
    for result in data.get('Results', []):
        if result.get('Class') == 'os-pkgs':
            for vuln in result.get('Vulnerabilities', []):
                pkg = vuln.get('PkgName')
                if pkg:
                    packages.add(pkg)
    return sorted(packages)

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <trivy-output.json>")
        sys.exit(1)
    
    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {sys.argv[1]} not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {sys.argv[1]}")
        sys.exit(1)
    
    os_type = detect_os(data)
    packages = get_packages(data)
    
    output_file = "dockerfile-suggestions.txt"
    
    with open(output_file, 'w') as f:
        if os_type == 'apk':
            if packages:
                f.write("RUN apk update && \\\n")
                f.write(f"    apk upgrade {' '.join(packages)} && \\\n")
                f.write("    rm -rf /var/cache/apk/*\n")
        elif os_type == 'apt':
            if packages:
                f.write("RUN apt-get update && \\\n")
                f.write(f"    apt-get upgrade -y {' '.join(packages)} && \\\n")
                f.write("    apt-get clean && \\\n")
                f.write("    rm -rf /var/lib/apt/lists/*\n")
        else:
            print("Error: OS not detected or not supported (Debian/Alpine only)")
            sys.exit(1)
    
    print(f"Suggestions written to {output_file}")

if __name__ == '__main__':
    main()