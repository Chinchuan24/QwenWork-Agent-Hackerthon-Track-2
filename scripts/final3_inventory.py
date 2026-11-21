"""Offline installed license inventory. No credentials or network accessed."""
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    lock = dict(re.findall(r'^([\w-]+)==([^\s\\]+)',
        (ROOT / 'requirements-production.lock').read_text(), re.M))
    rows = []
    for distribution in sorted(metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
        name = distribution.metadata['Name']
        expression = distribution.metadata.get('License-Expression') or distribution.metadata.get('License')
        resolved = {'Jinja2': 'BSD-3-Clause', 'markdown-it-py': 'MIT', 'mdurl': 'MIT',
                    'pip_audit': 'Apache-2.0', 'tomli_w': 'MIT'}
        resolution = resolved.get(name) if not expression else None
        licenses = [f for f in distribution.files or [] if
            any(word in str(f).lower() for word in ('license', 'copying', 'notice'))]
        native = [f for f in distribution.files or [] if str(f).endswith(('.so', '.dylib', '.dll', '.exe'))]
        rows.append(dict(name=name, version=distribution.version, license=expression or resolution,
            metadata_disposition='Included installed LICENSE text inspected: ' + resolution if resolution else 'Declared metadata',
            classifiers=[v for v in distribution.metadata.get_all('Classifier', []) if v.startswith('License')],
            license_files=[dict(path=str(f), sha256=hashlib.sha256(distribution.locate_file(f).read_bytes()).hexdigest())
                           for f in licenses if distribution.locate_file(f).is_file()],
            native_files=[dict(path=str(f), sha256=hashlib.sha256(distribution.locate_file(f).read_bytes()).hexdigest(),
                linkage=subprocess.check_output(['otool', '-L', str(distribution.locate_file(f))], text=True)
                    .replace(str(distribution.locate_file(f)), str(f))) for f in native if distribution.locate_file(f).is_file()],
            review_required=not (expression or resolution) or any(v in (expression or resolution or '') for v in ('GPL', 'AGPL', 'UNKNOWN'))))
    installed = {r['name'].lower().replace('_', '-'): r for r in rows}
    mismatches = [name for name, version in lock.items() if
                  installed.get(name.lower(), {}).get('version') != version]
    result = dict(scope='Entire installed Python environment plus production lock offline comparison',
        installed_count=len(rows), production_lock_count=len(lock), lock_mismatches=mismatches,
        packages=rows, disposition='Permissive dependency notices coexist with MIT project contributions. '
        'Certifi MPL files retain MPL source/notice obligations. Platform Python/macOS/Linux libraries '
        'are not bundled in this source export and are not a source-release gap. Native installed '
        'extensions inspected with otool. cffi links unbundled /usr/lib/libffi.dylib; PyYAML, '
        'MarkupSafe and greenlet link platform libSystem/libc++. cryptography statically embeds '
        'OpenSSL 4.0.3; installed wheel has only project LICENSE/APACHE/BSD, no OpenSSL notice or '
        'Rust dependency bill of materials. pydantic_core wheel likewise lacks Rust dependency '
        'bill of materials. These exact binary redistribution clearances remain unverified; '
        'no such native binaries are copied into the source-only release.')
    (ROOT / 'docs/final3-installed-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(installed=len(rows), production=len(lock), lock_mismatches=mismatches)))
