"""Download exact upstream commits into ignored build contexts (Python 3.8+)."""
import io
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
REVISIONS = {
    'snare': 'b17fdfe7c2ba3ac540548763d73fc475cfc185c4',
    'tanner': '3bc9ae2831db2d7e9c3aa3fb98b3b3a6fc73b18c',
}
for name, revision in REVISIONS.items():
    target = ROOT / 'vendor' / name
    if target.exists():
        print('{} already present; preserve local source'.format(name))
        continue
    url = 'https://codeload.github.com/mushorg/{}/tar.gz/{}'.format(name, revision)
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts[1:]
            if not parts or member.isdir():
                continue
            if member.issym() or member.islnk() or not member.isfile() or '..' in parts:
                raise ValueError('Unexpected archive member: {}'.format(member.name))
            destination = target.joinpath(*parts).resolve()
            if target.resolve() not in destination.parents:
                raise ValueError('Archive path escapes source directory')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.extractfile(member).read())
    print('{}: {}'.format(name, revision))
