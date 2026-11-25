"""Exact input-file identity; not an attestation of result authenticity."""
import hashlib
from pathlib import Path


def input_identity(paths):
    digests = sorted(hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths)
    if not digests:
        raise ValueError('At least one input file required')
    return 'sha256-files-v1:' + hashlib.sha256('\n'.join(digests).encode('ascii')).hexdigest()
