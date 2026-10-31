"""One lease holder for the K-C contention test. Run as a script: <lease_dir> <holder> <rounds>.

Acquires and releases the same resource in a loop and prints the fencing tokens it saw as JSON.
Started with subprocess by test_kc_native_lease.py so nothing is pickled across the process boundary.
"""

import json
import random
import sys
import time


def main(lease_dir, holder, rounds):
    from kibisis import LeaseConflictError
    from kibisis.lease import FileLeaseCoordinator

    c = FileLeaseCoordinator(lease_dir)
    tokens = []
    deadline = time.monotonic() + 90
    while len(tokens) < rounds:
        if time.monotonic() > deadline:
            break  # the caller's count assertion names the shortfall instead of a hung job
        try:
            lease = c.acquire("shared", holder, ttl_seconds=5)
        except LeaseConflictError:
            time.sleep(random.uniform(0.001, 0.005))
            continue
        tokens.append(lease.fencing_token)
        assert c.validate_fencing_token("shared", holder, lease.fencing_token)
        assert c.release(lease)
    print(json.dumps(tokens))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
