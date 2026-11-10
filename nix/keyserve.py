"""Serve a private key on a FIFO: one complete copy per open.

Usage: printf '%s\\n' "$key" | iam-ra-keyserve FIFO PARENT_PID

Each reader gets at least one whole copy (aws_signing_helper takes the
first PEM block, so repeats are harmless). Exits, removing FIFO and its
directory, once PARENT_PID is no longer our parent, even after SIGKILL.
"""

import errno
import os
import signal
import sys
import time

fifo, parent = sys.argv[1], int(sys.argv[2])
key = sys.stdin.buffer.read()
signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def pause():
    """Sleep briefly; clean up and exit if the parent is gone."""
    if os.getppid() != parent:
        try:
            os.unlink(fifo)
            os.rmdir(os.path.dirname(fifo))
        except OSError:
            pass
        sys.exit(1)
    time.sleep(0.005)


while True:
    # Non-blocking open fails with ENXIO until a reader opens the FIFO,
    # so we can poll the parent instead of hanging in open(). No O_CREAT:
    # a missing path means the wrapper is gone.
    try:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    except OSError as e:
        if e.errno != errno.ENXIO:
            sys.exit(f"iam-ra-keyserve: {fifo}: {e.strerror}")
        pause()
        continue
    os.set_blocking(fd, True)
    # Close only after one full copy went out in a single write; on EPIPE
    # or a short write, write it all again for the next reader.
    while True:
        try:
            if os.write(fd, key) == len(key):
                break
        except BrokenPipeError:
            pass
        pause()
    os.close(fd)
