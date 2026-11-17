"""Passive-only census of a confirmed child PGID; never authorizes or sends signals."""
import time


def passive_drain(pgid, read_members, seconds=3.0, interval=0.1,
                  monotonic=time.monotonic, sleep=time.sleep):
    deadline = monotonic() + seconds
    members = read_members(pgid)
    samples = [members]
    while members and monotonic() < deadline:
        sleep(min(interval, max(0.0, deadline - monotonic())))
        members = read_members(pgid)
        samples.append(members)
    return members, samples
