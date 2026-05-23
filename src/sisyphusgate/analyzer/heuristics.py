from __future__ import annotations

from sisyphusgate.gateway.session import Session


def analyze_heuristics(session: Session) -> tuple[int, list[str]]:
    score = 0
    tags: list[str] = []

    payload_size_score, payload_tags = _check_payload_size(session)
    score += payload_size_score
    tags.extend(payload_tags)

    fast_close_score, fast_close_tags = _check_fast_close(session)
    score += fast_close_score
    tags.extend(fast_close_tags)

    binary_score, binary_tags = _check_binary_data(session)
    score += binary_score
    tags.extend(binary_tags)

    return score, tags


def _check_payload_size(session: Session) -> tuple[int, list[str]]:
    if len(session.initial_data) > 2048:
        return 20, ["large_payload"]
    return 0, []


def _check_fast_close(session: Session) -> tuple[int, list[str]]:
    if len(session.initial_data) == 0:
        return 25, ["port_scan_probe"]
    return 0, []


def _check_binary_data(session: Session) -> tuple[int, list[str]]:
    data = session.initial_data
    if not data:
        return 0, []

    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / len(data)
    if ratio < 0.5:
        return 15, ["binary_payload"]
    return 0, []