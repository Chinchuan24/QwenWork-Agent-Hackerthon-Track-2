"""Static contracts only; browser execution is not asserted here."""
from pathlib import Path
import re

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'static/approval-review.js'


@pytest.fixture
def source():
    assert SCRIPT.is_file(), 'G1 external visibility script is missing'
    return SCRIPT.read_text(encoding='utf-8')


def test_activation_requires_marker_and_csrf(source):
    assert 'querySelector("[data-review-view-url]")' in source
    assert 'getAttribute("data-csrf")' in source
    assert 'if (!urlValue || !csrf) return;' in source


def test_requires_observer_and_visible_document(source):
    assert 'typeof IntersectionObserver' in source
    assert 'new IntersectionObserver' in source
    assert 'entry.isIntersecting && entry.intersectionRatio > 0' in source
    assert 'document.visibilityState !== "visible"' in source
    assert 'visibilitychange' in source


def test_same_origin_post_with_csrf_only(source):
    assert 'new URL(urlValue, window.location.href)' in source
    assert 'url.origin !== window.location.origin' in source
    assert 'method: "POST"' in source
    assert 'credentials: "same-origin"' in source
    assert 'mode: "same-origin"' in source
    assert 'redirect: "error"' in source
    assert 'new URLSearchParams({ csrf: csrf })' in source


def test_success_once_and_no_overlapping_attempts(source):
    assert 'if (sent || pending || !intersecting ||' in source
    assert source.index('pending = true;') < source.index('await fetch(')
    assert 'if (response.ok)' in source
    assert 'sent = true;' in source
    assert 'observer.disconnect();' in source
    assert 'removeEventListener("visibilitychange", attempt)' in source


def test_failure_rearms_without_automatic_retry(source):
    assert re.search(r'finally\s*\{\s*pending = false;\s*\}', source)
    assert not re.search(r'setTimeout|setInterval|requestAnimationFrame|\bwhile\s*\(', source)
    assert source.count('attempt();') == 1


def test_no_client_timestamp_or_dynamic_script(source):
    assert not re.search(r'\bDate\b|performance\.now|timestamp|viewed_at|sendBeacon', source)
    assert not re.search(r'\beval\s*\(|new Function|<script|onclick|innerHTML', source)


def test_passive_tracking_does_not_change_focus_or_controls(source):
    assert not re.search(r'\.focus\s*\(|preventDefault|\.disabled\s*=|setAttribute\(', source)
