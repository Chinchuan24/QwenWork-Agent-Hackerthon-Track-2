from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock
import socket

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from aegis.alarm import Assessment, AlarmManagement, reminder_view


def test_midnight_singapore_calendar_deadline():
    a = Assessment(True, 500, 'unknown', True, datetime(2026, 11, 18, 15, 59, tzinfo=timezone.utc))
    before = reminder_view(a, datetime(2026, 11, 18, 15, 59, tzinfo=timezone.utc))
    after = reminder_view(a, datetime(2026, 11, 18, 16, 1, tzinfo=timezone.utc))
    assert before['assessed_at'] == '2026-11-18T23:59:00+08:00'
    assert before['deadline'] == '2026-11-21T23:59:59+08:00'
    assert before['remaining_seconds'] - after['remaining_seconds'] == 120
    assert after['timezone'] == 'Asia/Singapore'


@pytest.mark.parametrize('count,harm', [(499, 'yes'), (500, 'no'), (900, 'unknown')])
def test_no_automatic_determination(count, harm):
    view = reminder_view(Assessment(True, count, harm), datetime.now(timezone.utc))
    assert view['state'] == 'awaiting_assessment'
    assert view['deadline'] is None


def test_no_personal_data():
    view = reminder_view(Assessment(False), datetime.now(timezone.utc))
    assert view['state'] == 'no_personal_data'
    assert not view['show_reminder']


@pytest.mark.parametrize('kwargs', [
    {'personal_data': 'yes'}, {'people_count': True}, {'people_count': -1},
    {'harm': 'private text'}, {'owner_notifiable': 'yes'}, {'owner_notifiable': True},
    {'owner_notifiable': True, 'assessed_at': datetime(2026, 11, 18)},
    {'personal_data': False, 'owner_notifiable': True, 'assessed_at': datetime.now(timezone.utc)},
    {'assessed_at': datetime.now(timezone.utc)},
])
def test_invalid_assessment(kwargs):
    values = {'personal_data': True}
    values.update(kwargs)
    with pytest.raises(ValueError):
        Assessment(**values)


def test_overdue_future_and_naive_clock():
    a = Assessment(True, None, 'unknown', True, datetime(2026, 11, 18, tzinfo=timezone.utc))
    assert reminder_view(a, datetime(2026, 11, 21, 15, 59, 59, tzinfo=timezone.utc))['remaining_seconds'] == 0
    assert reminder_view(a, datetime(2026, 11, 21, 16, tzinfo=timezone.utc))['state'] == 'overdue'
    for now in (datetime(2026, 11, 17, tzinfo=timezone.utc), datetime(2026, 11, 19)):
        with pytest.raises(ValueError):
            reminder_view(a, now)


def test_no_outgoing_calls_or_personal_text(monkeypatch):
    monkeypatch.setattr(socket, 'socket', Mock(side_effect=AssertionError('network forbidden')))
    assert reminder_view(Assessment(True, 500, 'yes'), datetime.now(timezone.utc))['deadline'] is None
    assert set(Assessment.__dataclass_fields__) == {'personal_data', 'people_count', 'harm', 'owner_notifiable', 'assessed_at'}


def test_management_delegation_and_failure():
    adapter = Mock()
    adapter.perform.return_value = {'status': 'recorded'}
    request = object()
    management = AlarmManagement(adapter)
    assert management.perform(request, 'freeze_helper', 'card-1') == {'status': 'recorded'}
    adapter.perform.assert_called_once_with(request, 'freeze_helper', 'card-1', None)
    adapter.perform.side_effect = PermissionError('denied')
    with pytest.raises(PermissionError):
        management.perform(request, 'unfreeze_helper', 'card-1')
    with pytest.raises(RuntimeError):
        AlarmManagement().perform(request, 'freeze_helper', 'card-1')


def test_contract_only_target_frozen_helpers_cannot_unfreeze():
    class Adapter:
        def __init__(self):
            self.frozen = set()
        def perform(self, request, operation, target, assessment):
            if request != 'authenticated-human':
                raise PermissionError('human required')
            if operation == 'freeze_helper':
                self.frozen.add(target)
            elif operation == 'unfreeze_helper':
                self.frozen.remove(target)
            return {'status': 'recorded'}
    adapter = Adapter()
    management = AlarmManagement(adapter)
    management.perform('authenticated-human', 'freeze_helper', 'card-1')
    assert 'card-1' in adapter.frozen and 'card-2' not in adapter.frozen
    for target in ('card-1', 'card-2'):
        with pytest.raises(PermissionError):
            management.perform('helper', 'unfreeze_helper', target)
    assert 'card-1' in adapter.frozen


def test_invalid_commands_never_delegate():
    adapter = Mock()
    for operation, target in [('send_notification', 'card-1'), ('freeze_helper', ''), ('stop_everything', 'card-1')]:
        with pytest.raises(ValueError):
            AlarmManagement(adapter).perform(object(), operation, target)
    adapter.perform.assert_not_called()


def test_template_plain_inert_escaped():
    root = Path(__file__).resolve().parents[1]
    env = Environment(loader=FileSystemLoader(root / 'templates'), autoescape=select_autoescape())
    html = env.get_template('alarm.html').render(alarm=reminder_view(Assessment(False), datetime.now(timezone.utc)), helpers=[{'card_id': '<script>private</script>', 'frozen': True}], user=None, live_mode=True)
    assert '<script>private</script>' not in html
    assert '&lt;script&gt;private&lt;/script&gt;' in html
    assert 'Security room' in html and 'not legal advice' in html
    assert 'No personal data' in html
    text = (root / 'templates/alarm.html').read_text().lower()
    for word in ('compliant', 'certified', 'approved by', 'guarantees', 'fetch(', 'type="submit"'):
        assert word not in text
