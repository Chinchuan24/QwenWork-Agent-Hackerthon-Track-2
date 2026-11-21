"""Pure hello negotiation tests; injected capabilities are test data only."""

from copy import deepcopy

import pytest

from aegis.signer_protocol import negotiate_hello


def test_valid_v2_and_inputs_are_unchanged():
    request = {'protocol_versions': [1, 2], 'required_capabilities': ['atomic_sign']}
    capabilities = {1: {'verify'}, 2: {'verify', 'atomic_sign'}}
    before = deepcopy((request, capabilities))
    assert negotiate_hello(request, capabilities) == {
        'ok': True, 'protocol_version': 2,
        'capabilities': ['atomic_sign', 'verify'],
    }
    assert (request, capabilities) == before


@pytest.mark.parametrize('capabilities,expected', [
    ({1: {'verify'}, 2: {'verify'}, 3: {'verify'}}, 3),
    ({1: {'verify'}, 2: {'sign'}, 3: {'sign'}}, 1),
])
def test_highest_common_version_satisfying_requirements(capabilities, expected):
    request = {'protocol_versions': [2, 1, 3], 'required_capabilities': ['verify']}
    assert negotiate_hello(request, capabilities)['protocol_version'] == expected


@pytest.mark.parametrize('capabilities', [{1: {'verify'}}, {}])
def test_no_overlap(capabilities):
    result = negotiate_hello(
        {'protocol_versions': [2], 'required_capabilities': ['verify']}, capabilities)
    assert result == {'ok': False, 'error': 'PROTOCOL_INCOMPATIBLE',
                      'missing_capabilities': {}}


def test_capabilities_cannot_be_unioned_across_versions():
    result = negotiate_hello(
        {'protocol_versions': [1, 2], 'required_capabilities': ['sign', 'verify']},
        {1: {'sign'}, 2: {'verify'}})
    assert result == {'ok': False, 'error': 'PROTOCOL_INCOMPATIBLE',
                      'missing_capabilities': {2: ['sign'], 1: ['verify']}}


def test_duplicates_are_deduplicated_and_empty_requirements_are_valid():
    assert negotiate_hello(
        {'protocol_versions': [1, 2, 2], 'required_capabilities': []},
        {1: {'verify'}, 2: set()}) == {
            'ok': True, 'protocol_version': 2, 'capabilities': []}
    assert negotiate_hello(
        {'protocol_versions': [1, 1], 'required_capabilities': ['sign', 'sign']},
        {1: set()})['missing_capabilities'] == {1: ['sign']}


@pytest.mark.parametrize('handshake', [
    None, [], 'hello', 1, True, {},
    {'required_capabilities': []}, {'protocol_versions': [1]},
    *({'protocol_versions': value, 'required_capabilities': []}
      for value in (None, [], '1', (1,), [True], [False], [0], [-1],
                    [1.0], ['1'], [None], [1, True])),
    *({'protocol_versions': [1], 'required_capabilities': value}
      for value in (None, 'sign', ('sign',), [''], [None], [1], [True])),
])
def test_malformed_handshake(handshake):
    result = negotiate_hello(handshake, {1: set()})
    assert result['ok'] is False
    assert result['error'] == 'BAD_HANDSHAKE'
    assert isinstance(result['message'], str) and result['message']
