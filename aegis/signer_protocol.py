"""Hello negotiation only, not signer transport or transactional signing.

The caller supplies the capabilities actually supported by each protocol version.
This module declares no server capabilities and no storage format.
"""

from collections.abc import Iterable, Mapping


def negotiate_hello(
    request: object, protocol_capabilities: Mapping[int, Iterable[str]]
) -> dict:
    """Select the highest common version meeting every requested capability.

    The capability mapping is trusted caller configuration. Duplicate versions
    and requirements are accepted and deduplicated; empty requirements are valid.
    Missing capabilities are reported separately for each common version.
    """
    if not isinstance(request, dict):
        return {'ok': False, 'error': 'BAD_HANDSHAKE',
                'message': 'Handshake must be an object.'}

    versions = request.get('protocol_versions')
    if (not isinstance(versions, list) or not versions
            or any(type(version) is not int or version <= 0 for version in versions)):
        return {'ok': False, 'error': 'BAD_HANDSHAKE',
                'message': 'protocol_versions must be a nonempty list of positive integers.'}

    required = request.get('required_capabilities')
    if (not isinstance(required, list)
            or any(not isinstance(capability, str) or not capability
                   for capability in required)):
        return {'ok': False, 'error': 'BAD_HANDSHAKE',
                'message': 'required_capabilities must be a list of nonempty strings.'}

    required = set(required)
    missing_by_version = {}
    for version in sorted(set(versions).intersection(protocol_capabilities), reverse=True):
        capabilities = set(protocol_capabilities[version])
        missing = sorted(required - capabilities)
        if not missing:
            return {'ok': True, 'protocol_version': version,
                    'capabilities': sorted(capabilities)}
        missing_by_version[version] = missing

    return {'ok': False, 'error': 'PROTOCOL_INCOMPATIBLE',
            'missing_capabilities': missing_by_version}
