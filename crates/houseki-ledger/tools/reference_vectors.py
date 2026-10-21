#!/usr/bin/env python3
"""Independent integer hash and canonical record oracle for reference schema 1.

This tool uses no Rust encoder, executable or digest output.

Public pinned constants are stored alongside it and an established recipient hash checks
our independent arithmetic.

The --check path only reads the retained fixtures and never regenerates them.
"""

import argparse
import json
from pathlib import Path

# The reference Goldilocks prime defines every modular operation.
PRIME = 2 ** 64 - 2 ** 32 + 1

# The fixed external block matrix is evaluated directly rather than through Rust.
MATRIX = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def external(state):
    """Evaluate the complete external matrix directly with integer modular arithmetic."""
    return [
        sum(
            state[column]
            * MATRIX[row % 4][column % 4]
            * (2 if row // 4 == column // 4 else 1)
            for column in range(16)
        ) % PRIME
        for row in range(16)
    ]


def permute(state, initial, internal, final, diagonal):
    """Apply the fixed round schedule with direct modular powers and matrix products."""
    state = external(state)
    for offset in range(0, 64, 16):
        state = external([
            pow(value + initial[offset + i], 7, PRIME)
            for i, value in enumerate(state)
        ])

    for constant in internal:
        state[0] = pow(state[0] + constant, 7, PRIME)
        total = sum(state)
        state = [(total + value * diagonal[i]) % PRIME for i, value in enumerate(state)]

    for offset in range(0, 64, 16):
        state = external([
            pow(value + final[offset + i], 7, PRIME)
            for i, value in enumerate(state)
        ])

    return state


def digest(label, parts, parameters):
    """Frame the literal parts and evaluate the complete sponge and integer extraction."""
    frame = len(label).to_bytes(2, 'little') + label + len(parts).to_bytes(4, 'little')
    for part in parts:
        frame += len(part).to_bytes(8, 'little') + part

    encoded = len(frame).to_bytes(8, 'little') + frame
    words = [int.from_bytes(encoded[i:i + 7], 'little') for i in range(0, len(encoded), 7)]
    words.append(1)
    words += [0] * (-len(words) % 7)

    state = [0] * 16
    for offset in range(0, len(words), 7):
        for i, word in enumerate(words[offset:offset + 7]):
            state[i] = (state[i] + word) % PRIME

        state = permute(state, *parameters)

    samples = state[:7] + permute(state, *parameters)[:4]
    integer = sum((value * PRIME ** i for i, value in enumerate(samples))) % 2 ** 512

    return integer.to_bytes(64, 'little').hex()


def u32(n):
    """Encode a complete schema tag."""
    return n.to_bytes(4, 'little')


def u64(n):
    """Encode a complete sequence or length."""
    return n.to_bytes(8, 'little')


def u128(n):
    """Encode a complete amount or count."""
    return n.to_bytes(16, 'little')


def blob(value):
    """Frame one record with its independent byte length."""
    return u64(len(value)) + value


def listing(values):
    """Frame an ordered list with count and record prefixes."""
    return u64(len(values)) + b''.join((blob(v) for v in values))


def vectors():
    """Build exact public records directly from the governing field order tables."""
    parameters = json.loads(
        Path(__file__).with_name('poseidon2_parameters.json').read_text()
    )['parameters']
    assert digest(
        b"houseki/v1/recipient/kem-key", [b""], parameters
    ) == (
        '9eaca7771384bbd29d7a6ab689ebf558b05a7a0d1afbfa9dd1924798123f1c0d'
        'b97518cea39f4c3b72ce77930b93db258477e3d25db9e21e46e090ae612dc301'
    )

    def h(domain, value):
        """Commit one reference schema record under its fixed ledger domain."""
        return bytes.fromhex(digest(
            b'houseki/v1/ledger/' + domain, [u32(1), value], parameters
        ))

    network = bytes([7]) * 64
    policy = (
        u32(1)
        + listing([u32(0xffff0008)])
        + listing([u32(0xffff0007)])
        + u32(0xffff0001)
    )
    policy += u128(0) + u128(1) + u128(1) + u128(1)
    policy += (
        b''.join(
            u64(n) for n in [
                16384, 2097152, 4096, 64, 16777216, 64, 128, 33554432,
                4096, 4096, 64, 64, 16384, 32, 64,
            ]
        )
        + u32(1) * 3
    )

    def nh(role, parts):
        """Hash note tree components under the independent network binding."""
        return bytes.fromhex(digest(
            b'houseki/v1/note-tree/' + role, [network, *parts], parameters
        ))

    top = nh(b'empty', [])
    empty = [top]
    for level in range(64):
        top = nh(b'node', [u32(level), top, top])
        empty.append(top)

    root = nh(b'root', [u32(64), u128(0), top])
    authority = bytes([14]) * 2592
    account_id = bytes.fromhex(digest(
        b'houseki/v1/reward/account', [network, u32(1), authority], parameters
    ))

    high = 0x0102030405060708
    weight = 0x0102030405060708090a0b0c0d0e0f10
    account = account_id + authority + u128(7) + u64(high)
    anchor = u64(0) + network + u128(0) + root
    committee = bytes([5]) * 64 + u128(weight) + account_id + blob(bytes([6]))

    snapshot = (
        network
        + root
        + u128(0)
        + listing([])
        + listing([account])
        + listing([anchor])
        + blob(policy)
        + u64(0)
        + bytes([3]) * 64
        + listing([committee])
        + u128(100)
        + u128(107)
    )

    body = (
        u32(1)
        + u32(1)
        + bytes([1]) * 64
        + u32(1)
        + u32(0xffff0008)
        + u32(0xffff0001)
        + u64(0)
        + u64(9)
    )
    body += (
        bytes([3]) * 64
        + u64(1)
        + bytes(64)
        + u128(0)
        + u64(1)
        + bytes([2]) * 64
        + bytes(1568)
        + blob(b'')
    )

    envelope = u32(1) + blob(body) + blob(bytes([5, 6, 7])) + blob(b'')
    occurrence = (
        bytes([1]) * 64
        + bytes([2]) * 64
        + u64(0)
        + bytes([3]) * 64
        + u64(2 ** 64 - 1)
        + blob(envelope)
    )
    occurrences = listing([occurrence])
    receipts = listing([bytes([1]) * 64 + u64(2 ** 64 - 1) + u32(1) + u32(0)])

    ae = account_id + u128(7) + u64(high) + u128(9) + u64(high)
    payload = (
        listing([bytes(64)])
        + listing([u64(high) + bytes([2]) * 64])
        + listing([ae])
        + u128(100)
        + u128(98)
    )
    effects = listing([bytes([1]) * 64 + u64(2 ** 64 - 1) + u32(1) + blob(payload)])

    unit = u64(0) + bytes(64) + occurrences
    stream = network + bytes(64) + listing([h(b'fixture-order-unit', unit)])

    order = bytes([4]) * 64 + bytes([5]) * 64 + u64(0) + u64(1) + u64(1)
    events = listing([])
    header = (
        u32(1)
        + h(b'execution-policy', policy)
        + network
        + u64(high)
        + u64(0)
        + bytes([3]) * 64
        + bytes(64)
        + h(b'reference-state', snapshot) * 2
        + blob(order)
        + h(b'ordered-occurrences', occurrences)
        + u64(1)
        + h(b'receipts', receipts)
        + h(b'public-effects', effects)
        + h(b'system-events', events)
    )

    one = nh(b'leaf', [bytes([2]) * 64])
    for level in range(64):
        one = nh(b'node', [u32(level), one, empty[level]])

    one_root = nh(b'root', [u32(64), u128(1), one])

    bootstrap_account = account_id + authority + u128(0) + u64(0)
    bootstrap_anchor = u64(0) + network + u128(1) + one_root
    bootstrap_committee = bytes([5]) * 64 + u128(1) + account_id + blob(bytes([6]))
    bootstrap = (
        network
        + one_root
        + u128(1)
        + listing([])
        + listing([bootstrap_account])
        + listing([bootstrap_anchor])
        + blob(policy)
        + u64(0)
        + bytes([3]) * 64
        + listing([bootstrap_committee])
        + u128(100)
        + u128(100)
    )

    records = {
        'bootstrap': bootstrap,
        'policy': policy,
        'snapshot': snapshot,
        'occurrences': occurrences,
        'receipts': receipts,
        'effects': effects,
        'artifact_header': header,
        'fixture_unit': unit,
        'fixture_stream': stream,
        'system_events': events,
    }

    domains = {
        'bootstrap': b'reference-state',
        'policy': b'execution-policy',
        'snapshot': b'reference-state',
        'occurrences': b'ordered-occurrences',
        'receipts': b'receipts',
        'effects': b'public-effects',
        'artifact_header': b'execution-artifact',
        'fixture_unit': b'fixture-order-unit',
        'fixture_stream': b'fixture-order-stream',
        'system_events': b'system-events',
    }

    result = {name + '.bin': value for name, value in records.items()}
    result.update({
        name + '.hex': (h(domains[name], value).hex() + '\n').encode()
        for name, value in records.items()
    })

    return result


def main():
    """Check immutable fixtures or explicitly create their initial files."""
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', type=Path)
    group.add_argument('--write', type=Path)
    args = parser.parse_args()

    directory = args.check or args.write
    expected = vectors()
    if args.write:
        directory.mkdir(parents=True, exist_ok=True)

    for name, value in expected.items():
        target = directory / name
        if args.write:
            target.write_bytes(value)
        elif target.read_bytes() != value:
            raise SystemExit('fixture mismatch: ' + name)

    print(
        str(len(expected))
        + ' independent record/hash fixtures '
        + ('checked' if args.check else 'written')
    )


if __name__ == '__main__':
    main()
