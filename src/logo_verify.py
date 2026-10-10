#!/usr/bin/env python3
"""Independent verifier for ZTE/MediaTek B760H LOGO candidates."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

TABLE_OFFSET = 0x260
PAYLOAD_OFFSET = 0x278
FILE_SIZE = 0x300000
WRAPPER_OFFSET = 0x60
HEADER_END_OFFSET = 0x44
RESOURCE_COUNT = 4
RESOURCE_TABLE_SIZE = 0x18
WRAPPER_SIZE_OFFSET = 0x64
TABLE_COUNT_OFFSET = 0x260
TABLE_TOTAL_OFFSET = 0x264
TABLE_SIZE_OFFSET = 0x268
TABLE_ENDS_OFFSET = 0x26C

RESOURCE_DIMENSIONS = ((720, 480), (720, 576), (1280, 720), (1920, 1080))
RGB565_BYTES_PER_PIXEL = 2
ANIMATION_FRAME_COUNT = 35
ANIMATION_DIMENSIONS = (1920, 1080)
IMMUTABLE_HEADER_RANGES = ((0x00, 0x44), (0x48, 0x64), (0x68, 0x260))


@dataclass(frozen=True)
class Resource:
    start: int
    end: int
    compressed: bytes
    raw: bytes


@dataclass(frozen=True)
class Logo:
    data: bytes
    size: int
    sha256: str
    wrapper_size: int
    table_total: int
    table_size: int
    package_end: int
    header44: int
    resources: tuple[Resource, ...]


@dataclass(frozen=True)
class Animation:
    start: int
    end: int
    compressed: bytes
    raw: bytes


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resource_raw_size(width: int, height: int) -> int:
    return width * height * RGB565_BYTES_PER_PIXEL


def animation_frame_size() -> int:
    width, height = ANIMATION_DIMENSIONS
    return resource_raw_size(width, height)


def animation_raw_size() -> int:
    return ANIMATION_FRAME_COUNT * animation_frame_size()


def parse_logo(path: Path) -> Logo:
    data = path.read_bytes()

    if len(data) != FILE_SIZE:
        raise ValueError(
            f"{path}: unexpected file size {len(data):,}; "
            f"expected {FILE_SIZE:,}"
        )

    if data[:4] != bytes.fromhex("55 66 77 88"):
        raise ValueError(f"{path}: invalid outer LOGO magic")

    if data[WRAPPER_OFFSET:WRAPPER_OFFSET + 4] != bytes.fromhex("88 16 88 58"):
        raise ValueError(f"{path}: invalid MTK wrapper magic")

    if data[0x68:0x6C] != b"LOGO":
        raise ValueError(f"{path}: missing LOGO wrapper name")

    wrapper_size = u32le(data, WRAPPER_SIZE_OFFSET)
    table_total = u32le(data, TABLE_TOTAL_OFFSET)
    count = u32le(data, TABLE_COUNT_OFFSET)
    table_size = u32le(data, TABLE_SIZE_OFFSET)
    package_end = TABLE_OFFSET + table_total
    header44 = u32be(data, HEADER_END_OFFSET)

    if count != RESOURCE_COUNT:
        raise ValueError(
            f"{path}: resource count={count}; expected {RESOURCE_COUNT}"
        )
    if table_size != RESOURCE_TABLE_SIZE:
        raise ValueError(
            f"{path}: table size=0x{table_size:X}; "
            f"expected 0x{RESOURCE_TABLE_SIZE:X}"
        )
    if wrapper_size != table_total:
        raise ValueError(f"{path}: wrapper/table size mismatch")
    if header44 + WRAPPER_OFFSET != package_end:
        raise ValueError(f"{path}: header/package size relation failed")
    if not (PAYLOAD_OFFSET < package_end <= FILE_SIZE):
        raise ValueError(f"{path}: invalid package end 0x{package_end:X}")

    ends = [
        u32le(data, TABLE_ENDS_OFFSET + index * 4)
        for index in range(RESOURCE_COUNT - 1)
    ]
    ends.append(table_total)
    boundaries = [PAYLOAD_OFFSET] + [
        TABLE_OFFSET + end for end in ends
    ]

    resources: list[Resource] = []
    for index, (width, height) in enumerate(RESOURCE_DIMENSIONS):
        start, end = boundaries[index], boundaries[index + 1]
        if not (PAYLOAD_OFFSET <= start < end <= package_end):
            raise ValueError(
                f"{path}: invalid resource {index} boundary "
                f"0x{start:X}->0x{end:X}"
            )

        compressed = data[start:end]
        try:
            raw = zlib.decompress(compressed)
        except zlib.error as exc:
            raise ValueError(
                f"{path}: resource {index} zlib failure: {exc}"
            ) from exc

        expected = resource_raw_size(width, height)
        if len(raw) != expected:
            raise ValueError(
                f"{path}: resource {index} raw size {len(raw):,}; "
                f"expected {expected:,}"
            )

        resources.append(Resource(start, end, compressed, raw))

    return Logo(
        data=data,
        size=len(data),
        sha256=sha256(data),
        wrapper_size=wrapper_size,
        table_total=table_total,
        table_size=table_size,
        package_end=package_end,
        header44=header44,
        resources=tuple(resources),
    )


def find_animation(data: bytes, package_end: int) -> Animation:
    expected_size = animation_raw_size()
    frame_size = animation_frame_size()
    candidates: list[Animation] = []

    for offset in range(package_end, len(data) - 2):
        if data[offset] != 0x78:
            continue

        cmf, flg = data[offset], data[offset + 1]
        if ((cmf << 8) | flg) % 31 != 0:
            continue

        try:
            decompressor = zlib.decompressobj()
            raw = decompressor.decompress(data[offset:], expected_size + 1)
        except zlib.error:
            continue

        if len(raw) != expected_size or not decompressor.eof:
            continue

        consumed = len(data[offset:]) - len(decompressor.unused_data)
        if consumed <= 0:
            continue

        first_frame = raw[:frame_size]
        if any(
            raw[index * frame_size:(index + 1) * frame_size] != first_frame
            for index in range(1, ANIMATION_FRAME_COUNT)
        ):
            continue

        candidates.append(
            Animation(
                start=offset,
                end=offset + consumed,
                compressed=data[offset:offset + consumed],
                raw=raw,
            )
        )

    if len(candidates) != 1:
        raise ValueError(
            f"animation search found {len(candidates)} valid candidates"
        )

    return candidates[0]


def verify(source: Path, candidate: Path) -> None:
    original = parse_logo(source)
    candidate_logo = parse_logo(candidate)
    failures: list[str] = []

    print("=" * 78)
    print("B760H LOGO INDEPENDENT VERIFIER")
    print("=" * 78)
    print(f"Source    : {source}")
    print(f"Candidate : {candidate}")
    print(f"Source SHA256    : {original.sha256}")
    print(f"Candidate SHA256 : {candidate_logo.sha256}")

    print("\n[1] Resource verification")
    changed_resources: list[int] = []

    for index, resource in enumerate(candidate_logo.resources):
        changed = resource.compressed != original.resources[index].compressed
        state = "CHANGED" if changed else "UNCHANGED"

        if changed:
            changed_resources.append(index)

        print(
            f"  resource {index}: "
            f"{len(resource.compressed):,} compressed | "
            f"{len(resource.raw):,} raw | {state}"
        )

    if len(changed_resources) != RESOURCE_COUNT:
        failures.append(
            "not all four resources changed; "
            f"changed resources: {changed_resources}"
        )

    for index in range(RESOURCE_COUNT):
        if candidate_logo.resources[index].raw == original.resources[index].raw:
            failures.append(
                f"resource {index} decompressed RGB565 data did not change"
            )

    print("\n[2] Independent animation search")
    original_animation = find_animation(
        original.data, original.package_end
    )
    candidate_animation = find_animation(
        candidate_logo.data, candidate_logo.package_end
    )

    print(
        f"  source animation    : "
        f"0x{original_animation.start:X}->0x{original_animation.end:X}"
    )
    print(
        f"  candidate animation : "
        f"0x{candidate_animation.start:X}->0x{candidate_animation.end:X}"
    )

    if (
        original_animation.compressed != candidate_animation.compressed
        or original_animation.raw != candidate_animation.raw
    ):
        failures.append("animation content changed")
    else:
        print("  animation bytes     : IDENTICAL")

    print("\n[3] Unknown region preservation")
    original_unknown = original.data[
        original.package_end:original_animation.start
    ]
    candidate_unknown = candidate_logo.data[
        candidate_logo.package_end:candidate_animation.start
    ]

    print(f"  source    : {len(original_unknown):,} bytes")
    print(f"  candidate : {len(candidate_unknown):,} bytes")

    if original_unknown != candidate_unknown:
        failures.append("unknown region changed")
    else:
        print("  unknown region      : IDENTICAL")

    print("\n[4] Tail and zero-padding")
    original_tail = original.data[original_animation.end:]
    candidate_tail_start = candidate_animation.end
    candidate_tail_end = candidate_tail_start + len(original_tail)
    candidate_tail = candidate_logo.data[
        candidate_tail_start:candidate_tail_end
    ]
    padding = candidate_logo.data[
        candidate_tail_end:
    ]

    if original_tail != candidate_tail:
        failures.append("preserved tail changed")
    else:
        print(
            f"  preserved tail      : "
            f"{len(original_tail):,} bytes | IDENTICAL"
        )

    if any(padding):
        failures.append("candidate final padding contains non-zero bytes")
    else:
        print(
            f"  final padding       : "
            f"{len(padding):,} bytes | ALL ZERO"
        )

    print("\n[5] Immutable header")
    for start, end in IMMUTABLE_HEADER_RANGES:
        if original.data[start:end] != candidate_logo.data[start:end]:
            failures.append(
                f"immutable header range changed: "
                f"0x{start:X}-0x{end:X}"
            )
        else:
            print(f"  0x{start:03X}-0x{end:03X} : IDENTICAL")

    print("\n[6] Structural equations")
    if candidate_logo.wrapper_size != candidate_logo.table_total:
        failures.append("wrapper size != table total")
    if candidate_logo.package_end != (
        TABLE_OFFSET + candidate_logo.table_total
    ):
        failures.append("package end equation failed")
    if candidate_logo.header44 + WRAPPER_OFFSET != candidate_logo.package_end:
        failures.append("header 0x44 equation failed")

    print(
        f"  0x44 + 0x60 = "
        f"0x{candidate_logo.header44 + WRAPPER_OFFSET:X}"
    )
    print(
        f"  0x260 + total = "
        f"0x{TABLE_OFFSET + candidate_logo.table_total:X}"
    )

    expected_shift = sum(
        len(original.resources[index].compressed)
        - len(candidate_logo.resources[index].compressed)
        for index in range(RESOURCE_COUNT)
    )
    actual_shift = original_animation.start - candidate_animation.start

    if expected_shift != actual_shift:
        failures.append(
            f"animation shift mismatch: "
            f"expected {expected_shift}, got {actual_shift}"
        )
    else:
        print(
            f"  animation shift   : "
            f"{actual_shift:,} bytes | CORRECT"
        )

    if failures:
        print("\nVERIFICATION FAILED")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)

    print("\n" + "=" * 78)
    print("INDEPENDENT VERIFICATION: SUCCESS")
    print("=" * 78)
    print("- all four resources structurally valid")
    print("- all four resources replaced")
    print("- animation preserved")
    print("- unknown region preserved")
    print("- tail preserved")
    print("- immutable header preserved except size fields")
    print("- fixed 3 MiB size valid")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independent forensic verifier for a B760H LOGO candidate."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()

    try:
        verify(args.source, args.candidate)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
