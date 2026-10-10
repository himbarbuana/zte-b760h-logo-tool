#!/usr/bin/env python3
"""
B760H LOGO Tool

A conservative command-line utility for inspecting, unpacking, verifying,
and repacking the ZTE/MediaTek B760H LOGO resource container.

All operations are English-only and designed around a read-only golden master.
The original master file is never modified by this tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MAGIC = bytes.fromhex("55 66 77 88")
WRAPPER_MAGIC = bytes.fromhex("88 16 88 58")
RESOURCE_NAME = b"LOGO"

FILE_SIZE = 0x300000
TABLE_OFFSET = 0x260
PAYLOAD_OFFSET = 0x278
HEADER_END_OFFSET = 0x44
WRAPPER_SIZE_OFFSET = 0x64
TABLE_COUNT_OFFSET = 0x260
TABLE_TOTAL_OFFSET = 0x264
TABLE_SIZE_OFFSET = 0x268
TABLE_ENDS_OFFSET = 0x26C
WRAPPER_OFFSET = 0x60
RESOURCE_COUNT = 4
RESOURCE_TABLE_SIZE = 0x18
SIZE_FIELD_END = 0x278
HEADER_PROTECTED_RANGES = ((0x00, 0x44), (0x48, 0x64), (0x68, 0x260))

RESOURCE_DIMENSIONS = ((720, 480), (720, 576), (1280, 720), (1920, 1080))
RGB565_BYTES_PER_PIXEL = 2
RGB888_BYTES_PER_PIXEL = 3
ANIMATION_FRAME_COUNT = 35
ANIMATION_DIMENSIONS = (1920, 1080)
ZLIB_LEVEL = 9


@dataclass(frozen=True)
class Resource:
    index: int
    width: int
    height: int
    start: int
    end: int
    compressed_size: int
    raw_size: int
    compressed_sha256: str
    raw_sha256: str


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    size: int
    sha256: str


@dataclass(frozen=True)
class Animation:
    start: int
    end: int
    compressed_size: int
    raw_size: int
    sha256: str


@dataclass(frozen=True)
class LogoMetadata:
    file_size: int
    sha256: str
    wrapper_size: int
    table_count: int
    table_size: int
    table_total: int
    package_end: int
    header_0x44_be: int
    resources: tuple[Resource, ...]
    animation: Animation
    unknown: Region
    tail: Region


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def p32le(value: int) -> bytes:
    return struct.pack("<I", value)


def p32be(value: int) -> bytes:
    return struct.pack(">I", value)


def resource_raw_size(width: int, height: int) -> int:
    return width * height * RGB565_BYTES_PER_PIXEL


def animation_frame_size() -> int:
    width, height = ANIMATION_DIMENSIONS
    return resource_raw_size(width, height)


def animation_raw_size() -> int:
    return ANIMATION_FRAME_COUNT * animation_frame_size()


def locate_animation(data: bytes, package_end: int) -> tuple[int, int, int]:
    """Locate the unique 35-frame 1920x1080 RGB565 zlib animation."""
    frame_size = animation_frame_size()
    expected_size = animation_raw_size()
    candidates: list[tuple[int, int]] = []

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

        candidates.append((offset, offset + consumed))

    if len(candidates) != 1:
        raise ValueError(
            f"Animation search found {len(candidates)} valid candidates"
        )

    start, end = candidates[0]
    return start, end, expected_size


def parse_logo(path: Path) -> tuple[bytes, LogoMetadata]:
    data = path.read_bytes()

    if len(data) < PAYLOAD_OFFSET:
        raise ValueError("LOGO file is too small")
    if data[0:4] != MAGIC:
        raise ValueError("Invalid LOGO magic at offset 0x00")
    if data[WRAPPER_OFFSET:WRAPPER_OFFSET + 4] != WRAPPER_MAGIC:
        raise ValueError("Invalid LOGO wrapper magic at offset 0x60")
    if data[0x68:0x6C] != RESOURCE_NAME:
        raise ValueError("LOGO wrapper name is not LOGO")

    wrapper_size = u32le(data, WRAPPER_SIZE_OFFSET)
    table_total = u32le(data, TABLE_TOTAL_OFFSET)
    table_count = u32le(data, TABLE_COUNT_OFFSET)
    table_size = u32le(data, TABLE_SIZE_OFFSET)
    package_end = TABLE_OFFSET + table_total
    header_end_be = u32be(data, HEADER_END_OFFSET)

    if table_count != RESOURCE_COUNT:
        raise ValueError(f"Expected {RESOURCE_COUNT} resources, found {table_count}")
    if table_size != RESOURCE_TABLE_SIZE:
        raise ValueError(
            f"Expected {RESOURCE_TABLE_SIZE}-byte resource table, found {table_size}"
        )
    if package_end > len(data):
        raise ValueError("Package end exceeds file size")
    if wrapper_size != table_total:
        raise ValueError("Wrapper size and table total differ")
    if header_end_be + WRAPPER_OFFSET != package_end:
        raise ValueError("Header BE32 size relation is invalid")

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
                f"Invalid resource {index} boundary 0x{start:X}->0x{end:X}"
            )

        compressed = data[start:end]
        try:
            raw = zlib.decompress(compressed)
        except zlib.error as exc:
            raise ValueError(f"Resource {index} zlib failure: {exc}") from exc

        expected = resource_raw_size(width, height)
        if len(raw) != expected:
            raise ValueError(
                f"Resource {index} decompressed to {len(raw)} bytes; "
                f"expected {expected}"
            )

        resources.append(
            Resource(
                index=index,
                width=width,
                height=height,
                start=start,
                end=end,
                compressed_size=len(compressed),
                raw_size=len(raw),
                compressed_sha256=sha256_bytes(compressed),
                raw_sha256=sha256_bytes(raw),
            )
        )

    animation_start, animation_end, animation_raw = locate_animation(
        data, package_end
    )
    unknown = data[package_end:animation_start]
    tail = data[animation_end:]

    metadata = LogoMetadata(
        file_size=len(data),
        sha256=sha256_bytes(data),
        wrapper_size=wrapper_size,
        table_count=table_count,
        table_size=table_size,
        table_total=table_total,
        package_end=package_end,
        header_0x44_be=header_end_be,
        resources=tuple(resources),
        animation=Animation(
            start=animation_start,
            end=animation_end,
            compressed_size=animation_end - animation_start,
            raw_size=animation_raw,
            sha256=sha256_bytes(data[animation_start:animation_end]),
        ),
        unknown=Region(
            start=package_end,
            end=animation_start,
            size=animation_start - package_end,
            sha256=sha256_bytes(unknown),
        ),
        tail=Region(
            start=animation_end,
            end=len(data),
            size=len(tail),
            sha256=sha256_bytes(tail),
        ),
    )
    return data, metadata


def rgb565_to_rgb888(raw: bytes, width: int, height: int) -> bytes:
    expected = resource_raw_size(width, height)
    if len(raw) != expected:
        raise ValueError("RGB565 buffer size does not match dimensions")

    pixel_count = width * height
    output = bytearray(pixel_count * RGB888_BYTES_PER_PIXEL)

    for index in range(pixel_count):
        pixel = raw[index * 2] | (raw[index * 2 + 1] << 8)
        red = (pixel >> 11) & 0x1F
        green = (pixel >> 5) & 0x3F
        blue = pixel & 0x1F
        output[index * 3] = (red << 3) | (red >> 2)
        output[index * 3 + 1] = (green << 2) | (green >> 4)
        output[index * 3 + 2] = (blue << 3) | (blue >> 2)

    return bytes(output)


def rgb888_to_rgb565(rgb: bytes, width: int, height: int) -> bytes:
    expected = width * height * RGB888_BYTES_PER_PIXEL
    if len(rgb) != expected:
        raise ValueError("RGB888 buffer size does not match dimensions")

    pixel_count = width * height
    output = bytearray(pixel_count * RGB565_BYTES_PER_PIXEL)

    for index in range(pixel_count):
        red = rgb[index * 3]
        green = rgb[index * 3 + 1]
        blue = rgb[index * 3 + 2]
        pixel = ((red >> 3) << 11) | ((green >> 2) << 5) | (blue >> 3)
        output[index * 2] = pixel & 0xFF
        output[index * 2 + 1] = (pixel >> 8) & 0xFF

    return bytes(output)


def require_pillow():
    try:
        from PIL import Image
        return Image
    except ImportError as exc:
        raise RuntimeError(
            "Pillow is required. Install it with the virtual-environment "
            "instructions in README.md."
        ) from exc


def unpack(path: Path, output_dir: Path) -> None:
    data, metadata = parse_logo(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    images_dir = output_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    Image = require_pillow()

    for resource in metadata.resources:
        compressed = data[resource.start:resource.end]
        raw = zlib.decompress(compressed)
        resource_dir = output_dir / f"resource_{resource.index}"
        resource_dir.mkdir(parents=True, exist_ok=True)
        (resource_dir / "resource.zlib").write_bytes(compressed)
        (resource_dir / "resource.rgb565").write_bytes(raw)

        rgb = rgb565_to_rgb888(raw, resource.width, resource.height)
        Image.frombytes(
            "RGB", (resource.width, resource.height), rgb
        ).save(
            images_dir / f"resource_{resource.index}.png",
            optimize=False,
        )

    animation = metadata.animation
    (output_dir / "animation.zlib").write_bytes(
        data[animation.start:animation.end]
    )
    (output_dir / "unknown.bin").write_bytes(
        data[metadata.unknown.start:metadata.unknown.end]
    )
    (output_dir / "tail.bin").write_bytes(data[metadata.tail.start:])
    (output_dir / "original_header.bin").write_bytes(data[:PAYLOAD_OFFSET])
    (output_dir / "metadata.json").write_text(
        json.dumps(metadata_to_dict(metadata), indent=2) + "\n"
    )

    print("Unpack completed successfully.")
    print(f"Source : {path}")
    print(f"Output : {output_dir}")
    print(f"Images : {images_dir}")


def metadata_to_dict(metadata: LogoMetadata) -> dict[str, Any]:
    return {
        "file_size": metadata.file_size,
        "sha256": metadata.sha256,
        "wrapper_size": metadata.wrapper_size,
        "table_count": metadata.table_count,
        "table_size": metadata.table_size,
        "table_total": metadata.table_total,
        "package_end": metadata.package_end,
        "header_0x44_be": metadata.header_0x44_be,
        "resources": [
            {
                "index": r.index,
                "width": r.width,
                "height": r.height,
                "start": r.start,
                "end": r.end,
                "compressed_size": r.compressed_size,
                "raw_size": r.raw_size,
                "compressed_sha256": r.compressed_sha256,
                "raw_sha256": r.raw_sha256,
            }
            for r in metadata.resources
        ],
        "animation": {
            "start": metadata.animation.start,
            "end": metadata.animation.end,
            "compressed_size": metadata.animation.compressed_size,
            "raw_size": metadata.animation.raw_size,
            "sha256": metadata.animation.sha256,
        },
        "unknown": {
            "start": metadata.unknown.start,
            "end": metadata.unknown.end,
            "size": metadata.unknown.size,
            "sha256": metadata.unknown.sha256,
        },
        "tail": {
            "start": metadata.tail.start,
            "size": metadata.tail.size,
            "sha256": metadata.tail.sha256,
        },
    }


def fit_artwork(source_img, width: int, height: int, Image):
    src_width, src_height = source_img.size
    scale = min(width / src_width, height / src_height)
    fit_width = max(1, round(src_width * scale))
    fit_height = max(1, round(src_height * scale))

    fitted = source_img.resize(
        (fit_width, fit_height),
        Image.Resampling.LANCZOS,
    )
    canvas = Image.new("RGB", (width, height), (0, 0, 0))
    x = (width - fit_width) // 2
    y = (height - fit_height) // 2
    canvas.paste(fitted, (x, y))
    return canvas


def encode_resource(source_img, width: int, height: int, Image) -> tuple[bytes, Any]:
    canvas = fit_artwork(source_img, width, height, Image)
    raw = rgb888_to_rgb565(canvas.tobytes(), width, height)
    compressed = zlib.compress(raw, level=ZLIB_LEVEL)
    return compressed, canvas


def build_resources(source_img, Image) -> tuple[list[bytes], list[Any]]:
    resources: list[bytes] = []
    previews: list[Any] = []

    for width, height in RESOURCE_DIMENSIONS:
        compressed, canvas = encode_resource(source_img, width, height, Image)
        resources.append(compressed)
        previews.append(canvas)

    return resources, previews


def rebuild_container(
    original_data: bytes,
    metadata: LogoMetadata,
    resources: Sequence[bytes],
) -> bytes:
    payload = b"".join(resources)
    boundaries = [PAYLOAD_OFFSET]
    cursor = PAYLOAD_OFFSET

    for resource in resources:
        cursor += len(resource)
        boundaries.append(cursor)

    unknown = original_data[metadata.unknown.start:metadata.unknown.end]
    animation = original_data[metadata.animation.start:metadata.animation.end]
    tail = original_data[metadata.tail.start:]

    new_package_end = boundaries[-1]
    new_table_total = new_package_end - TABLE_OFFSET
    new_header_44 = new_package_end - WRAPPER_OFFSET

    output = bytearray()
    output.extend(original_data[:PAYLOAD_OFFSET])
    output.extend(payload)
    output.extend(unknown)
    output.extend(animation)
    output.extend(tail)

    output[WRAPPER_SIZE_OFFSET:WRAPPER_SIZE_OFFSET + 4] = p32le(new_table_total)
    output[TABLE_TOTAL_OFFSET:TABLE_TOTAL_OFFSET + 4] = p32le(new_table_total)

    for index in range(RESOURCE_COUNT - 1):
        offset = TABLE_ENDS_OFFSET + index * 4
        output[offset:offset + 4] = p32le(
            boundaries[index + 1] - TABLE_OFFSET
        )

    output[HEADER_END_OFFSET:HEADER_END_OFFSET + 4] = p32be(new_header_44)

    if len(output) > FILE_SIZE:
        raise ValueError(
            f"Packed output exceeds fixed LOGO size: {len(output):,} bytes"
        )

    output.extend(b"\x00" * (FILE_SIZE - len(output)))
    return bytes(output)


def write_previews(preview_dir: Path, previews: Sequence[Any]) -> list[Path]:
    preview_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []

    for index, ((width, height), image) in enumerate(
        zip(RESOURCE_DIMENSIONS, previews)
    ):
        path = preview_dir / f"generated_resource_{index}_{width}x{height}.png"
        image.save(path, "PNG", optimize=False)
        paths.append(path)

    return paths


def build_from_png(
    original: Path,
    png: Path,
    output: Path,
    preview_dir: Path | None = None,
) -> None:
    """Build a candidate LOGO replacing all four boot-logo resources."""
    original_data, metadata = parse_logo(original)
    Image = require_pillow()
    source_image = Image.open(png).convert("RGB")

    resources, previews = build_resources(source_image, Image)
    preview_paths = (
        write_previews(preview_dir, previews)
        if preview_dir is not None
        else []
    )
    packed = rebuild_container(original_data, metadata, resources)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)

    print("Pack completed successfully.")
    print(f"Source master : {original}")
    print(f"Artwork       : {png}")

    for index, ((width, height), resource) in enumerate(
        zip(RESOURCE_DIMENSIONS, resources)
    ):
        preview = preview_paths[index] if preview_paths else "not written"
        print(
            f"Resource {index}   : {width}x{height} | "
            f"zlib={len(resource):,} bytes | preview={preview}"
        )

    print(f"Output        : {output}")
    print(f"Output size   : {len(packed):,} bytes")
    print(f"Output SHA256 : {sha256_bytes(packed)}")


def compare_protected_ranges(
    original_data: bytes,
    candidate_data: bytes,
    failures: list[str],
) -> None:
    for start, end in HEADER_PROTECTED_RANGES:
        if original_data[start:end] != candidate_data[start:end]:
            failures.append(
                f"immutable header range changed: 0x{start:X}-0x{end:X}"
            )


def verify(original: Path, candidate: Path) -> None:
    original_data, original_meta = parse_logo(original)
    candidate_data, candidate_meta = parse_logo(candidate)
    failures: list[str] = []

    if len(candidate_data) != FILE_SIZE:
        failures.append(
            f"candidate size is {len(candidate_data):,}, expected {FILE_SIZE:,}"
        )

    if candidate_meta.wrapper_size != candidate_meta.table_total:
        failures.append("wrapper/table size mismatch")

    if candidate_meta.package_end != (
        TABLE_OFFSET + candidate_meta.table_total
    ):
        failures.append("candidate package-end equation failed")

    if candidate_meta.header_0x44_be + WRAPPER_OFFSET != candidate_meta.package_end:
        failures.append("candidate header 0x44 size equation failed")

    print("RESOURCE VERIFICATION")
    print("-" * 72)

    for index, (expected_width, expected_height) in enumerate(
        RESOURCE_DIMENSIONS
    ):
        resource = candidate_meta.resources[index]
        if (resource.width, resource.height) != (
            expected_width, expected_height
        ):
            failures.append(
                f"resource {index} dimensions are "
                f"{resource.width}x{resource.height}, "
                f"expected {expected_width}x{expected_height}"
            )

        compressed = candidate_data[resource.start:resource.end]
        try:
            raw = zlib.decompress(compressed)
        except zlib.error as exc:
            failures.append(f"resource {index} zlib decompression failed: {exc}")
            continue

        expected_raw_size = resource_raw_size(expected_width, expected_height)
        if len(raw) != expected_raw_size:
            failures.append(
                f"resource {index} raw size is {len(raw):,}, "
                f"expected {expected_raw_size:,}"
            )

        original_resource = original_meta.resources[index]
        original_blob = original_data[
            original_resource.start:original_resource.end
        ]
        status = "CHANGED" if compressed != original_blob else "UNCHANGED"
        print(
            f"Resource {index}   : {expected_width}x{expected_height} | "
            f"zlib={len(compressed):,} | raw={len(raw):,} | {status}"
        )

    original_unknown = original_data[
        original_meta.unknown.start:original_meta.unknown.end
    ]
    candidate_unknown = candidate_data[
        candidate_meta.unknown.start:candidate_meta.unknown.end
    ]
    if candidate_unknown != original_unknown:
        failures.append("unknown region content changed")
    elif len(candidate_unknown) != len(original_unknown):
        failures.append("unknown region size changed")
    else:
        print(f"Unknown region : {len(candidate_unknown):,} bytes | IDENTICAL")

    original_animation = original_data[
        original_meta.animation.start:original_meta.animation.end
    ]
    candidate_animation = candidate_data[
        candidate_meta.animation.start:candidate_meta.animation.end
    ]
    if candidate_animation != original_animation:
        failures.append("animation content changed")
    elif len(candidate_animation) != len(original_animation):
        failures.append("animation size changed")
    else:
        print(
            f"Animation      : {len(candidate_animation):,} bytes | IDENTICAL"
        )

    original_tail = original_data[original_meta.tail.start:]
    candidate_tail_start = candidate_meta.tail.start
    candidate_tail_end = candidate_tail_start + len(original_tail)

    if candidate_tail_end > len(candidate_data):
        failures.append("candidate tail extends beyond file")
    else:
        candidate_tail = candidate_data[
            candidate_tail_start:candidate_tail_end
        ]
        if candidate_tail != original_tail:
            failures.append("preserved tail content changed")
        else:
            print(f"Tail           : {len(candidate_tail):,} bytes | IDENTICAL")

    compare_protected_ranges(original_data, candidate_data, failures)

    expected_table_total = candidate_meta.package_end - TABLE_OFFSET
    expected_header_44 = candidate_meta.package_end - WRAPPER_OFFSET
    if candidate_meta.table_total != expected_table_total:
        failures.append("candidate table total is incorrect")
    if candidate_meta.header_0x44_be != expected_header_44:
        failures.append("candidate header 0x44 is incorrect")

    tail_end = candidate_meta.tail.start + len(original_tail)
    if tail_end > len(candidate_data):
        failures.append("candidate tail extends beyond file")
    else:
        padding = candidate_data[tail_end:]
        if any(padding):
            failures.append(
                f"non-zero bytes found in final padding: {len(padding):,} bytes"
            )
        else:
            print(f"Final padding  : {len(padding):,} bytes | ALL ZERO")

    if failures:
        print()
        print("VERIFICATION FAILED")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)

    print()
    print("VERIFICATION SUCCESSFUL")
    print("=" * 72)
    print(f"Source SHA256   : {sha256_bytes(original_data)}")
    print(f"Candidate SHA256: {sha256_bytes(candidate_data)}")
    print("All 4 resources : valid and independently decompressed")
    print("Unknown region  : preserved")
    print("Animation       : preserved")
    print("Tail            : preserved")
    print("Protected header: preserved except required size fields")
    print("Fixed 3 MiB size: valid")


def info(path: Path) -> None:
    _, metadata = parse_logo(path)
    print("B760H LOGO INFORMATION")
    print("=" * 72)
    print(f"File       : {path}")
    print(f"Size       : {metadata.file_size:,} bytes")
    print(f"SHA256     : {metadata.sha256}")
    print(f"Wrapper    : 0x{metadata.wrapper_size:X}")
    print(f"Table total: 0x{metadata.table_total:X}")
    print(f"Package end: 0x{metadata.package_end:X}")
    print(f"Header 0x44: 0x{metadata.header_0x44_be:X} (BE32)")
    print()

    for resource in metadata.resources:
        print(
            f"Resource {resource.index}: "
            f"{resource.width}x{resource.height} | "
            f"0x{resource.start:X}->0x{resource.end:X} | "
            f"zlib={resource.compressed_size:,} | raw={resource.raw_size:,}"
        )

    animation = metadata.animation
    print(
        f"Animation : 0x{animation.start:X}->0x{animation.end:X} | "
        f"compressed={animation.compressed_size:,} | raw={animation.raw_size:,}"
    )
    print(
        f"Unknown   : 0x{metadata.unknown.start:X}->"
        f"0x{metadata.unknown.end:X} | {metadata.unknown.size:,} bytes"
    )
    print(
        f"Tail      : 0x{metadata.tail.start:X}->EOF | "
        f"{metadata.tail.size:,} bytes"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="B760H LOGO container tool; source files are never modified."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="Inspect a LOGO file")
    info_parser.add_argument("file", type=Path)

    unpack_parser = subparsers.add_parser(
        "unpack",
        help="Unpack a LOGO file into an explicit output directory",
    )
    unpack_parser.add_argument("file", type=Path)
    unpack_parser.add_argument("--output", type=Path, required=True)

    pack_parser = subparsers.add_parser(
        "pack",
        help="Pack a new LOGO using one artwork for all four resources",
    )
    pack_parser.add_argument("--source", type=Path, required=True)
    pack_parser.add_argument("--image", type=Path, required=True)
    pack_parser.add_argument("--output", type=Path, required=True)
    pack_parser.add_argument(
        "--preview-dir",
        type=Path,
        help="Optional directory for generated resource PNG previews",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a candidate against a supplied source",
    )
    verify_parser.add_argument("--source", type=Path, required=True)
    verify_parser.add_argument("--candidate", type=Path, required=True)

    args = parser.parse_args()

    try:
        if args.command == "info":
            info(args.file)
        elif args.command == "unpack":
            unpack(args.file, args.output)
        elif args.command == "pack":
            build_from_png(args.source, args.image, args.output, args.preview_dir)
        elif args.command == "verify":
            verify(args.source, args.candidate)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
