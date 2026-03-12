"""
Media Scanner Plugin — XtractR Forensic Platform
Scans for images, video, and audio files; extracts EXIF metadata from JPEG/TIFF.
"""
import os
import struct
import logging
from typing import List, Dict, Any, Optional
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.media_scanner")

# All extensions considered forensically relevant on Android/iOS
MEDIA_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.heif',
    '.tiff', '.tif', '.raw', '.dng',
    # Video
    '.mp4', '.mkv', '.avi', '.mov', '.3gp', '.3g2', '.webm', '.m4v',
    '.flv', '.wmv', '.ts',
    # Audio
    '.mp3', '.aac', '.m4a', '.ogg', '.opus', '.flac', '.wav', '.wma', '.amr',
}

# EXIF tag IDs to human names
_EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8769: "ExifIFD",
    0x8825: "GPSInfo",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9286: "UserComment",
    0xA420: "ImageUniqueID",
}

# EXIF GPS sub-tags
_GPS_TAGS = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x000C: "GPSSpeedRef",
    0x000D: "GPSSpeed",
    0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection",
    0x001D: "GPSDateStamp",
}


class MediaScanner(BasePlugin):
    NAME = "Media Scanner"
    VERSION = "2.0.0"
    DESCRIPTION = "Scans for Images/Videos/Audio and extracts full EXIF metadata including GPS"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        errors = []

        for root, dirs, files in vfs.walk(""):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in MEDIA_EXTENSIONS:
                    continue

                path = os.path.join(root, f)
                try:
                    stats = vfs.stat(path)
                except Exception as e:
                    logger.warning(f"[MediaScanner] stat failed for {path}: {e}")
                    errors.append(f"stat:{path}:{e}")
                    continue

                exif: Dict[str, Any] = {}
                gps: Dict[str, Any] = {}

                if ext in {'.jpg', '.jpeg'}:
                    try:
                        data = vfs.read_bytes(path, 131072)  # 128 KB for EXIF headers
                        exif, gps = self._extract_exif_full(data)
                    except Exception as e:
                        logger.warning(f"[MediaScanner] EXIF extraction failed for {path}: {e}")
                        errors.append(f"exif:{path}:{e}")

                details: Dict[str, Any] = {
                    "filename": f,
                    "extension": ext,
                    "size_bytes": stats.get("size", 0),
                    "mtime_ms": int(stats.get("mtime", 0) * 1000),
                }
                if exif:
                    details["exif"] = exif
                if gps:
                    details["gps"] = gps

                timestamp_ms = int(stats.get("mtime", 0) * 1000)

                artifacts.append(Artifact(
                    artifact_id=f"media_{abs(hash(path))}",
                    artifact_type="MEDIA",
                    source_path=path,
                    timestamp_utc=timestamp_ms,
                    parser_name=self.NAME,
                    parser_version=self.VERSION,
                    actor="DEVICE",
                    details=details,
                ))

        if errors:
            logger.info(f"[MediaScanner] Completed with {len(errors)} non-fatal errors / {len(artifacts)} artifacts found.")

        return artifacts

    # ──────────────────────────────────────────────────────────────────────────
    # EXIF parsing — full IFD walker
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_exif_full(self, data: bytes):
        """
        Parse EXIF data from JPEG bytes.
        Returns (exif_dict, gps_dict).
        """
        exif: Dict[str, Any] = {}
        gps: Dict[str, Any] = {}

        if len(data) < 4 or data[:2] != b'\xff\xd8':
            return exif, gps  # Not a JPEG

        offset = 2
        while offset < len(data) - 3:
            if data[offset] != 0xFF:
                break
            marker = data[offset + 1]
            if marker == 0xDA:  # SOS — start of scan, no more metadata
                break

            try:
                seg_len = struct.unpack_from(">H", data, offset + 2)[0]
            except struct.error:
                break

            if marker == 0xE1:  # APP1 — EXIF or XMP
                app1_data = data[offset + 4: offset + 2 + seg_len]
                if app1_data[:6] == b'Exif\x00\x00':
                    tiff_data = app1_data[6:]
                    try:
                        exif, gps = self._parse_tiff_block(tiff_data)
                    except Exception as e:
                        logger.debug(f"[MediaScanner] TIFF parse error: {e}")
                break  # Only care about the first APP1

            offset += 2 + seg_len

        return exif, gps

    def _parse_tiff_block(self, data: bytes):
        """Parse a TIFF/IFD block in EXIF APP1 data."""
        exif: Dict[str, Any] = {}
        gps: Dict[str, Any] = {}

        if len(data) < 8:
            return exif, gps

        if data[:2] == b'MM':
            endian = '>'
        elif data[:2] == b'II':
            endian = '<'
        else:
            return exif, gps

        ifd0_offset = struct.unpack_from(endian + 'I', data, 4)[0]
        self._read_ifd(data, ifd0_offset, endian, _EXIF_TAGS, exif)

        # Follow ExifIFD sub-IFD if present
        if "ExifIFD" in exif:
            try:
                exif_ifd_offset = int(exif.pop("ExifIFD"))
                sub_exif: Dict[str, Any] = {}
                self._read_ifd(data, exif_ifd_offset, endian, _EXIF_TAGS, sub_exif)
                exif.update(sub_exif)
            except (ValueError, TypeError):
                pass

        # Follow GPSInfo sub-IFD
        if "GPSInfo" in exif:
            try:
                gps_offset = int(exif.pop("GPSInfo"))
                self._read_ifd(data, gps_offset, endian, _GPS_TAGS, gps)
                # Convert rational GPS values to float where possible
                gps = self._convert_gps(gps)
            except (ValueError, TypeError):
                pass

        return exif, gps

    def _read_ifd(self, data: bytes, offset: int, endian: str,
                  tag_map: Dict[int, str], out: Dict[str, Any]):
        """Walk a single IFD and populate out dict."""
        if offset + 2 > len(data):
            return
        try:
            num_entries = struct.unpack_from(endian + 'H', data, offset)[0]
        except struct.error:
            return
        offset += 2

        for _ in range(num_entries):
            if offset + 12 > len(data):
                break
            try:
                tag, type_id, count, val_off = struct.unpack_from(endian + 'HHII', data, offset)
            except struct.error:
                offset += 12
                continue
            offset += 12

            tag_name = tag_map.get(tag)
            if tag_name is None:
                continue

            value = self._read_value(data, type_id, count, val_off, endian, offset - 12 + 8)
            if value is not None:
                out[tag_name] = value

    def _read_value(self, data: bytes, type_id: int, count: int,
                    val_off: int, endian: str, entry_pos: int) -> Optional[Any]:
        """
        Read EXIF field value.
        type_id: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL, 7=UNDEF,
                 9=SLONG, 10=SRATIONAL
        """
        _type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
        type_size = _type_sizes.get(type_id, 0)
        if type_size == 0:
            return None

        total = type_size * count
        if total <= 4:
            # Value fits inline in the offset field (stored big/little endian)
            raw = data[entry_pos: entry_pos + 4]
        else:
            # Offset points into TIFF block
            if val_off + total > len(data):
                return None
            raw = data[val_off: val_off + total]

        try:
            if type_id == 2:  # ASCII
                return raw[:count].rstrip(b'\x00').decode('latin-1', errors='replace')
            elif type_id == 3:  # SHORT
                vals = [struct.unpack_from(endian + 'H', raw, i * 2)[0] for i in range(count)]
                return vals[0] if count == 1 else vals
            elif type_id == 4:  # LONG
                vals = [struct.unpack_from(endian + 'I', raw, i * 4)[0] for i in range(count)]
                return vals[0] if count == 1 else vals
            elif type_id == 5:  # RATIONAL
                rationals = []
                for i in range(count):
                    n, d = struct.unpack_from(endian + 'II', raw, i * 8)
                    rationals.append(round(n / d, 6) if d != 0 else 0)
                return rationals[0] if count == 1 else rationals
            elif type_id == 9:  # SLONG
                vals = [struct.unpack_from(endian + 'i', raw, i * 4)[0] for i in range(count)]
                return vals[0] if count == 1 else vals
            elif type_id == 10:  # SRATIONAL
                rationals = []
                for i in range(count):
                    n, d = struct.unpack_from(endian + 'ii', raw, i * 8)
                    rationals.append(round(n / d, 6) if d != 0 else 0)
                return rationals[0] if count == 1 else rationals
            elif type_id == 1:  # BYTE
                vals = list(raw[:count])
                return vals[0] if count == 1 else vals
        except Exception:
            return None
        return None

    def _convert_gps(self, gps: Dict[str, Any]) -> Dict[str, Any]:
        """Convert GPS rationals to decimal degrees."""
        out = dict(gps)
        for coord_key, ref_key, result_key in [
            ("GPSLatitude", "GPSLatitudeRef", "latitude_decimal"),
            ("GPSLongitude", "GPSLongitudeRef", "longitude_decimal"),
        ]:
            raw = out.get(coord_key)
            ref = out.get(ref_key, "")
            if isinstance(raw, list) and len(raw) == 3:
                try:
                    decimal = raw[0] + raw[1] / 60 + raw[2] / 3600
                    if str(ref).upper() in ("S", "W"):
                        decimal = -decimal
                    out[result_key] = round(decimal, 6)
                except (TypeError, ZeroDivisionError):
                    pass
        return out
