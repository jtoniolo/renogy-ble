"""Ground-truth BLE probe for Renogy RNGRBP "BT Battery Pro" packs.

The renogy-ha integration creates the battery entities but every read fails
with `GATT Protocol Error: Unlikely Error` (ATT 0x0E). This probe answers, in
ONE run on the HA host, exactly why:

  1. Dumps the battery's full GATT table (services, chars, PROPERTIES) so we can
     see which characteristic actually notifies and which accepts writes.
  2. Subscribes to notifications on every notify-capable char in service fff0.
  3. Sends the device-info read (0x13F0 x 0x1C) trying every combination of
     {write char} x {write-with-response, write-without-response} x {device addr}
     and prints the raw response for each — so we learn the transport (write
     type / char) AND the Modbus slave address in a single pass.

Read-only (Modbus function 0x03). Run where Bluetooth can reach the battery:
    python scripts/battery_probe.py [BLE_MAC_or_NAME]

Default target is the first advertised RNGRBP* device. Pass a MAC (e.g.
4C:E1:74:4A:7A:9A) or name to override.

IMPORTANT: disable the two battery config entries in Home Assistant (or stop
the renogy integration) before running, so the integration's 60 s poll does not
fight this probe for the single BLE connection.
"""

import asyncio
import sys

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Classic Renogy BT-1/BT-2 GATT layout (what the library + DC Home app use).
NOTIFY_SERVICE = "0000fff0-0000-1000-8000-00805f9b34fb"
WRITE_SERVICE = "0000ffd0-0000-1000-8000-00805f9b34fb"
CHAR_FFF1 = "0000fff1-0000-1000-8000-00805f9b34fb"  # library notify/read char
CHAR_FFF2 = "0000fff2-0000-1000-8000-00805f9b34fb"  # app RNGPMS notify char
CHAR_FFD1 = "0000ffd1-0000-1000-8000-00805f9b34fb"  # library + app write char

# device_info read: func 0x03, reg 0x13F0, count 0x1C (28). Matches the DC Home
# app tag "battery_read_5104_5131_data" = 0313F0001C.
READ_FUNC = 0x03
INFO_REG = 0x13F0
INFO_COUNT = 0x1C

# Modbus slave-address candidates. Library "pro" path uses 0xFF; classic Renogy
# smart batteries answer at 0x30; the app reads the address from pairing data.
ADDR_CANDIDATES = [0xFF, 0x30, 0x01, 0x02, 0x48, 0xF7]

_notifications: list[bytes] = []


def modbus_crc(frame: bytes) -> bytes:
    crc = 0xFFFF
    for b in frame:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])  # low, high


def build_read(addr: int, reg: int, count: int) -> bytes:
    body = bytes([addr, READ_FUNC]) + reg.to_bytes(2, "big") + count.to_bytes(2, "big")
    return body + modbus_crc(body)


def notify_handler(_char, data: bytearray) -> None:
    _notifications.append(bytes(data))
    print(f"    <-- notify {len(data)}B: {data.hex()}")


async def find_target(arg: str | None):
    print("Scanning 8 s for Renogy batteries (RNGRBP*)...")
    devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
    hits = []
    for dev, adv in devices.values():
        name = adv.local_name or dev.name or ""
        mfg = adv.manufacturer_data
        if arg:
            if arg.upper() in (dev.address.upper(), name.upper()):
                return dev, name, mfg
        elif name.startswith("RNGRBP") or 0xE14C in mfg:
            hits.append((dev, name, mfg))
    if arg:
        print(f"  target {arg} not found in scan")
        return None
    for dev, name, mfg in hits:
        print(f"  found {dev.address}  name={name!r}  mfg_ids={list(mfg)}")
    return hits[0] if hits else None


def dump_gatt(client: BleakClient):
    print("\n=== GATT TABLE ===")
    for service in client.services:
        print(f"service {service.uuid}")
        for ch in service.characteristics:
            print(f"    char {ch.uuid}  props={ch.properties}")


def _resolve_handles(client: BleakClient):
    """Resolve notify/write handles by (service, char, property) — the disambiguation
    the library's _resolve_battery_characteristics performs, so duplicate UUIDs in the
    vendor d0ff service can't shadow the real chars."""
    notify_handle = write_handle = None
    for service in client.services:
        su = service.uuid.lower()
        for ch in service.characteristics:
            cu = ch.uuid.lower()
            props = set(ch.properties)
            if su == NOTIFY_SERVICE and cu == CHAR_FFF1 and "notify" in props:
                notify_handle = ch.handle
            if (
                su == WRITE_SERVICE
                and cu == CHAR_FFD1
                and props & {"write", "write-without-response"}
            ):
                write_handle = ch.handle
    return notify_handle, write_handle


# All four reads the DC Home app issues for a single battery.
BAT_READS = {
    "device_info(0x13F0x1C)": (INFO_REG, INFO_COUNT),
    "pack_status(0x13B2x6)": (0x13B2, 0x06),
    "cell_status(0x1388x22)": (0x1388, 0x22),
    "extra(0x146Cx9)": (0x146C, 0x09),
}


async def try_reads(client: BleakClient):
    notify_handle, write_handle = _resolve_handles(client)
    print(f"\nresolved notify_handle={notify_handle}  write_handle={write_handle}")
    if notify_handle is None or write_handle is None:
        print("  could not resolve handles — aborting read test")
        return

    await client.start_notify(notify_handle, notify_handler)
    print(f"  subscribed to notify handle {notify_handle}")

    # First find the responding device address using the info read, trying both
    # write types.
    good_addr = None
    good_response = None
    for response in (True, False):
        for addr in ADDR_CANDIDATES:
            _notifications.clear()
            frame = build_read(addr, INFO_REG, INFO_COUNT)
            print(
                f"\n--> handle-write {'RESP' if response else 'NORESP'} "
                f"addr=0x{addr:02X}: {frame.hex()}"
            )
            try:
                await client.write_gatt_char(write_handle, frame, response=response)
            except BleakError as exc:
                print(f"    WRITE REJECTED: {exc!r}")
                continue
            await asyncio.sleep(1.0)
            if not _notifications:
                print("    (no notification)")
                continue
            joined = b"".join(_notifications)
            if len(joined) >= 3 and joined[1] == 0x83:
                print(f"    MODBUS EXCEPTION code 0x{joined[2]:02X}")
            elif len(joined) >= 5 and joined[1] == 0x03:
                print(f"    *** VALID *** addr=0x{joined[0]:02X} nbytes={joined[2]}")
                good_addr, good_response = addr, response
                break
        if good_addr is not None:
            break

    if good_addr is None:
        print("\nNo address responded with valid data.")
        return

    print(
        f"\n=== FULL READ at addr=0x{good_addr:02X} "
        f"({'RESP' if good_response else 'NORESP'}) ==="
    )
    for label, (reg, count) in BAT_READS.items():
        _notifications.clear()
        frame = build_read(good_addr, reg, count)
        await client.write_gatt_char(write_handle, frame, response=good_response)
        await asyncio.sleep(1.0)
        joined = b"".join(_notifications)
        print(f"\n{label}: {frame.hex()}")
        print(f"  raw: {joined.hex()}")
        if len(joined) >= 5 and joined[1] == 0x03:
            n = joined[2]
            payload = joined[3 : 3 + n]
            words = [
                int.from_bytes(payload[i : i + 2], "big")
                for i in range(0, len(payload) - 1, 2)
            ]
            print(f"  16-bit regs: {words}")


async def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    target = await find_target(arg)
    if not target:
        print("No battery found.")
        return
    dev, name, mfg = target
    print(f"\nConnecting to {dev.address}  name={name!r}  mfg_ids={list(mfg)}")
    try:
        async with BleakClient(dev) as client:
            print(f"connected={client.is_connected}")
            dump_gatt(client)
            await try_reads(client)
    except Exception as exc:  # noqa: BLE001
        print(f"CONNECTION/PROBE ERROR: {exc!r}")


if __name__ == "__main__":
    asyncio.run(main())
