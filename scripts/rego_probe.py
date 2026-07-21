"""One-shot read probe for the REGO 3000 thing-model registers.

Read-only (Modbus function 0x03). Prints the raw response for each register
and every candidate decode so the wire encoding can be confirmed by eye.
Run where Bluetooth can reach the inverter:  python scripts/rego_probe.py
"""

import asyncio
import struct

from bleak import BleakClient, BleakScanner

BLE_NAME = "BTRIC130000029"
WRITE_UUID = "0000ffd1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
INIT_CHAR_UUID = "0000ffd4-0000-1000-8000-00805f9b34fb"
DEVICE_IDS = [0x20, 0xFF]  # try 0x20 first, 0xFF as fallback
READS = [
    ("control_4327_known_good", 4327, 7),  # positive control: proves transport
    ("ac_input", 0x5B01, 9),
    ("ac_output", 0x5C01, 14),
    ("battery_input", 0x5D01, 11),
]


def modbus_crc(frame: bytes) -> bytes:
    crc = 0xFFFF
    for b in frame:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])  # low, high


def build_read(device_id: int, register: int, count: int) -> bytes:
    body = (
        bytes([device_id, 0x03])
        + register.to_bytes(2, "big")
        + count.to_bytes(2, "big")
    )
    return body + modbus_crc(body)


def decode(name: str, register: int, count: int, resp: bytes) -> bool:
    print(f"\n=== {name} (reg 0x{register:04X}, requested {count} regs) ===")
    print("raw:", resp.hex())
    if len(resp) >= 3 and resp[1] == 0x83:
        print(
            f"  MODBUS EXCEPTION from device 0x{resp[0]:02X}: "
            f"code 0x{resp[2]:02X}"
            + (
                " (Illegal Data Address — register does not exist)"
                if resp[2] == 0x02
                else ""
            )
        )
        return False
    if len(resp) < 5 or resp[1] != 0x03:
        print("  (no valid 0x03 response)")
        return False
    n = resp[2]
    payload = resp[3 : 3 + n]
    words = [
        int.from_bytes(payload[i : i + 2], "big") for i in range(0, len(payload), 2)
    ]
    print("  16-bit regs:", [f"{w}" for w in words])
    for k in range(0, len(words) - 1):
        be = (words[k] << 16) | words[k + 1]  # high-word-first
        le = (words[k + 1] << 16) | words[k]  # low-word-first
        s_be = struct.unpack(">i", be.to_bytes(4, "big"))[0]
        print(
            f"  32-bit @reg{k}: hi-first u={be} "
            f"(x0.1={be * 0.1:.2f} x0.01={be * 0.01:.3f}) "
            f"hi-first s={s_be} | lo-first u={le}"
        )
    return True


async def main() -> None:
    dev = await BleakScanner.find_device_by_filter(
        lambda d, ad: (d.name or ad.local_name or "") == BLE_NAME, timeout=20.0
    )
    if dev is None:
        print(f"device {BLE_NAME} not found in range")
        return
    async with BleakClient(dev) as client:
        got = {}

        def on_notify(_char, data: bytearray) -> None:
            got["resp"] = bytes(data)
            got["evt"].set()

        await client.start_notify(NOTIFY_UUID, on_notify)
        await asyncio.sleep(1.0)
        try:
            await client.read_gatt_char(INIT_CHAR_UUID)
        except Exception as exc:  # noqa: BLE001
            print(f"init read of {INIT_CHAR_UUID} failed (continuing): {exc}")
        for device_id in DEVICE_IDS:
            print(f"\n########## device_id 0x{device_id:02X} ##########")
            any_ok = False
            for name, register, count in READS:
                got["evt"] = asyncio.Event()
                got.pop("resp", None)
                request = build_read(device_id, register, count)
                await client.write_gatt_char(WRITE_UUID, request, response=False)
                try:
                    await asyncio.wait_for(got["evt"].wait(), timeout=8.0)
                except asyncio.TimeoutError:
                    print(f"\n=== {name} (reg 0x{register:04X}) === TIMEOUT")
                    continue
                if decode(name, register, count, got["resp"]):
                    any_ok = True
                await asyncio.sleep(1.0)
            if any_ok:
                break  # this device_id works; stop
        await client.stop_notify(NOTIFY_UUID)


if __name__ == "__main__":
    asyncio.run(main())
