"""Confirm REGO 3000 setting read-back and prove a safe write.

Reads the inverter config registers (function 0x03), prints each as raw x0.1,
then performs a zero-net-change write: reads AC input current limit (0x1168),
writes the SAME value back (function 0x06, value already raw), and confirms the
read-back is unchanged. Run where Bluetooth reaches the inverter.
"""

import asyncio

from bleak import BleakClient, BleakScanner

BLE_NAME = "BTRIC130000029"
WRITE_UUID = "0000ffd1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
INIT_CHAR_UUID = "0000ffd4-0000-1000-8000-00805f9b34fb"  # prime with read + 1s delay
DEVICE_ID = 0x20
SETPOINTS = {  # register: (label, unit)
    0x1168: ("AC input current limit", "A"),
    0x1146: ("charge current", "A"),
    0x1149: ("boost charge voltage", "V"),
    0x114B: ("float charge voltage", "V"),
    0x114E: ("low-voltage warn", "V"),
    0x1164: ("battery over-voltage", "V"),
}


def modbus_crc(frame: bytes) -> bytes:
    crc = 0xFFFF
    for b in frame:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def build_read(register: int, count: int) -> bytes:
    body = (
        bytes([DEVICE_ID, 0x03])
        + register.to_bytes(2, "big")
        + count.to_bytes(2, "big")
    )
    return body + modbus_crc(body)


def build_write(register: int, raw: int) -> bytes:
    body = (
        bytes([DEVICE_ID, 0x06]) + register.to_bytes(2, "big") + raw.to_bytes(2, "big")
    )
    return body + modbus_crc(body)


async def txn(client, got, frame, timeout=8.0):
    got["evt"] = asyncio.Event()
    got.pop("resp", None)
    await client.write_gatt_char(WRITE_UUID, frame, response=False)
    try:
        await asyncio.wait_for(got["evt"].wait(), timeout=timeout)
    except asyncio.TimeoutError:
        return None
    return got.get("resp")


def read_reg(resp):
    if not resp or len(resp) < 5 or resp[1] != 0x03:
        return None
    return int.from_bytes(resp[3:5], "big")  # first 16-bit register


async def main() -> None:
    dev = await BleakScanner.find_device_by_filter(
        lambda d, ad: (d.name or ad.local_name or "") == BLE_NAME, timeout=20.0
    )
    if dev is None:
        print(f"device {BLE_NAME} not found")
        return
    async with BleakClient(dev) as client:
        got = {}

        def on_notify(_c, data: bytearray) -> None:
            got["resp"] = bytes(data)
            got["evt"].set()

        await client.start_notify(NOTIFY_UUID, on_notify)
        await asyncio.sleep(1.0)
        try:  # inverter devices need a priming read of the init char first
            await client.read_gatt_char(INIT_CHAR_UUID)
        except Exception as exc:  # noqa: BLE001
            print(f"init read of {INIT_CHAR_UUID} failed (continuing): {exc}")

        print("=== current setpoints (read via 0x03, shown as raw x0.1) ===")
        for reg, (label, unit) in SETPOINTS.items():
            raw = read_reg(await txn(client, got, build_read(reg, 1)))
            decoded = "None" if raw is None else f"{raw * 0.1:.1f}{unit}"
            print(f"  0x{reg:04X} {label:28} raw={raw} value={decoded}")
            await asyncio.sleep(0.6)

        # Also test the count-35 block read Task 2 wants (0x1146..0x1168). If this
        # excepts (0x83 ...), Task 2 must NOT use a 35-count spec — read per-register.
        print("\n=== Task-2 block-read check: 0x1146 count 35 ===")
        block = await txn(client, got, build_read(0x1146, 35))
        if block and len(block) >= 3 and block[1] == 0x83:
            print(
                f"  EXCEPTION code 0x{block[2]:02X} — 35-count block rejected; "
                "use per-register reads"
            )
        elif block and len(block) >= 5 and block[1] == 0x03:
            print(f"  OK — block read returned {block[2]} bytes of data")
        else:
            print(f"  no valid response: {block.hex() if block else None}")

        print("\n=== safe write proof: AC input current limit (0x1168) ===")
        before = read_reg(await txn(client, got, build_read(0x1168, 1)))
        print(f"  before raw={before}")
        if before is None:
            print("  cannot read 0x1168; aborting write proof")
        else:
            await asyncio.sleep(0.6)
            ack = await txn(client, got, build_write(0x1168, before))  # same value back
            print(f"  write ack raw={ack.hex() if ack else None}")
            await asyncio.sleep(1.0)
            after = read_reg(await txn(client, got, build_read(0x1168, 1)))
            verdict = (
                "UNCHANGED (write path OK)"
                if after == before
                else "CHANGED — investigate"
            )
            print(f"  after raw={after}  {verdict}")

        await client.stop_notify(NOTIFY_UUID)


if __name__ == "__main__":
    asyncio.run(main())
