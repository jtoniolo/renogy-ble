"""Read-only probe for the REGO 3000 ac_input thing-model group (mid 0x5B01).

Confirms whether AC_input_watts (native W register) is served on-wire, and
decodes the whole 9-register block per assets/rtmmodels/ac_input.rtm:

  reg 0-1  AC_input_Voltage    float  x0.1  V
  reg 2-3  AC_input_current    float  x0.01 (unit mA, signed)
  reg 4-5  AC_input_frequency  float  x0.01 Hz
  reg 6-7  Ac_Volt_Range       int          (setting)
  reg 8    AC_input_watts      int          W   <-- the field in question

Run where Bluetooth can reach the inverter:  python scripts/rego_ac_input_probe.py
"""

import asyncio
import struct

from bleak import BleakClient, BleakScanner

BLE_NAME = "BTRIC130000029"
WRITE_UUID = "0000ffd1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
INIT_CHAR_UUID = "0000ffd4-0000-1000-8000-00805f9b34fb"
DEVICE_IDS = [0xFF, 0x20]  # app uses 0xFF for the thing-model block
READS = [
    ("control_4327_known_good", 4327, 7),  # positive control: proves transport
    ("ac_input_5B01_count9", 0x5B01, 9),  # the group under test
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


def decode_ac_input(words: list[int], payload: bytes) -> None:
    if len(words) < 9:
        print(f"  !! expected 9 regs, got {len(words)} — cannot decode group")
        return
    v_raw = (words[0] << 16) | words[1]
    i_raw = (words[2] << 16) | words[3]
    i_signed = struct.unpack(">i", i_raw.to_bytes(4, "big"))[0]
    f_raw = (words[4] << 16) | words[5]
    range_raw = (words[6] << 16) | words[7]
    watts = words[8]
    print("  --- decoded per ac_input.rtm ---")
    print(f"  AC_input_Voltage   = {v_raw * 0.1:.1f} V   (raw {v_raw})")
    print(
        f"  AC_input_current   = {i_signed * 0.01:.2f} (unit mA, signed raw {i_signed})"
    )
    print(f"  AC_input_frequency = {f_raw * 0.01:.2f} Hz  (raw {f_raw})")
    print(f"  Ac_Volt_Range      = {range_raw}")
    print(f"  AC_input_watts     = {watts} W   <== native power register")
    print(f"  (sanity V*I as VA  = {v_raw * 0.1 * i_signed * 0.01:.1f})")


def decode(name: str, register: int, count: int, resp: bytes) -> bool:
    print(f"\n=== {name} (reg 0x{register:04X}, requested {count} regs) ===")
    print("raw:", resp.hex())
    if len(resp) >= 3 and resp[1] == 0x83:
        print(
            f"  MODBUS EXCEPTION from device 0x{resp[0]:02X}: code 0x{resp[2]:02X}"
            + (" (Illegal Data Address)" if resp[2] == 0x02 else "")
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
    print("  16-bit regs:", [str(w) for w in words])
    if register == 0x5B01:
        decode_ac_input(words, payload)
    return True


async def main() -> None:
    print(f"scanning for {BLE_NAME} ...")
    dev = await BleakScanner.find_device_by_filter(
        lambda d, ad: (d.name or ad.local_name or "") == BLE_NAME, timeout=20.0
    )
    if dev is None:
        print(f"device {BLE_NAME} not found in range")
        return
    print(f"found {dev.address}; connecting ...")
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
                break
        await client.stop_notify(NOTIFY_UUID)


if __name__ == "__main__":
    asyncio.run(main())
