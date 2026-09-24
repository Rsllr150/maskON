"""SPI control-key checksum (French fiscal identification number).

Pure function, no dependencies: given a string of digits, returns True if the
number is 13 digits and the last 3 equal the first 10 modulo 511.
"""


def cle_spi(number: str) -> bool:
    # Guard: only a 13-digit string can be a valid SPI.
    if not number.isdigit() or len(number) != 13:
        return False

    return int(number[:10]) % 511 == int(number[10:])
