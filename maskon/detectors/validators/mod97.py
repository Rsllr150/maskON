"""IBAN checksum, mod-97 (ISO 7064 / ISO 13616).

Pure function: given an IBAN string, returns True if its two check digits are
consistent with the rest of the account number. Normalizes spaces and case
itself so callers can pass the raw matched text.
"""

# An IBAN is at most 34 characters; anything longer is not one.
_MAX_LEN = 34


def mod97(iban: str) -> bool:
    # 1. Normalize: drop spaces, uppercase everything.
    iban = iban.replace(" ", "").upper()

    # 2. Guard: an IBAN is letters + digits only, never tiny, never huge.
    if not iban.isalnum() or not iban.isascii() or not 5 <= len(iban) <= _MAX_LEN:
        return False

    # 3. Move the first 4 characters (country code + check digits) to the end.
    rearranged = iban[4:] + iban[:4]

    # 4. Replace each letter by a number: A→10, B→11, … Z→35; digits stay.
    #    `int(char, 36)` reads a single base-36 character, which gives exactly
    #    that mapping.
    digits = "".join(str(int(char, 36)) for char in rearranged)

    # 5. Valid iff the whole number ≡ 1 (mod 97). Computed piecewise, 9 digits
    #    at a time (carrying the remainder), so no big integer is ever built.
    remainder = 0
    for i in range(0, len(digits), 9):
        remainder = int(str(remainder) + digits[i : i + 9]) % 97
    return remainder == 1
