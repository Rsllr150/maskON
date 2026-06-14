"""IBAN checksum, mod-97 (ISO 7064 / ISO 13616).

Pure function: given an IBAN string, returns True if its two check digits are
consistent with the rest of the account number. Normalizes spaces and case
itself so callers can pass the raw matched text.
"""


def mod97(iban: str) -> bool:
    # 1. Normalize: drop spaces, uppercase everything.
    iban = iban.replace(" ", "").upper()

    # 2. Guard: an IBAN is letters + digits only, and never tiny.
    if not iban.isalnum() or not iban.isascii() or len(iban) < 5:
        return False

    # 3. Move the first 4 characters (country code + check digits) to the end.
    rearranged = iban[4:] + iban[:4]

    # 4. Replace each letter by a number: A→10, B→11, … Z→35; digits stay.
    #    `int(char, 36)` reads a single base-36 character, which gives exactly
    #    that mapping.
    digits = "".join(str(int(char, 36)) for char in rearranged)

    # 5. The whole thing, read as one big integer, is valid iff it ≡ 1 (mod 97).
    return int(digits) % 97 == 1
