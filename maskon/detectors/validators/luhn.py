"""Luhn checksum (ISO/IEC 7812).

Pure function, no dependencies: given a string of digits, returns True if the
control key is valid. Used to validate SIREN/SIRET numbers and, later, bank
card numbers.
"""


def luhn(number: str) -> bool:
    # Guard: only non-empty, digit-only strings can be a valid number.
    if not number.isdigit():
        return False

    total = 0
    # Walk the digits from RIGHT to left.
    # `reversed` flips the string; `enumerate` gives the position (0, 1, 2…).
    for position, char in enumerate(reversed(number)):
        digit = int(char)
        # Every second digit from the right is doubled:
        # odd positions (1, 3, 5…) in the zero-based index.
        if position % 2 == 1:
            digit *= 2
            # If doubling exceeds 9, subtract 9 (same as summing the two
            # digits: 16 → 1+6 = 7, and 16-9 = 7).
            if digit > 9:
                digit -= 9
        total += digit

    # The number is valid if the total is a multiple of 10.
    return total % 10 == 0
