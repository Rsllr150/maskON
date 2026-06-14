"""NIR control-key checksum (French social security number).

A NIR is 15 characters: a 13-character identity number + a 2-digit key.
The key must equal 97 - (identity mod 97). Corsican departments use the
letters 2A / 2B, replaced by 19 / 18 for the computation.
"""


def cle_nir(nir: str) -> bool:
    s = nir.replace(" ", "").upper()
    if len(s) != 15:
        return False

    base, key = s[:13], s[13:]
    # Corsica: the department field can be 2A or 2B → 19 / 18 for the maths.
    base = base.replace("2A", "19").replace("2B", "18")

    if not base.isdigit() or not key.isdigit():
        return False

    expected = 97 - (int(base) % 97)
    return int(key) == expected
