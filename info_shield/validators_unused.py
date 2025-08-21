import re

def luhn_check(s: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", s)]
    if not digits:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0