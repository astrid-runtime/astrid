"""State-owner-v2 display grammar for the independent reader."""


class OwnerFormatError(ValueError):
    pass


def principal_text(principal):
    if principal == b"\0":
        return "system"
    if len(principal) == 33 and principal[:1] == b"\1":
        return principal[1:].hex()
    if len(principal) == 33 and principal[:1] == b"\2":
        return f"fleet:{principal[1:].hex()}"
    if len(principal) == 33 and principal[:1] == b"\3":
        return f"user:{principal[1:].hex()}"
    raise OwnerFormatError("invalid state-owner-v2 encoding")
