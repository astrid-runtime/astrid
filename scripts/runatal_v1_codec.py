"""Shared byte cursor and tagged identities for the independent reader."""

class FormatError(Exception):
    pass


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        if end > len(self.data):
            raise FormatError("truncated payload")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, length):
        return int.from_bytes(self.take(length), "little")

    def done(self):
        if self.offset != len(self.data):
            raise FormatError("trailing payload bytes")


def identity(cursor):
    algorithm = cursor.integer(2)
    construction = cursor.integer(2)
    length = cursor.integer(4)
    if not algorithm or not construction or not length:
        raise FormatError("zero identity tag field")
    return (algorithm, construction, cursor.take(length))


def identity_text(value):
    return f"{value[0]}:{value[1]}:{len(value[2])}:{value[2].hex()}"

