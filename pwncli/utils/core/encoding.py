"""负载编码：URL 与 Base64。适用于 web-pwn / IoT 题目。"""

__all__ = [
    "url_encode",
    "url_decode",
    "b64_encode",
    "b64_decode",
]


def url_encode(data, safe='') -> str:
    """对 bytes/str 负载进行 URL 编码。适用于 web-pwn / IoT 题目。

    Args:
        data: 待编码的 bytes 或 str
        safe: 不进行编码的字符（默认：全部编码）

    Returns:
        URL 编码后的字符串

    Examples:
        >>> url_encode(b'\\x00\\x01/bin/sh\\x00')
        '%00%01%2Fbin%2Fsh%00'
        >>> url_encode(b'hello world')
        'hello%20world'
        >>> url_encode(b'/bin/sh', safe='/')
        '/bin/sh'
    """
    from urllib.parse import quote
    if isinstance(data, str):
        data = data.encode('latin-1')
    return quote(data, safe=safe)


def url_decode(data) -> bytes:
    """将字符串 URL 解码回 bytes。

    Args:
        data: URL 编码的字符串（如 '%00%01%2Fbin'）

    Returns:
        解码后的 bytes

    Examples:
        >>> url_decode('%00%01%2Fbin%2Fsh%00')
        b'\\x00\\x01/bin/sh\\x00'
        >>> url_decode('hello%20world')
        b'hello world'
    """
    from urllib.parse import unquote_to_bytes
    if isinstance(data, bytes):
        data = data.decode('ascii')
    return unquote_to_bytes(data)


def b64_encode(data) -> str:
    """对 bytes/str 负载进行 Base64 编码。

    Args:
        data: 待编码的 bytes 或 str

    Returns:
        Base64 编码后的字符串（无换行）

    Examples:
        >>> b64_encode(b'\\x00\\x01\\x02\\xff')
        'AAEC/w=='
        >>> b64_encode(b'/bin/sh')
        'L2Jpbi9zaA=='
    """
    from base64 import b64encode
    if isinstance(data, str):
        data = data.encode('latin-1')
    return b64encode(data).decode('ascii')


def b64_decode(data) -> bytes:
    """将 Base64 字符串解码回 bytes。

    Args:
        data: Base64 编码的字符串

    Returns:
        解码后的 bytes

    Examples:
        >>> b64_decode('AAEC/w==')
        b'\\x00\\x01\\x02\\xff'
        >>> b64_decode('L2Jpbi9zaA==')
        b'/bin/sh'
    """
    from base64 import b64decode
    if isinstance(data, bytes):
        data = data.decode('ascii')
    return b64decode(data)


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)
