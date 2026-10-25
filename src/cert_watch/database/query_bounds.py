"""Pagination offsets that SQLite can bind as signed integers."""

MAX_SQLITE_OFFSET = 2**63 - 1


def page_offset(page: int, per_page: int) -> int:
    """Keep far-out pages empty without overflowing SQLite's integer binding.

    Python can compute a page position beyond SQLite's signed 64-bit range.
    Saturate that position at the maximum offset before binding it to SQL.
    """
    return min(MAX_SQLITE_OFFSET, max(0, (page - 1) * per_page))
