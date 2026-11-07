"""Small, bounded helpers for comments and quoted strings in mail headers."""
import re


def mask_header(value, quotes=False):
    result = []
    depth, quoted, escaped = 0, False, False
    for char in str(value):
        if escaped:
            result.append(" " if depth or (quotes and quoted) else char)
            escaped = False
        elif char == "\\" and (depth or quoted):
            result.append(" " if depth or (quotes and quoted) else char)
            escaped = True
        elif depth:
            depth += (char == "(") - (char == ")")
            result.append(" ")
        elif char == '"':
            quoted = not quoted
            result.append(" " if quotes else char)
        elif not quoted and char == "(":
            depth = 1
            result.append(" ")
        else:
            result.append(" " if quotes and quoted else char)
    return "".join(result)


def split_clauses(value):
    value = str(value)
    boundaries = [m.start() for m in re.finditer(";", mask_header(value, quotes=True))]
    start = 0
    for end in boundaries + [len(value)]:
        yield value[start:end]
        start = end + 1


def assignments(value):
    pairs = {}
    pattern = r'(?<![\w.-])([a-z][\w.-]*)\s*=\s*("(?:\\.|[^"\\])*"|[^\s;]+)'
    for match in re.finditer(pattern, mask_header(value), re.I):
        key, val = match.groups()
        if val.startswith('"') and val.endswith('"'):
            val = re.sub(r"\\(.)", r"\1", val[1:-1])
        pairs[key.lower()] = val
    return pairs
