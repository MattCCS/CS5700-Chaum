"""
Helper methods for ANSI escape sequences.
"""


ESC = chr(27)

NORMAL = 0
BRIGHT = 1

FG_BLACK = 30
FG_RED = 31
FG_GREEN = 32
FG_YELLOW = 33
FG_BLUE = 34
FG_MAGENTA = 35
FG_CYAN = 36
FG_WHITE = 37

BG_BLACK = 40
BG_RED = 41
BG_GREEN = 42
BG_YELLOW = 43
BG_BLUE = 44
BG_MAGENTA = 45
BG_CYAN = 46
BG_WHITE = 47


def _ansi(*values):
    return f"{ESC}[{';'.join(map(str, values))}m"


def _reset():
    return _ansi(NORMAL)


def _color(string, *values):
    """Colors the given string with the given ANSI color index."""
    return f"{_ansi(*values)}{string}{_reset()}"


def red(string):
    return _color(string, FG_RED)


def green(string):
    return _color(string, FG_GREEN)


def blue(string):
    return _color(string, FG_BLUE)


def yellow(string):
    return _color(string, FG_YELLOW)


def white(string):
    return _color(string, FG_WHITE)


def black(string):
    return _color(string, FG_BLACK)


def info(line):
    return _color(line, FG_WHITE, BRIGHT)


def warning(line):
    return _color(line, FG_YELLOW, BRIGHT)


def error(line):
    return _color(line, FG_RED, BRIGHT)


def fatal(line):
    return _color(line, FG_WHITE, BG_RED, BRIGHT)


def critical(line):
    return _color(line, FG_WHITE, BG_RED, BRIGHT)
