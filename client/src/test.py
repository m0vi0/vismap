import curses
import time
import math

WIDTH = 80
HEIGHT = 24

def draw_frame(stdscr, t):
    stdscr.clear()

    # moving dot demo
    x = int((math.sin(t) + 1) * (WIDTH // 2))
    y = HEIGHT // 2

    stdscr.addstr(0, 0, "pacmap (terminal mode)")
    stdscr.addstr(y, x, "●")

    stdscr.refresh()

def main(stdscr):
    curses.curs_set(0)

    t = 0
    while True:
        draw_frame(stdscr, t)
        time.sleep(0.05)
        t += 0.1

curses.wrapper(main)
