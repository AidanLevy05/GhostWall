import curses
import time
import random
from datetime import datetime


def draw_menu(stdscr, selected_row):
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    menu = ["View Dashboard", "Reset Counter", "Exit"]

    for idx, row in enumerate(menu):
        x = w // 2 - len(row) // 2
        y = h // 2 - len(menu) // 2 + idx

        if idx == selected_row:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, row)
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.addstr(y, x, row)

    stdscr.refresh()


def dashboard(stdscr, counter):
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        title = "DASHBOARD (Press 'q' to return)"
        stdscr.addstr(1, w // 2 - len(title) // 2, title)

        stdscr.addstr(3, 5, f"Time: {datetime.now().strftime('%H:%M:%S')}")
        stdscr.addstr(4, 5, f"Counter: {counter}")
        stdscr.addstr(5, 5, f"CPU Usage: {random.randint(10, 90)}%")

        stdscr.refresh()
        counter += 1

        stdscr.timeout(1000)
        key = stdscr.getch()

        if key == ord("q"):
            break


def main(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)

    current_row = 0
    counter = 0

    while True:
        draw_menu(stdscr, current_row)

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % 3
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % 3
        elif key == curses.KEY_ENTER or key in [10, 13]:

            if current_row == 0:
                dashboard(stdscr, counter)

            elif current_row == 1:
                counter = 0

            elif current_row == 2:
                break


curses.wrapper(main)