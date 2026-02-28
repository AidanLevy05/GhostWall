from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, ListView, ListItem
from textual.reactive import reactive
from textual.widget import Widget
from datetime import datetime
import random


class Dashboard(Widget):
    """Dashboard panel with live time and dummy stats."""
    time = reactive("")

    def on_mount(self):
        # Update every second
        self.set_interval(1, self.update_time)

    def update_time(self):
        self.time = datetime.now().strftime("%H:%M:%S")
        self.refresh()

    def render(self):
        # Dummy CPU/Memory values
        cpu = random.randint(10, 90)
        mem = random.randint(20, 80)
        return f"""
[bold cyan]DASHBOARD[/bold cyan]

Time: {self.time}
CPU Usage: {cpu}%
Memory Usage: {mem}%
Status: Running
"""


class Menu(ListView):
    """Sidebar menu."""
    def compose(self) -> ComposeResult:
        yield ListItem(Static("View Dashboard"))
        yield ListItem(Static("Reset Data"))
        yield ListItem(Static("Exit"))


class DashboardApp(App):
    """Main Textual app."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #main {
        layout: horizontal;
    }

    ListView {
        width: 30%;
        border: solid cyan;
    }

    #content {
        width: 70%;
        padding: 2;
        border: solid green;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            # Sidebar menu
            yield Menu(id="menu")
            # Pre-mount dashboard
            self.dashboard_widget = Dashboard()
            yield Vertical(self.dashboard_widget, id="content")
        yield Footer()

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle menu selections."""
        label = event.item.query_one(Static).text
        content = self.query_one("#content")

        if label == "Exit":
            await self.action_quit()

        elif label == "Reset Data":
            # Clear container and show reset message
            content.clear()
            content.mount(Static("Data reset successfully!"))

        elif label == "View Dashboard":
            # Clear container and mount the pre-created dashboard widget
            content.clear()
            content.mount(self.dashboard_widget)


if __name__ == "__main__":
    DashboardApp().run()