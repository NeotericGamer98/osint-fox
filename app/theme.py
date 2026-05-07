class Theme:
    def __init__(self, dark=True):
        self.dark = dark
        self._set_colors()

    def _set_colors(self):
        if self.dark:
            self.ORANGE = "#E8751A"
            self.DARK_BG = "#1A1A2E"
            self.DARKER_BG = "#16162A"
            self.CARD_BG = "#222244"
            self.TEXT = "#E0E0E0"
            self.TEXT_DIM = "#8888AA"
            self.SUCCESS = "#4CAF50"
            self.WARNING = "#FF9800"
            self.ERROR = "#F44336"
            self.ACCENT = "#E8751A"
            self.INPUT_BG = "#2A2A4A"
            self.BORDER = "#333366"
            self.SIDEBAR_BG = "#1A1A2E"
            self.HEADER_BG = "#16162A"
            self.RESULTS_BG = "#12121E"
            self.STATUS_BG = "#0E0E1A"
            self.BUTTON_HOVER = "#C45F10"
            self.BUTTON_SECONDARY = "#3A3A5C"
            self.BUTTON_SEC_HOVER = "#4A4A6C"
        else:
            self.ORANGE = "#0066CC"
            self.DARK_BG = "#F0F2F5"
            self.DARKER_BG = "#E8EAF0"
            self.CARD_BG = "#FFFFFF"
            self.TEXT = "#222222"
            self.TEXT_DIM = "#666666"
            self.SUCCESS = "#2E7D32"
            self.WARNING = "#F57C00"
            self.ERROR = "#D32F2F"
            self.ACCENT = "#0066CC"
            self.INPUT_BG = "#FFFFFF"
            self.BORDER = "#CCCCCC"
            self.SIDEBAR_BG = "#E8EAF0"
            self.HEADER_BG = "#0066CC"
            self.RESULTS_BG = "#FFFFFF"
            self.STATUS_BG = "#E8EAF0"
            self.BUTTON_HOVER = "#004C99"
            self.BUTTON_SECONDARY = "#DDDDDD"
            self.BUTTON_SEC_HOVER = "#CCCCCC"

    def toggle(self):
        self.dark = not self.dark
        self._set_colors()
        return self


CURRENT = Theme(dark=True)
