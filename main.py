import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.gui import OSINTFoxApp

if __name__ == "__main__":
    app = OSINTFoxApp()
    app.run()
