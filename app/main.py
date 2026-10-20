"""Cipher application entry point.

The app is a single Flet page.  Navigation is handled internally (see
``app.ui.shell``) so that no Android activity transitions leak screen content
into the recents thumbnail.
"""

from __future__ import annotations

import flet as ft

from ui.shell import CipherApp


def main(page: ft.Page) -> None:
    CipherApp(page)


ft.app(main)
