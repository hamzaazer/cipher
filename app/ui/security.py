"""Runtime security probing.

Every flag shown in the UI comes from a probe, never from a build constant.
If the native extension is missing, the app still works but reports degraded
mode loudly: file identity, no hardware binding, no screenshot protection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import flet as ft

from identity import Identity, IdentityError, load_file_identity, load_identity, unlock
from ui.theme import DANGER, MUTED, SURFACE_2, TEXT, WARN


@dataclass
class SecurityState:
    native: bool = False
    secure_screen: bool = False
    hardware: bool = False
    strongbox: bool = False
    sdk: Optional[int] = None
    identity: Optional[Identity] = None
    degraded_reason: str = ""
    native_status: dict[str, Any] = field(default_factory=dict)

    @property
    def identity_storage(self) -> str:
        return self.identity.storage if self.identity else "none"

    @property
    def degraded(self) -> bool:
        return self.identity_storage != "keystore" or not self.secure_screen


def probe(native: Any = None) -> SecurityState:
    state = SecurityState()
    if native is not None:
        try:
            status = native.status()
            state.native_status = status
            state.native = bool(status.get("available"))
            state.secure_screen = bool(status.get("secure"))
            state.hardware = bool(status.get("hardware"))
            state.strongbox = bool(status.get("strongbox"))
            sdk = status.get("sdk")
            state.sdk = int(sdk) if isinstance(sdk, (int, float, str)) else None
        except Exception as exc:
            state.degraded_reason = _reason(exc)

    backend = None
    if state.native:
        try:
            backend = load_identity(prefer_native=True)
            state.identity = unlock(backend)
        except Exception as exc:
            state.degraded_reason = _reason(exc)

    if state.identity is None:
        try:
            backend = load_file_identity()
            state.identity = unlock(backend)
        except Exception as exc:
            state.degraded_reason = _reason(exc)
            state.identity = None

    return state


def _reason(exc: BaseException) -> str:
    if isinstance(exc, IdentityError):
        return str(exc)
    return exc.__class__.__name__


def banner(state: SecurityState) -> Optional[ft.Control]:
    """Red degraded-mode banner, or None when the hardware path is active."""
    if state.identity is not None and not state.degraded:
        return None
    if state.identity is None:
        text = "No usable identity. Cipher cannot start a conversation."
    else:
        text = "DEGRADED: file identity, no hardware binding, screenshots not blocked."
    return ft.Container(
        bgcolor="#3A1114",
        border=ft.border.all(1, DANGER),
        border_radius=8,
        padding=ft.padding.symmetric(horizontal=12, vertical=8),
        content=ft.Row(
            tight=True,
            spacing=8,
            controls=[
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=DANGER, size=16),
                ft.Text(text, color=TEXT, size=11, expand=True),
            ],
        ),
    )


def status_line(state: SecurityState) -> ft.Control:
    if state.identity is None:
        label = "identity: unavailable"
        color = DANGER
    elif state.identity_storage == "keystore":
        label = "Keystore identity" + (" (StrongBox)" if state.strongbox else " (hardware)")
        color = TEXT
    else:
        label = "File identity (degraded)"
        color = WARN
    secure = "screenshots blocked" if state.secure_screen else "screenshots NOT blocked"
    return ft.Row(
        tight=True,
        alignment=ft.MainAxisAlignment.CENTER,
        spacing=6,
        controls=[
            ft.Container(width=6, height=6, border_radius=3, bgcolor=color),
            ft.Text(f"{label} · {secure}", color=MUTED, size=10),
        ],
    )


def security_rows(state: SecurityState) -> list[ft.Control]:
    """Rows for the Security screen (Phase 4 reuses this)."""
    rows = [
        _row("Identity storage", state.identity_storage),
        _row("Hardware-backed", _yes_no(state.hardware)),
        _row("StrongBox", _yes_no(state.strongbox)),
        _row("Screenshots", "blocked" if state.secure_screen else "NOT blocked"),
        _row("Native channel", _yes_no(state.native)),
        _row("Android SDK", str(state.sdk) if state.sdk else "n/a"),
    ]
    if state.degraded_reason:
        rows.append(_row("Degraded reason", state.degraded_reason))
    return rows


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _row(label: str, value: str) -> ft.Control:
    return ft.Container(
        bgcolor=SURFACE_2,
        border_radius=8,
        padding=ft.padding.symmetric(horizontal=12, vertical=10),
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Text(label, color=MUTED, size=11),
                ft.Text(value, color=TEXT, size=11, weight=ft.FontWeight.W_500),
            ],
        ),
    )
