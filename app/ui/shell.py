"""Cipher UI: onboarding, conversations, chat, pairing, security, settings.

The shell is intentionally a single Flet page with internal navigation.  No
route or activity transition can expose message content in the recents
thumbnail, and the hidden native control stays mounted for the whole session.

All secrets stay in the service layer.  This module only displays the SAS,
fingerprints and message bodies that the user is meant to see, and it never
offers a copy action for message text or invite secrets.
"""

from __future__ import annotations

import base64
import io
import threading
import time
from typing import Any, Optional

import flet as ft
import qrcode

from config import relay_pins, relay_url
from crypto.constants import PROTOCOL_VERSION
from identity import IdentityError
from messaging import (
    InviteSession,
    JoinSession,
    MessagingError,
    MessagingService,
    PendingPair,
)
from paths import db_path
from relay_client import PinMismatch, RelayClient
from storage.store import CipherStore, StorageError
from ui.security import SecurityState, banner, probe, security_rows, status_line
from ui.theme import (
    ACCENT,
    BG,
    BORDER,
    BUBBLE_IN,
    BUBBLE_OUT,
    DANGER,
    MUTED,
    SURFACE,
    SURFACE_2,
    TEXT,
    WARN,
)

try:
    from cipher_native import CipherNative
except Exception:  # pragma: no cover - broken installs fall back to file identity
    CipherNative = None  # type: ignore[assignment]


def _short_id(key_id: bytes) -> str:
    return key_id.hex().upper()[:16]


def _grouped(key_id: bytes) -> str:
    text = key_id.hex().upper()
    return " ".join(text[i : i + 4] for i in range(0, len(text), 4))


def _minutes_left(expires_at: int, now: Optional[int] = None) -> str:
    left = max(0, expires_at - (int(time.time()) if now is None else now))
    if left >= 3600:
        return f"{left // 3600}h {(left % 3600) // 60:02d}m"
    if left >= 60:
        return f"{left // 60}m {left % 60:02d}s"
    return f"{left}s"


class CipherApp:
    def __init__(self, page: ft.Page) -> None:
        self.page = page
        self._configure_page()

        self.screen = "onboarding"
        self.conv_id: Optional[bytes] = None
        self.invite_session: Optional[InviteSession] = None
        self.join_session: Optional[JoinSession] = None
        self.pending: Optional[PendingPair] = None
        self.pair_mode = "create"
        self.pair_error = ""
        self.wiped = False
        self.last_error = ""

        # The native control must be mounted before `status` can be called:
        # before `page.add`, `Control.page` is None and the platform call would
        # assert, silently forcing every Android launch into degraded mode.
        # Only create it on Android; desktop has no plugin registration.
        is_android = page.platform == ft.PagePlatform.ANDROID
        self.native = (
            CipherNative() if CipherNative is not None and is_android else None
        )
        if self.native is not None:
            page.overlay.append(self.native)

        self.security: SecurityState = SecurityState()
        self.service: Optional[MessagingService] = None
        self.service_error = ""
        self.store: Optional[CipherStore] = None

        self._ui_lock = threading.RLock()
        self._poll_stop = threading.Event()
        self._conv_sig: Any = None
        self._msg_sig: Any = None
        self.chat_input: Optional[ft.TextField] = None
        self.join_input: Optional[ft.TextField] = None
        self.pair_status: Optional[ft.Text] = None
        self.pair_countdown: Optional[ft.Text] = None
        self.msg_list: Optional[ft.Column] = None
        self.conv_list: Optional[ft.Column] = None

        self.banner_host = ft.Column(tight=True, spacing=0)
        self.top_host = ft.Column(tight=True, spacing=0)
        self.body = ft.Column(expand=True, spacing=0)
        self.root = ft.Column(
            expand=True, spacing=0, controls=[self.banner_host, self.top_host, self.body]
        )
        # `page.add` mounts the overlay native control and runs its
        # `did_mount`, which binds the Python bridge.  Probe only afterwards so
        # the Keystore/screenshot flags reflect the real channel.
        page.add(self.root)
        self.security = probe(self.native)
        self._init_service()
        page.update()

        self._render()
        page.run_thread(self._poll_loop)

    # -- setup -----------------------------------------------------------

    def _configure_page(self) -> None:
        page = self.page
        page.title = "Cipher"
        page.bgcolor = BG
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 0
        page.spacing = 0
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        page.vertical_alignment = ft.MainAxisAlignment.START

    def _init_service(self) -> None:
        identity = self.security.identity
        if identity is None:
            self.service_error = "No usable identity."
            return
        try:
            self.store = CipherStore(
                db_path(),
                identity.kek,
                identity.key_id,
                identity.public_key,
                identity.storage,
            )
            relay = RelayClient(relay_url(), relay_pins())
            self.service = MessagingService(self.store, identity, relay)
            try:
                self.service.expire()
            except StorageError:
                pass
        except Exception as exc:
            self.service_error = _friendly_error(exc)
            self.service = None

    # -- rendering -------------------------------------------------------

    def _render(self) -> None:
        with self._ui_lock:
            self._render_banner()
            if self.wiped:
                self._render_wiped()
            elif self.security.identity is None:
                self._render_fatal()
            elif self.screen == "onboarding":
                self._render_onboarding()
            elif self.screen == "conversations":
                self._render_conversations()
            elif self.screen == "chat":
                self._render_chat()
            elif self.screen == "pairing":
                self._render_pairing()
            elif self.screen == "security":
                self._render_security()
            elif self.screen == "settings":
                self._render_settings()
            else:
                self._render_onboarding()
        self.page.update()

    def _render_banner(self) -> None:
        self.banner_host.controls.clear()
        warning = banner(self.security)
        if warning is not None:
            self.banner_host.controls.append(warning)
        if self.service is None and not self.wiped:
            detail = self.service_error or (
                "Relay not configured in this build: pairing and messaging "
                "are disabled. Rebuild with CIPHER_RELAY_URL and "
                "CIPHER_RELAY_PINS."
            )
            self.banner_host.controls.append(_notice(detail, WARN))

    def _set_screen(self, screen: str, conv_id: Optional[bytes] = None) -> None:
        self.screen = screen
        self.conv_id = conv_id
        self.pair_error = ""
        self._render()

    def _header(
        self,
        title: str,
        *,
        back_to: Optional[str] = None,
        actions: Optional[list[ft.Control]] = None,
    ) -> ft.Control:
        controls: list[ft.Control] = []
        if back_to is not None:
            controls.append(
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    icon_color=TEXT,
                    icon_size=20,
                    tooltip="Back",
                    on_click=lambda e: self._set_screen(back_to),
                )
            )
        controls.append(
            ft.Text(title, size=18, weight=ft.FontWeight.W_600, color=TEXT, expand=True)
        )
        controls.extend(actions or [])
        return ft.Container(
            bgcolor=SURFACE,
            padding=ft.padding.symmetric(horizontal=8, vertical=4),
            content=ft.Row(
                controls=controls,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=2,
            ),
        )

    def _nav_actions(self) -> list[ft.Control]:
        return [
            ft.IconButton(
                icon=ft.Icons.SECURITY,
                icon_color=MUTED,
                icon_size=20,
                tooltip="Security",
                on_click=lambda e: self._set_screen("security"),
            ),
            ft.IconButton(
                icon=ft.Icons.SETTINGS,
                icon_color=MUTED,
                icon_size=20,
                tooltip="Settings",
                on_click=lambda e: self._set_screen("settings"),
            ),
        ]

    def _render_wiped(self) -> None:
        self.top_host.controls.clear()
        self.body.controls = [
            _center(
                [
                    ft.Icon(ft.Icons.LOCK_OUTLINE, size=56, color=MUTED),
                    ft.Text("Cipher wiped", size=26, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Text(
                        "Identity, conversations and ratchet state are destroyed. "
                        "Close and reopen the app to create a new identity.",
                        size=12,
                        color=MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ]
            )
        ]

    def _render_fatal(self) -> None:
        self.top_host.controls.clear()
        self.body.controls = [
            _center(
                [
                    ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=48, color=DANGER),
                    ft.Text("Identity unavailable", size=24, color=TEXT),
                    ft.Text(
                        "Cipher cannot start without an identity. "
                        "Reinstall the app; there is no recovery path by design.",
                        size=12,
                        color=MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ]
            )
        ]

    # -- onboarding ------------------------------------------------------

    def _render_onboarding(self) -> None:
        self.top_host.controls.clear()
        start = ft.ElevatedButton(
            "Get started",
            bgcolor=ACCENT,
            color=BG,
            on_click=lambda e: self._set_screen("conversations"),
        )
        self.body.controls = [
            _center(
                [
                    ft.Icon(ft.Icons.LOCK_OUTLINE, size=64, color=ACCENT),
                    ft.Text("Cipher", size=36, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Text(
                        "Ephemeral, end-to-end encrypted 1:1 messaging",
                        size=12,
                        color=MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(height=8),
                    _feature("No accounts, no phone number", "Identity is a key generated on this device."),
                    _feature("Nothing is recoverable", "Lose the device and the identity is gone."),
                    _feature("24-hour lifetime", "Messages and chats crypto-shred after 24 hours."),
                    _feature("Pairing is deliberate", "Scan a one-time QR or type its short secret."),
                    ft.Container(height=8),
                    start,
                    status_line(self.security),
                ]
            )
        ]

    # -- conversations ---------------------------------------------------

    def _render_conversations(self) -> None:
        self.top_host.controls = [
            self._header(
                "Cipher",
                actions=[
                    ft.IconButton(
                        icon=ft.Icons.ADD,
                        icon_color=ACCENT,
                        icon_size=24,
                        tooltip="Pair a device",
                        on_click=lambda e: self._open_pairing(),
                    ),
                    *self._nav_actions(),
                ],
            )
        ]
        self.conv_list = ft.Column(spacing=8)
        convs = self.service.conversations() if self.service else []
        if not convs:
            self.conv_list.controls = [
                _center(
                    [
                        ft.Icon(ft.Icons.LINK_OFF, size=44, color=MUTED),
                        ft.Text("No conversations yet", size=16, color=TEXT),
                        ft.Text(
                            "Pair with one other device. Both people must compare "
                            "the six-digit code.",
                            size=11,
                            color=MUTED,
                            text_align=ft.TextAlign.CENTER,
                        ),
                        ft.ElevatedButton(
                            "Pair a device",
                            bgcolor=ACCENT,
                            color=BG,
                            disabled=self.service is None,
                            on_click=lambda e: self._open_pairing(),
                        ),
                    ]
                )
            ]
        else:
            for conv in convs:
                last = ""
                msgs = self.service.messages(conv.conv_id) if self.service else []
                if msgs:
                    last = msgs[-1].plaintext.decode("utf-8", "replace")
                self.conv_list.controls.append(
                    _conversation_tile(
                        peer=_short_id(conv.peer_key_id),
                        preview=last or "Paired. No messages yet.",
                        ttl=_minutes_left(conv.expires_at),
                        on_click=lambda e, c=conv: self._set_screen("chat", c.conv_id),
                    )
                )
        self.body.controls = [
            ft.Container(
                expand=True,
                padding=ft.padding.symmetric(horizontal=12, vertical=12),
                content=ft.Column(
                    [self.conv_list],
                    scroll=ft.ScrollMode.AUTO,
                    expand=True,
                ),
            )
        ]

    # -- chat ------------------------------------------------------------

    def _render_chat(self) -> None:
        if self.service is None or self.conv_id is None:
            self._set_screen("conversations")
            return
        try:
            conv = self.store.get_conv(self.conv_id) if self.store else None
        except StorageError:
            self._set_screen("conversations")
            return
        if conv is None:
            self._set_screen("conversations")
            return

        self.top_host.controls = [
            self._header(
                _short_id(conv.peer_key_id),
                back_to="conversations",
                actions=[
                    ft.Text(_minutes_left(conv.expires_at), size=10, color=MUTED),
                    ft.IconButton(
                        icon=ft.Icons.DELETE_OUTLINE,
                        icon_color=MUTED,
                        icon_size=20,
                        tooltip="Delete conversation",
                        on_click=lambda e: self._confirm_delete_conversation(conv.conv_id),
                    ),
                ],
            )
        ]

        self.msg_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        self.chat_input = ft.TextField(
            hint_text="Message (not copyable)",
            color=TEXT,
            hint_style=ft.TextStyle(color=MUTED, size=12),
            bgcolor=SURFACE_2,
            border_color=BORDER,
            focused_border_color=ACCENT,
            border_radius=20,
            content_padding=ft.padding.symmetric(horizontal=14, vertical=10),
            text_size=13,
            expand=True,
            multiline=False,
            shift_enter=False,
            on_submit=lambda e: self._send(),
        )
        composer = ft.Container(
            bgcolor=SURFACE,
            padding=ft.padding.symmetric(horizontal=10, vertical=8),
            content=ft.Row(
                spacing=6,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.chat_input,
                    ft.IconButton(
                        icon=ft.Icons.SEND,
                        icon_color=ACCENT,
                        icon_size=22,
                        tooltip="Send",
                        on_click=lambda e: self._send(),
                    ),
                ],
            ),
        )
        self.body.controls = [
            ft.Container(
                expand=True,
                padding=ft.padding.symmetric(horizontal=10, vertical=8),
                content=self.msg_list,
            ),
            composer,
        ]
        self._fill_messages(conv.conv_id)

    def _fill_messages(self, conv_id: bytes) -> None:
        if self.msg_list is None or self.service is None:
            return
        msgs = self.service.messages(conv_id)
        self._msg_sig = (
            len(msgs),
            msgs[-1].msg_id if msgs else b"",
        )
        self.msg_list.controls = [
            _bubble(m.plaintext, outgoing=m.direction == 1, sent_at=m.sent_at)
            for m in msgs
        ] or [
            _center(
                [
                    ft.Icon(ft.Icons.LOCK_OUTLINE, size=32, color=MUTED),
                    ft.Text(
                        "Messages are end-to-end encrypted and disappear after 24 hours.",
                        size=11,
                        color=MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ]
            )
        ]

    def _send(self) -> None:
        if self.chat_input is None or self.service is None or self.conv_id is None:
            return
        text = self.chat_input.value or ""
        if not text.strip():
            return
        try:
            self.service.send(self.conv_id, text)
        except (MessagingError, StorageError, IdentityError) as exc:
            self._toast(_friendly_error(exc), DANGER)
            return
        self.chat_input.value = ""
        self._fill_messages(self.conv_id)
        self.page.update()

    # -- pairing ---------------------------------------------------------

    def _open_pairing(self) -> None:
        if self.service is None:
            self._toast("Relay is not configured; pairing is disabled.", DANGER)
            return
        self.invite_session = None
        self.join_session = None
        self.pending = None
        self.pair_mode = "create"
        self._set_screen("pairing")

    def _render_pairing(self) -> None:
        self.top_host.controls = [
            self._header(
                "Pair a device",
                back_to="conversations",
                actions=[
                    ft.Container(
                        padding=ft.padding.only(right=8),
                        content=ft.Text("120 s one-time invite", size=9, color=MUTED),
                    )
                ],
            )
        ]

        if self.pending is not None:
            self.body.controls = [self._sas_panel(self.pending)]
            return

        tabs = ft.Row(
            spacing=6,
            controls=[
                _tab(
                    "Create invite",
                    active=self.pair_mode == "create",
                    on_click=lambda e: self._switch_pair_mode("create"),
                ),
                _tab(
                    "Join invite",
                    active=self.pair_mode == "join",
                    on_click=lambda e: self._switch_pair_mode("join"),
                ),
            ],
        )

        if self.pair_mode == "create":
            panel = self._create_invite_panel()
        else:
            panel = self._join_invite_panel()

        self.body.controls = [
            ft.Container(
                expand=True,
                padding=ft.padding.symmetric(horizontal=14, vertical=12),
                content=ft.Column(
                    [tabs, panel],
                    spacing=12,
                    scroll=ft.ScrollMode.AUTO,
                    expand=True,
                ),
            )
        ]
        if self.pair_error:
            self._toast(self.pair_error, DANGER)

    def _switch_pair_mode(self, mode: str) -> None:
        if self.pair_mode == mode:
            return
        self._cancel_pairing_silently()
        self.pair_mode = mode
        self.pair_error = ""
        self._render()

    def _create_invite_panel(self) -> ft.Control:
        if self.invite_session is None:
            return ft.Column(
                spacing=12,
                controls=[
                    ft.Text(
                        "Create a one-time invite. Show the QR code to the other "
                        "device, or read out the short secret. The invite is "
                        "deleted when used or after 120 seconds.",
                        size=12,
                        color=MUTED,
                    ),
                    ft.ElevatedButton(
                        "Create invite",
                        bgcolor=ACCENT,
                        color=BG,
                        disabled=self.service is None,
                        on_click=lambda e: self._create_invite(),
                    ),
                ],
            )

        session = self.invite_session
        qr = _qr_image(session.uri)
        self.pair_countdown = ft.Text(
            _minutes_left(session.invite.expires_at),
            size=11,
            color=MUTED,
        )
        self.pair_status = ft.Text(
            "Waiting for the other device to scan or type the secret...",
            size=11,
            color=MUTED,
            text_align=ft.TextAlign.CENTER,
        )
        return ft.Column(
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Container(
                    bgcolor=ft.Colors.WHITE,
                    border_radius=10,
                    padding=8,
                    content=qr,
                ),
                ft.Text(
                    "Do not screenshot or share this code.",
                    size=10,
                    color=WARN,
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Container(
                    bgcolor=SURFACE_2,
                    border_radius=8,
                    padding=ft.padding.symmetric(horizontal=12, vertical=10),
                    content=ft.Column(
                        tight=True,
                        spacing=4,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.Text("Or type this secret", size=10, color=MUTED),
                            ft.Text(
                                session.base32,
                                size=13,
                                color=TEXT,
                                selectable=False,
                                text_align=ft.TextAlign.CENTER,
                            ),
                        ],
                    ),
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    controls=[
                        ft.Icon(ft.Icons.HOURGLASS_EMPTY, size=14, color=MUTED),
                        self.pair_countdown,
                    ],
                ),
                self.pair_status,
                ft.TextButton(
                    "Cancel invite",
                    on_click=lambda e: self._cancel_pairing(),
                ),
            ],
        )

    def _join_invite_panel(self) -> ft.Control:
        if self.join_session is None:
            self.join_input = ft.TextField(
                hint_text="cipher://pair/v1/... or 26-character secret",
                color=TEXT,
                hint_style=ft.TextStyle(color=MUTED, size=11),
                bgcolor=SURFACE_2,
                border_color=BORDER,
                focused_border_color=ACCENT,
                border_radius=10,
                content_padding=ft.padding.symmetric(horizontal=12, vertical=12),
                text_size=12,
                multiline=True,
                min_lines=2,
                max_lines=3,
                on_submit=lambda e: self._join_invite(),
            )
            return ft.Column(
                spacing=12,
                controls=[
                    ft.Text(
                        "Scan the other device's QR code, or paste/type the "
                        "short secret it shows. The invite can be used once.",
                        size=12,
                        color=MUTED,
                    ),
                    self.join_input,
                    ft.ElevatedButton(
                        "Join and verify",
                        bgcolor=ACCENT,
                        color=BG,
                        disabled=self.service is None,
                        on_click=lambda e: self._join_invite(),
                    ),
                ],
            )

        session = self.join_session
        self.pair_countdown = ft.Text(
            _minutes_left(session.expires_at), size=11, color=MUTED
        )
        self.pair_status = ft.Text(
            "Handshake sent. Waiting for the other device to accept...",
            size=11,
            color=MUTED,
            text_align=ft.TextAlign.CENTER,
        )
        return ft.Column(
            spacing=14,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.ProgressRing(color=ACCENT, width=28, height=28, stroke_width=3),
                self.pair_status,
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    controls=[
                        ft.Icon(ft.Icons.HOURGLASS_EMPTY, size=14, color=MUTED),
                        self.pair_countdown,
                    ],
                ),
                ft.TextButton(
                    "Cancel",
                    on_click=lambda e: self._cancel_pairing(),
                ),
            ],
        )

    def _sas_panel(self, pending: PendingPair) -> ft.Control:
        return ft.Container(
            expand=True,
            padding=ft.padding.symmetric(horizontal=18, vertical=20),
            content=ft.Column(
                spacing=16,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
                controls=[
                    ft.Icon(ft.Icons.SHIELD_OUTLINED, size=40, color=ACCENT),
                    ft.Text(
                        "Compare this code",
                        size=20,
                        weight=ft.FontWeight.W_600,
                        color=TEXT,
                    ),
                    ft.Text(
                        "Both devices must show the same six digits. If they "
                        "differ, an attacker may be in the middle: cancel.",
                        size=11,
                        color=MUTED,
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(
                        bgcolor=SURFACE_2,
                        border_radius=14,
                        padding=ft.padding.symmetric(horizontal=20, vertical=16),
                        content=ft.Text(
                            f"{pending.sas[:3]} {pending.sas[3:]}",
                            size=40,
                            weight=ft.FontWeight.BOLD,
                            color=ACCENT,
                            selectable=False,
                        ),
                    ),
                    ft.Text(
                        "Peer fingerprint",
                        size=9,
                        color=MUTED,
                    ),
                    ft.Text(
                        _grouped(pending.peer_key_id),
                        size=10,
                        color=TEXT,
                        text_align=ft.TextAlign.CENTER,
                        selectable=False,
                    ),
                    ft.Container(height=4),
                    ft.ElevatedButton(
                        "The codes match",
                        bgcolor=ACCENT,
                        color=BG,
                        width=260,
                        on_click=lambda e: self._confirm_pairing(),
                    ),
                    ft.TextButton(
                        "Cancel — codes differ",
                        on_click=lambda e: self._cancel_pairing(),
                    ),
                ],
            ),
        )

    def _create_invite(self) -> None:
        if self.service is None:
            return
        try:
            self.invite_session = self.service.start_invite()
        except Exception as exc:
            self.pair_error = _friendly_error(exc)
            self._toast(self.pair_error, DANGER)
            return
        self.pair_error = ""
        self._render()

    def _join_invite(self) -> None:
        if self.service is None or self.join_input is None:
            return
        value = self.join_input.value or ""
        try:
            self.join_session = self.service.join(value)
        except Exception as exc:
            self.pair_error = _friendly_error(exc)
            self._toast(self.pair_error, DANGER)
            return
        self.pair_error = ""
        self._render()

    def _confirm_pairing(self) -> None:
        if self.service is None or self.pending is None:
            return
        try:
            conv = self.service.complete_pairing(self.pending)
        except Exception as exc:
            self._toast(_friendly_error(exc), DANGER)
            return
        self.invite_session = None
        self.join_session = None
        self.pending = None
        self._set_screen("chat", conv.conv_id)

    def _cancel_pairing(self) -> None:
        self._cancel_pairing_silently()
        self.invite_session = None
        self.join_session = None
        self.pending = None
        self._set_screen("conversations")

    def _cancel_pairing_silently(self) -> None:
        if self.service is None:
            return
        session = self.invite_session or self.join_session
        if session is not None:
            try:
                self.service.cancel_pairing(session)
            except Exception:
                pass

    def _confirm_delete_conversation(self, conv_id: bytes) -> None:
        def delete(e: ft.ControlEvent) -> None:
            self.page.close(dialog)
            if self.service is not None:
                try:
                    self.service.delete_conversation(conv_id)
                except Exception as exc:
                    self._toast(_friendly_error(exc), DANGER)
                    return
            self._set_screen("conversations")

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Delete conversation?"),
            content=ft.Text(
                "Every message and the ratchet state are crypto-shredded. "
                "This cannot be undone.",
                size=12,
                color=MUTED,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.TextButton("Delete", on_click=delete),
            ],
        )
        self.page.open(dialog)

    # -- security --------------------------------------------------------

    def _render_security(self) -> None:
        self.top_host.controls = [
            self._header("Security", back_to="conversations")
        ]
        rows = security_rows(self.security)

        pins = relay_pins()
        protocol = [
            ("End-to-end encryption", "X25519 + ChaCha20-Poly1305"),
            ("Pairing", "one-time invite + 6-digit SAS"),
            ("Message ratchet", "per-message HMAC-SHA256 chains"),
            ("Forward secrecy", "messages already consumed"),
            ("Post-compromise security", "NOT available (see threat model)"),
            ("Screenshot block", "on" if self.security.secure_screen else "OFF"),
            ("Clipboard copy", "no copy actions in the UI"),
            ("Identity recovery", "none, by design"),
            ("TLS pinning", "embedded SPKI pins" if pins else "NOT configured"),
            ("Relay visibility", "mailbox ids, size, timing; never bodies"),
            ("Lifetime", "24 hours, then crypto-shred"),
        ]
        section = [
            ft.Text("Device", size=11, color=MUTED),
            *rows,
            ft.Container(height=6),
            ft.Text("Protocol", size=11, color=MUTED),
            *[_row(label, value) for label, value in protocol],
            ft.Container(height=6),
            ft.Text(
                "Cipher does not protect against a rooted device, a custom ROM, "
                "a modified APK, an external camera, or an unlocked stolen "
                "device before the TTL fires. The relay can see that two "
                "mailbox ids are active and how large/timing-sensitive the "
                "traffic is.",
                size=10,
                color=MUTED,
            ),
        ]
        self.body.controls = [
            ft.Container(
                expand=True,
                padding=ft.padding.symmetric(horizontal=14, vertical=12),
                content=ft.Column(
                    section, spacing=4, scroll=ft.ScrollMode.AUTO, expand=True
                ),
            )
        ]

    # -- settings --------------------------------------------------------

    def _render_settings(self) -> None:
        self.top_host.controls = [
            self._header("Settings", back_to="conversations")
        ]
        ident = self.security.identity
        relay_host = relay_url().split("://", 1)[-1].split("/", 1)[0]
        rows = [
            _row("Identity storage", self.security.identity_storage),
            _row("Hardware-backed", "yes" if self.security.hardware else "no"),
            _row("StrongBox", "yes" if self.security.strongbox else "no"),
            _row("Screenshots", "blocked" if self.security.secure_screen else "NOT blocked"),
            _row("Protocol", f"v{PROTOCOL_VERSION}"),
            _row("Relay", relay_host),
            _row("TLS pinning", "yes" if relay_pins() else "NOT configured"),
            _row("Relay status", "configured" if self.service else "unavailable"),
            _row("Messages", "24 h ephemeral"),
            ft.Container(height=6),
            ft.Text("Fingerprint", size=10, color=MUTED),
            ft.Text(
                _grouped(ident.key_id) if ident else "unavailable",
                size=10,
                color=TEXT,
                selectable=False,
            ),
            ft.Container(height=12),
            ft.ElevatedButton(
                "Delete everything",
                bgcolor="#3A1114",
                color=DANGER,
                on_click=lambda e: self._confirm_wipe(),
            ),
            ft.Text(
                "Cipher never offers account recovery. Deleting everything "
                "destroys the identity and all keys immediately.",
                size=10,
                color=MUTED,
            ),
        ]
        self.body.controls = [
            ft.Container(
                expand=True,
                padding=ft.padding.symmetric(horizontal=14, vertical=12),
                content=ft.Column(
                    rows, spacing=5, scroll=ft.ScrollMode.AUTO, expand=True
                ),
            )
        ]

    def _confirm_wipe(self) -> None:
        def wipe(e: ft.ControlEvent) -> None:
            self.page.close(dialog)
            if self.service is None:
                self.wiped = True
                self._render()
                return
            try:
                self.service.wipe_all()
            except Exception as exc:
                self._toast(_friendly_error(exc), DANGER)
                return
            self.wiped = True
            self._render()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Delete everything?"),
            content=ft.Text(
                "The identity key, every conversation, message and ratchet "
                "state will be destroyed. There is no recovery.",
                size=12,
                color=MUTED,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.TextButton("Delete everything", on_click=wipe),
            ],
        )
        self.page.open(dialog)

    # -- polling ---------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._poll_stop.is_set():
            try:
                if not self.wiped and self.service is not None:
                    self.service.expire()
                    if self.screen == "pairing":
                        self._pair_tick()
                    else:
                        received = self.service.drain_all()
                        if self.screen == "chat" and self.conv_id is not None:
                            msgs = self.service.messages(self.conv_id)
                            sig = (len(msgs), msgs[-1].msg_id if msgs else b"")
                            if sig != self._msg_sig:
                                self._safe_fill_chat()
                        elif self.screen == "conversations" and received:
                            self._safe_render_conversations()
            except Exception:
                # UI polling must never crash on a transient relay or storage
                # failure.  The next tick retries; no error text is logged.
                pass
            self._poll_stop.wait(1.0 if self.screen == "pairing" else 4.0)

    def _pair_tick(self) -> None:
        if self.service is None or self.pending is not None:
            return
        try:
            if self.invite_session is not None:
                pending = self.service.poll_responder(self.invite_session)
            elif self.join_session is not None:
                pending = self.service.poll_joiner(self.join_session)
            else:
                pending = None
        except Exception as exc:
            self.pair_error = _friendly_error(exc)
            self._cancel_pairing_silently()
            self.invite_session = None
            self.join_session = None
            self._safe_render()
            return
        if pending is not None:
            self.pending = pending
            self._safe_render()
            return
        self._tick_countdown()

    def _tick_countdown(self) -> None:
        session = self.invite_session or self.join_session
        if session is None or self.pair_countdown is None:
            return
        expires = (
            session.invite.expires_at
            if isinstance(session, InviteSession)
            else session.expires_at
        )
        try:
            self.pair_countdown.value = _minutes_left(expires)
            self.pair_countdown.update()
        except Exception:
            pass

    def _safe_fill_chat(self) -> None:
        with self._ui_lock:
            if self.conv_id is None:
                return
            try:
                self._fill_messages(self.conv_id)
                self.page.update()
            except Exception:
                pass

    def _safe_render_conversations(self) -> None:
        with self._ui_lock:
            if self.screen != "conversations":
                return
            try:
                self._render_conversations()
                self.page.update()
            except Exception:
                pass

    def _safe_render(self) -> None:
        with self._ui_lock:
            try:
                self._render()
            except Exception:
                pass

    # -- feedback --------------------------------------------------------

    def _toast(self, message: str, color: str = TEXT) -> None:
        try:
            self.page.open(
                ft.SnackBar(
                    content=ft.Text(message, size=12, color=color),
                    bgcolor=SURFACE_2,
                )
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Small presentational helpers
# ---------------------------------------------------------------------------


def _friendly_error(exc: BaseException) -> str:
    if isinstance(exc, (MessagingError, StorageError, IdentityError, PinMismatch)):
        return str(exc)
    name = exc.__class__.__name__
    if name in {"RelayNotFound"}:
        return "Invite is invalid or already used."
    if name in {"RelayRateLimited"}:
        return "Relay rate limit reached. Try again shortly."
    if name in {"RelayError"}:
        return "Relay is unreachable."
    return "Operation failed. Nothing was sent."


def _center(controls: list[ft.Control]) -> ft.Control:
    return ft.Container(
        expand=True,
        alignment=ft.alignment.center,
        padding=ft.padding.symmetric(horizontal=24, vertical=24),
        content=ft.Column(
            tight=True,
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            controls=controls,
        ),
    )


def _feature(title: str, detail: str) -> ft.Control:
    return ft.Container(
        bgcolor=SURFACE,
        border_radius=10,
        padding=ft.padding.symmetric(horizontal=14, vertical=10),
        content=ft.Column(
            tight=True,
            spacing=2,
            controls=[
                ft.Text(title, size=12, color=TEXT, weight=ft.FontWeight.W_500),
                ft.Text(detail, size=10, color=MUTED),
            ],
        ),
    )


def _notice(text: str, color: str) -> ft.Control:
    return ft.Container(
        bgcolor=SURFACE_2,
        border=ft.border.only(left=ft.BorderSide(3, color)),
        padding=ft.padding.symmetric(horizontal=12, vertical=8),
        content=ft.Text(text, size=9, color=MUTED),
    )


def _tab(label: str, *, active: bool, on_click) -> ft.Control:
    return ft.Container(
        expand=True,
        bgcolor=SURFACE_2 if active else SURFACE,
        border=ft.border.all(1, ACCENT if active else BORDER),
        border_radius=8,
        padding=ft.padding.symmetric(vertical=9),
        on_click=on_click,
        alignment=ft.alignment.center,
        content=ft.Text(
            label,
            size=11,
            color=ACCENT if active else MUTED,
            weight=ft.FontWeight.W_500,
        ),
    )


def _row(label: str, value: str) -> ft.Control:
    return ft.Container(
        bgcolor=SURFACE,
        border_radius=8,
        padding=ft.padding.symmetric(horizontal=12, vertical=9),
        content=ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            spacing=8,
            controls=[
                ft.Text(label, color=MUTED, size=10, expand=True),
                ft.Text(
                    value,
                    color=TEXT,
                    size=10,
                    weight=ft.FontWeight.W_500,
                    text_align=ft.TextAlign.RIGHT,
                ),
            ],
        ),
    )


def _conversation_tile(
    *, peer: str, preview: str, ttl: str, on_click
) -> ft.Control:
    return ft.Container(
        bgcolor=SURFACE,
        border=ft.border.all(1, BORDER),
        border_radius=12,
        padding=ft.padding.symmetric(horizontal=14, vertical=12),
        ink=True,
        on_click=on_click,
        content=ft.Row(
            spacing=12,
            controls=[
                ft.Container(
                    width=40,
                    height=40,
                    border_radius=20,
                    bgcolor=BUBBLE_OUT,
                    alignment=ft.alignment.center,
                    content=ft.Icon(ft.Icons.LOCK_OUTLINE, size=20, color=ACCENT),
                ),
                ft.Column(
                    tight=True,
                    spacing=3,
                    expand=True,
                    controls=[
                        ft.Row(
                            controls=[
                                ft.Text(
                                    f"Peer {peer}",
                                    size=12,
                                    color=TEXT,
                                    weight=ft.FontWeight.W_600,
                                    expand=True,
                                ),
                                ft.Text(ttl, size=9, color=MUTED),
                            ]
                        ),
                        ft.Text(
                            preview,
                            size=10,
                            color=MUTED,
                            max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS,
                        ),
                    ],
                ),
            ],
        ),
    )


def _bubble(plaintext: bytes, *, outgoing: bool, sent_at: int) -> ft.Control:
    text = plaintext.decode("utf-8", "replace")
    stamp = time.strftime("%H:%M", time.localtime(sent_at))
    return ft.Row(
        alignment=ft.MainAxisAlignment.END if outgoing else ft.MainAxisAlignment.START,
        controls=[
            ft.Container(
                bgcolor=BUBBLE_OUT if outgoing else BUBBLE_IN,
                border_radius=ft.border_radius.only(
                    top_left=12,
                    top_right=12,
                    bottom_left=12 if outgoing else 3,
                    bottom_right=3 if outgoing else 12,
                ),
                padding=ft.padding.symmetric(horizontal=12, vertical=8),
                content=ft.Column(
                    tight=True,
                    spacing=3,
                    controls=[
                        ft.Text(text, size=13, color=TEXT, selectable=False),
                        ft.Text(stamp, size=8, color=MUTED),
                    ],
                ),
            )
        ],
    )


def _qr_image(data: str) -> ft.Image:
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return ft.Image(
        src_base64=base64.b64encode(buffer.getvalue()).decode("ascii"),
        width=220,
        height=220,
        fit=ft.ImageFit.CONTAIN,
    )
