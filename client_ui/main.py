"""
Client UI for user signup using Flet framework.
Sends registration data to the FastAPI backend.
"""

import flet as ft
import httpx
from flet import (
    Column,
    ControlEvent,
    ElevatedButton,
    Text,
    TextField,
)


def main(page: ft.Page) -> None:
    page.title = "Signup"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.LIGHT
    page.window_width = 400
    page.window_height = 400
    page.window_resizable = False

    text_username: TextField = TextField(
        label="Username", text_align=ft.TextAlign.LEFT, width=200
    )
    text_password: TextField = TextField(
        label="Password", text_align=ft.TextAlign.LEFT, width=200, password=True
    )
    text_tg_login: TextField = TextField(
        label="Telegram Username", text_align=ft.TextAlign.LEFT, width=200
    )
    button_submit: ElevatedButton = ElevatedButton(
        text="Submit", width=200, disabled=True
    )

    def validate(e: ControlEvent):
        if text_username.value and text_password.value and text_tg_login.value:
            button_submit.disabled = False
        else:
            button_submit.disabled = True
        page.update()

    async def submit(e: ControlEvent):
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "http://localhost:8000/register",
                    json={
                        "username": text_username.value,
                        "password": text_password.value,
                        "telegram_username": text_tg_login.value,
                    },
                )
            except httpx.RequestError as exc:
                page.add(
                    Text(f"An error occurred while requesting {exc.request.url!r}.")
                )
                return
            except httpx.HTTPStatusError as exc:
                page.add(
                    Text(
                        f"Error response {exc.response.status_code} while requesting {exc.request.url!r}."
                    )
                )
                return
            else:
                if response.status_code == 200:
                    page.add(
                        Text(
                            "Registration successful! Check your Telegram for the code."
                        )
                    )
                else:
                    page.add(
                        Text(f"Error: {response.json().get('detail', 'Unknown error')}")
                    )
                    return
        page.clean()

    text_username.on_change = validate
    text_password.on_change = validate
    text_tg_login.on_change = validate
    button_submit.on_click = submit

    page.add(
        Column(controls=[text_username, text_password, text_tg_login, button_submit])
    )


if __name__ == "__main__":
    ft.app(target=main)
