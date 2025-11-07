import asyncio
import base64
import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

import httpx
import websockets

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security.security import aes_decrypt, aes_encrypt

CLIENT_SERVER = "http://localhost:8001"  # client backend
BASE_WS_USER = "ws://localhost:8000/ws"  # connect as /ws/{user_id}


class ClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Client GUI")
        self.shared_key_b64 = None
        self.shared_key = None  # bytes
        self.ws = None
        self.ws_loop = None

        self.build_ui()

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.grid(row=0, column=0)

        # Tabs
        self.tabs = ttk.Notebook(frame)
        self.tab_auth = ttk.Frame(self.tabs)
        self.tab_chat = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_auth, text="Auth / Register")
        self.tabs.add(self.tab_chat, text="Chat")
        self.tabs.grid(row=0, column=0)

        # Auth tab
        ttk.Label(self.tab_auth, text="User ID (numeric)").grid(
            row=0, column=0, sticky="w"
        )
        self.username_entry = ttk.Entry(self.tab_auth)
        self.username_entry.grid(row=0, column=1, sticky="we")

        ttk.Label(self.tab_auth, text="Password").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(self.tab_auth, show="*")
        self.password_entry.grid(row=1, column=1, sticky="we")

        ttk.Label(self.tab_auth, text="Telegram username (no @)").grid(
            row=2, column=0, sticky="w"
        )
        self.tg_username_entry = ttk.Entry(self.tab_auth)
        self.tg_username_entry.grid(row=2, column=1, sticky="we")

        self.register_btn = ttk.Button(
            self.tab_auth, text="Register (base_client)", command=self.on_register
        )
        self.register_btn.grid(row=3, column=0, pady=5)

        self.get_code_btn = ttk.Button(
            self.tab_auth, text="Get Telegram code", command=self.on_get_code
        )
        self.get_code_btn.grid(row=3, column=1, pady=5)

        ttk.Label(self.tab_auth, text="TG code").grid(row=4, column=0, sticky="w")
        self.tg_code_entry = ttk.Entry(self.tab_auth)
        self.tg_code_entry.grid(row=4, column=1, sticky="we")

        self.login_btn = ttk.Button(
            self.tab_auth, text="Authenticate", command=self.on_authenticate
        )
        self.login_btn.grid(row=5, column=0, columnspan=2, pady=6)

        self.auth_log = scrolledtext.ScrolledText(self.tab_auth, height=6)
        self.auth_log.grid(row=6, column=0, columnspan=2, sticky="we")
        self.auth_log.insert(tk.END, "Ready\n")

        # Chat tab
        ttk.Label(self.tab_chat, text="Chat").grid(row=0, column=0, sticky="w")
        self.chat_box = scrolledtext.ScrolledText(self.tab_chat, height=15)
        self.chat_box.grid(row=1, column=0, columnspan=2)

        self.msg_entry = ttk.Entry(self.tab_chat, width=50)
        self.msg_entry.grid(row=2, column=0, sticky="we")
        self.send_btn = ttk.Button(self.tab_chat, text="Send", command=self.on_send)
        self.send_btn.grid(row=2, column=1, sticky="e")

        # disable chat until authenticated
        self.tabs.tab(1, state="disabled")

    def log(self, text):
        def _insert():
            self.auth_log.insert(tk.END, text + "\n")
            self.auth_log.see(tk.END)

        self.root.after(0, _insert)

    def on_register(self):
        user_id = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        tg_un = self.tg_username_entry.get().strip()
        if not user_id or not password or not tg_un:
            messagebox.showerror("Error", "Fill user_id/password/tg")
            return

        async def _reg():
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    "http://localhost:8000/register",
                    json={
                        "username": user_id,
                        "password": password,
                        "telegram_username": tg_un,
                    },
                )
                if r.status_code == 200:
                    self.log("Registered")
                else:
                    self.log(f"Reg failed: {r.text}")

        asyncio.run(_reg())

    def on_get_code(self):
        user_id = self.username_entry.get().strip()
        if not user_id:
            messagebox.showerror("Error", "Enter user id")
            return

        async def _get():
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{CLIENT_SERVER}/create_challenge", json={"username": user_id}
                )
                if r.status_code == 200:
                    self.log("Challenge requested; check Telegram")
                else:
                    self.log(f"Challenge failed: {r.text}")

        asyncio.run(_get())

    def on_authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        tg_code = self.tg_code_entry.get().strip()
        if not username or not password or not tg_code:
            messagebox.showerror("Error", "Fill fields")
            return

        async def _auth():
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{CLIENT_SERVER}/authenticate",
                    json={
                        "username": username,
                        "password": password,
                        "tg_code": tg_code,
                    },
                )
                if r.status_code == 200:
                    data = r.json()
                    shared_key_b64 = data.get("shared_key")
                    user_id = data.get("user_id")
                    if shared_key_b64:
                        self.shared_key_b64 = shared_key_b64
                        self.shared_key = base64.b64decode(shared_key_b64)
                        self.user_id = user_id
                        self.log("Authenticated & DH complete. Key obtained.")
                        # enable chat tab and open ws
                        self.tabs.tab(1, state="normal")
                        # start ws thread
                        t = threading.Thread(
                            target=self.start_ws_loop, args=(user_id,), daemon=True
                        )
                        t.start()
                    else:
                        self.log("No shared key in response")
                else:
                    self.log(f"Auth failed: {r.text}")

        asyncio.run(_auth())

    def start_ws_loop(self, user_id):
        # create new event loop for background websocket
        self.ws_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.ws_loop)
        self.ws_loop.run_until_complete(self.ws_main(user_id))

    async def ws_main(self, user_id):
        uri = f"{BASE_WS_USER}/{user_id}"
        try:
            async with websockets.connect(uri) as ws:
                self.ws = ws
                self.log("Connected to WS")
                async for msg in ws:
                    try:
                        plaintext = aes_decrypt(msg, self.shared_key)
                        self.append_chat("admin", plaintext)
                    except Exception as e:
                        self.log(f"decrypt error: {e}")
        except Exception as e:
            self.log(f"WS closed: {e}")

    def append_chat(self, sender, text):
        def _append():
            self.chat_box.insert(tk.END, f"{sender}: {text}\n")
            self.chat_box.see(tk.END)

        self.root.after(0, _append)

    def on_send(self):
        text = self.msg_entry.get().strip()
        if not text or not self.shared_key or not self.ws:
            return

        enc = aes_encrypt(text, self.shared_key)  # returns base64 string

        # send using existing ws via background loop
        async def _send():
            try:
                await self.ws.send(enc)
            except Exception as e:
                self.log(f"Send error: {e}")

        # schedule coroutine on ws_loop
        asyncio.run_coroutine_threadsafe(_send(), self.ws_loop)

        self.append_chat("me", text)
        self.msg_entry.delete(0, tk.END)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    gui = ClientGUI()
    gui.run()
