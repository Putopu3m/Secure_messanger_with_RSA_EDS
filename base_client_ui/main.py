import asyncio
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, simpledialog

import httpx
import websockets

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_WS_ADMIN = "ws://localhost:8000/ws/0"
BASE_HTTP = "http://localhost:8000"


class AdminGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BaseClient Admin")
        self.users = []
        self.open_chats = {}
        self.chat_histories = {}

        self.setup_ui()

        self.ws = None
        self.loop = asyncio.new_event_loop()
        t = threading.Thread(target=self.start_ws_loop, daemon=True)
        t.start()

    def setup_ui(self):
        mainframe = ttk.Frame(self.root, padding="12")
        mainframe.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        label = ttk.Label(mainframe, text="Online users")
        label.grid(row=0, column=0, sticky="w")

        self.lb = tk.Listbox(mainframe, height=15)
        self.lb.grid(row=1, column=0, sticky="nsew")
        self.lb.bind("<Double-Button-1>", self.on_user_double)

        self.log = scrolledtext.ScrolledText(mainframe, height=8)
        self.log.grid(row=2, column=0, sticky="nsew")
        self.log.insert(tk.END, "Admin GUI started\n")

        # Создание голосования
        self.create_poll_btn = ttk.Button(mainframe, text="Create Poll", command=self.on_create_poll)
        self.create_poll_btn.grid(row=0, column=1)
        self.tally_poll_btn = ttk.Button(mainframe, text="Tally Selected", command=self.on_tally)
        self.tally_poll_btn.grid(row=1, column=1)

    def on_create_poll(self):
        topic = simpledialog.askstring("Create poll", "Topic:")
        if not topic: return
        async def _create():
            async with httpx.AsyncClient() as client:
                r = await client.post(f"{BASE_HTTP}/polls/create", json={"topic": topic})
                if r.status_code == 200:
                    self.log_insert("Poll created")
                else:
                    self.log_insert(f"Create failed: {r.text}")
        asyncio.run_coroutine_threadsafe(_create(), self.loop)

    def on_tally(self):
        # sel = self.lb.curselection()
        # if not sel: 
        #     messagebox.showerror("Error","Select user to know poll? (Or implement poll list UI)")
        #     return
        # For simplicity, ask poll_id
        pid = simpledialog.askinteger("Tally", "Poll id:")
        if not pid: return
        async def _tally():
            async with httpx.AsyncClient() as client:
                r = await client.post(f"{BASE_HTTP}/polls/{pid}/tally")
                if r.status_code == 200:
                    self.log_insert(f"Tallied: {r.json()}")
                else:
                    self.log_insert(f"Tally failed: {r.text}")
        asyncio.run_coroutine_threadsafe(_tally(), self.loop)

    def on_user_double(self, event=None):
        sel = self.lb.curselection()
        if not sel:
            return
        username = self.lb.get(sel[0])
        if username not in self.open_chats:
            cw = ChatWindow(self, username, self.ws, self.loop)
            self.open_chats[username] = cw
        else:
            self.open_chats[username].show()

    def start_ws_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.ws_main())

    async def ws_main(self):
        try:
            async with websockets.connect(BASE_WS_ADMIN) as ws:
                self.ws = ws
                self.log_insert("Connected to base_client admin WS")
                async for raw in ws:
                    try:
                        data = json.loads(raw)
                    except Exception:
                        self.log_insert(f"Received non-json message: {raw}")
                        continue
                    await self.handle_event(data)
        except Exception as e:
            self.log_insert(f"Admin WS disconnected: {e}")
            await asyncio.sleep(3)
            await self.ws_main()

    async def handle_event(self, data: dict):
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception as e:
                self.log_insert(f"Received raw: {data} - Error: {e}")
                return

        t = data.get("type")
        if t == "users_list":
            users = data.get("users", [])
            self.set_users(users)
        elif t == "user_joined":
            username = data.get("username")
            self.add_user(username)
            self.log_insert(f"{username} joined")
        elif t == "user_left":
            username = data.get("username")
            self.remove_user(username)
            self.log_insert(f"{username} left")
        elif t == "message":
            fr = data.get("from")
            txt = data.get("text")
            user = data.get("user", fr)
            self.chat_histories.setdefault(user, []).append((fr, txt))
            self.log_insert(f"[{fr}] {txt}")
            if fr in self.open_chats:
                self.open_chats[fr].append_message(fr, txt)
        else:
            self.log_insert(f"Unknown event: {data}")

    def set_users(self, users):
        self.users = users
        self.lb.delete(0, tk.END)
        for u in users:
            self.lb.insert(tk.END, u)

    def add_user(self, username):
        if username not in self.users:
            self.users.append(username)
            self.lb.insert(tk.END, username)

    def remove_user(self, username):
        if username in self.users:
            idx = self.users.index(username)
            self.lb.delete(idx)
            self.users.remove(username)

    def log_insert(self, text):
        def _insert():
            self.log.insert(tk.END, text + "\n")
            self.log.see(tk.END)

        self.root.after(0, _insert)

    def run(self):
        self.root.mainloop()


class ChatWindow:
    def __init__(self, parent: AdminGUI, username: str, ws, loop):
        self.parent = parent
        self.username = username
        self.ws = ws
        self.loop = loop
        self.win = tk.Toplevel(parent.root)
        self.win.title(f"Chat with {username}")
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)
        # messages area
        self.txt = scrolledtext.ScrolledText(self.win, width=60, height=20)
        self.txt.grid(row=0, column=0, columnspan=2)
        # entry
        self.entry = ttk.Entry(self.win, width=50)
        self.entry.grid(row=1, column=0, sticky="we")
        self.send_btn = ttk.Button(self.win, text="Send", command=self.on_send)
        self.send_btn.grid(row=1, column=1, sticky="e")
        self.shared_key = None
        self.load_history()

    def load_history(self):
        history = self.parent.chat_histories.get(self.username, [])
        for fr, txt in history:
            self.append_message(fr, txt)

    def append_message(self, sender: str, text: str):
        def _append():
            self.txt.insert(tk.END, f"{sender}: {text}\n")
            self.txt.see(tk.END)

        self.win.after(0, _append)

    def on_send(self):
        text = self.entry.get().strip()
        if not text:
            return

        async def _send():
            async with httpx.AsyncClient() as client:
                try:
                    r = await client.post(
                        f"{BASE_HTTP}/send_to_user",
                        json={"user_id": self.username, "text": text},
                    )
                    if r.status_code == 200:
                        self.parent.chat_histories.setdefault(self.username, []).append(
                            ("admin", text)
                        )
                        self.append_message("admin", text)
                        self.entry.delete(0, tk.END)
                    else:
                        self.append_message("error", f"Send failed: {r.text}")
                except Exception as e:
                    self.append_message("error", f"HTTP error: {e}")

        asyncio.run_coroutine_threadsafe(_send(), self.loop)

    def show(self):
        self.win.deiconify()

    def on_close(self):
        self.win.destroy()
        if self.username in self.parent.open_chats:
            del self.parent.open_chats[self.username]


if __name__ == "__main__":
    gui = AdminGUI()
    gui.run()
