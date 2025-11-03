from fastapi import FastAPI

from base_client.app.api.router_api import router as router_api
from base_client.app.api.router_ws import router as router_ws

app = FastAPI()

app.include_router(router_api)
app.include_router(router_ws)
