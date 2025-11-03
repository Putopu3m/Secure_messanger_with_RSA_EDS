from fastapi import FastAPI

from client.app.api.router_api import router as router_api

app = FastAPI()


app.include_router(router_api)
