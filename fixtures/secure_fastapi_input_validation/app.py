from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Account(BaseModel):
    name: str


@app.post("/accounts")
def create_account(payload: Account):
    return payload
