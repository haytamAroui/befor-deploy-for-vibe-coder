from fastapi import FastAPI

app = FastAPI()
path = "/accounts"


@app.post(path)
def create_account(payload: dict[str, str]):
    return payload


@app.post("/other")
def create_other(payload: PayloadAlias):
    return payload
