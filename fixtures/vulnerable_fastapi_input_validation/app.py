from fastapi import Depends, FastAPI

app = FastAPI()


def current_user():
    return object()


@app.post("/accounts")
def create_account(payload: dict, user=Depends(current_user)):
    return {"received": payload}
