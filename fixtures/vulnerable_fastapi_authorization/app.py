from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    return "authenticated-user"


@app.post("/accounts")
def create_account(user=Depends(get_current_user)):
    return {"status": "created"}
