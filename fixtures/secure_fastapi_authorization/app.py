from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    return "authenticated-user"


def require_account_owner():
    return "authorized-owner"


@app.post("/accounts")
def create_account(
    user=Depends(get_current_user),
    owner=Depends(require_account_owner),
):
    return {"status": "created"}
