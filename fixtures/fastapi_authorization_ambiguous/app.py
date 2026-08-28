from fastapi import Depends, FastAPI

app = FastAPI()
route_path = "/accounts"


def get_current_user():
    return "authenticated-user"


def dependency_factory():
    return get_current_user


@app.post(route_path)
def dynamic_account(user=Depends(dependency_factory())):
    return {"status": "created"}


class App:
    def post(self, path):
        return lambda function: function


other_app = App()


@other_app.post("/accounts")
def other_account(user=Depends(get_current_user)):
    return {"status": "created"}
