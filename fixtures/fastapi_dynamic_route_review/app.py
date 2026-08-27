from fastapi import Depends, FastAPI

app = FastAPI()
prefix = "/accounts"
methods = ["POST"]


@app.post(prefix)
def create_account():
    return {}


@app.api_route("/reports", methods=methods)
def create_report():
    return {}


@app.get("/healthz", dependencies=[Depends(lambda: None)])
def healthz():
    return {"status": "ok"}
