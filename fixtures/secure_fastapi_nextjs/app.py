from fastapi import Depends, FastAPI
from starlette.middleware.cors import CORSMiddleware

app = FastAPI(debug=False)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.test"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
)


def require_user():
    return {"id": "user-1"}


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}


@app.post("/users")
def create_user(email: str, current_user=Depends(require_user)):
    return {"email": email, "actor": current_user["id"]}


def find_user(cursor, user_id: str):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
