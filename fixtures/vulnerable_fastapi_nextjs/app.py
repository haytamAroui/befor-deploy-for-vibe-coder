from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

DEBUG = True
app = FastAPI(debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)

api_key = "demo-secret-value-only-for-fixture-1234567890"


@app.post("/users")
def create_user(email: str):
    return {"email": email}


def find_user(cursor, user_id: str):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
