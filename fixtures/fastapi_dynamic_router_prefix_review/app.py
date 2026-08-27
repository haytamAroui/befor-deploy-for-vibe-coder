from fastapi import APIRouter

api_prefix = "/api/v1"
router = APIRouter(prefix=api_prefix)


@router.post("/accounts")
def create_account():
    return {}
