from pathlib import Path

from fastapi import FastAPI, UploadFile

app = FastAPI()


@app.post("/upload")
async def upload_document(upload: UploadFile):
    safe_name = Path(upload.filename).name
    destination = approved_storage_path(safe_name)
    await save_to_storage(destination, upload)
    return {"status": "stored"}
