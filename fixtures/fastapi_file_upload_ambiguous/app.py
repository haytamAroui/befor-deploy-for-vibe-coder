from fastapi import FastAPI, UploadFile

app = FastAPI()
route_path = "/upload"


@app.post(route_path)
async def upload_document(upload: UploadFile):
    save_upload(upload.filename)
    return {"status": "stored"}


@app.post("/other")
async def other_upload(upload: UploadFile | None):
    open(upload.filename, "wb")
    return {"status": "stored"}
