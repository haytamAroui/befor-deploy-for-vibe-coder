from fastapi import FastAPI, UploadFile

app = FastAPI()


@app.post("/upload")
async def upload_document(upload: UploadFile):
    with open(upload.filename, "wb") as destination:
        destination.write(await upload.read())
    return {"status": "stored"}
