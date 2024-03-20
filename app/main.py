from fastapi.middleware.cors import CORSMiddleware
from app import endpoints
from fastapi import FastAPI


app = FastAPI()

origins = [
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(endpoints.router, tags=["hackaton"])

@app.get("/api/healthchecker")
def root():
    return {"message": "The API is LIVE!!"}