import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

__version__ = "1"
app = FastAPI(
    title="Sparq",
    description="Бэкэнд часть sparq",
    version=__version__,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
logger = logging.getLogger("uvicorn.error")
