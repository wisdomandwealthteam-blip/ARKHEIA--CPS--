from pydantic import BaseModel

class AutoContractIn(BaseModel):
    apr: float
    credit_band: str
    payment_to_income: float
    doc_fee: float
    state: str

class HousingContractIn(BaseModel):
    rent: float
    income: float
    fees: float
    state: str
