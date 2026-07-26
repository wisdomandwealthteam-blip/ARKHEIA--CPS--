from pydantic import BaseModel


class AutoContractIn(BaseModel):
    vin: str
    driver_age: int
    vehicle_value: float


class HousingContractIn(BaseModel):
    address: str
    square_feet: int
    year_built: int
