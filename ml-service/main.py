from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd

app = FastAPI(title="ML Prediction Service")

class PredictRequest(BaseModel):
    department_id: int
    forecast_horizon_hours: int

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ml-service"}

@app.post("/predict")
def predict_demand(request: PredictRequest):
    # TODO: Query historical data from PostgreSQL
    # TODO: Load pre-trained models (demand, wait time, occupancy)
    # TODO: Run inference
    
    # Mock response
    return {
        "department_id": request.department_id,
        "forecast_time": "2026-09-27T22:00:00Z",
        "predictions": [
            {"target_type": "expected_demand", "predicted_value": 45},
            {"target_type": "expected_wait_time", "predicted_value": 30.5}
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
