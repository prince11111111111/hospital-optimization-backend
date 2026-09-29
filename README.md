# 🏥 Hospital Optimization Platform - Backend

This repository contains the backend infrastructure for the AI-driven Hospital Optimization Platform. It is designed to ingest live hospital data, predict patient demand, and dynamically allocate resources (doctors, beds) to prevent overloading using Machine Learning and Constraint Programming (Google OR-Tools).

🔗 **[Click here to view the Frontend Repository](https://github.com/prince11111111111/hospital-optimization-frontend)**

---

## 🚀 Live Deployments

*   **API Gateway URL**: https://hospital-optimization-backend-api-gateway.onrender.com
*   **ML Prediction Service**: https://hospital-optimization-backend-ml-service.onrender.com
*   **Optimization Service**: https://hospital-optimization-backend-sfwz.onrender.com
*   **Swagger API Documentation**: https://hospital-optimization-backend-api-gateway.onrender.com/docs

---

## 🏗️ Architecture

The backend operates as a three-tier microservice Monorepo:

### 1. API Gateway (`/api-gateway`)
*   **Tech**: Node.js, Express, TypeScript, Prisma, PostgreSQL
*   **Role**: The central nervous system. Handles JWT Authentication, strict Role-Based Access Control (RBAC), data ingestion (walk-in arrivals, queue lengths), CRUD operations for hospital domains, and routing. Exposes all data via a standard REST API.

### 2. ML Prediction Service (`/ml-service`)
*   **Tech**: Python, FastAPI, Pandas, Scikit-Learn
*   **Role**: Reads historical `PatientArrival` data from PostgreSQL, engineers time-based features, and runs Random Forest regressors to forecast expected demand and wait times for specific departments.

### 3. Optimization Service (`/optimization-service`)
*   **Tech**: Python, FastAPI, Google OR-Tools (CP-SAT Solver)
*   **Role**: Ingests ML forecasts and maps them against live constraints (available Beds, Doctor shift availabilities). Uses constraint programming to calculate optimal resource reallocations and returns actionable `Recommendations`.

---

## 🛠️ Local Setup & Installation

### Prerequisites
*   Node.js (v18+)
*   Python (3.10+)
*   PostgreSQL running locally

### 1. Database Setup
```bash
cd api-gateway
# Create a .env file and add your DATABASE_URL
# Example: DATABASE_URL="postgresql://postgres:password@localhost:5432/hospital_db"

npm install
npx prisma db push
```

### 2. Running the API Gateway
```bash
cd api-gateway
npm run dev
# Running on http://localhost:3000
# View Swagger Docs at http://localhost:3000/docs
```

### 3. Running the ML Service
```bash
cd ml-service
python -m venv venv
# Windows: .\venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

### 4. Running the Optimization Service
```bash
cd optimization-service
python -m venv venv
# Windows: .\venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8002
```

---

## 🔒 Security & RBAC
*   **Data Integrity**: Prisma enums lock down states (e.g., `BedStatus: AVAILABLE | OCCUPIED | MAINTENANCE`).
*   **ADMIN Role**: Structural changes (creating departments, hiring doctors, applying ML recommendations) are strictly locked to the `ADMIN` JWT role.
*   **STAFF Role**: Day-to-day workflow actions (booking appointments, updating shift statuses, marking beds for maintenance) are available to all authenticated `STAFF`.

---

## 📜 License
MIT License
