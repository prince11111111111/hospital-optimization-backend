import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const app: Express = express();

app.use(cors());
app.use(express.json());

// Swagger setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Hospital Resource Optimization API',
      version: '1.0.0',
      description: 'API Gateway for the Hospital Optimization System',
    },
    servers: [
      {
        url: 'http://localhost:3000',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/app.ts'], // Tells Swagger where to look for annotations
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
// Serve the Swagger UI at the /docs route
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Check API Health
 *     responses:
 *       200:
 *         description: The API is running correctly
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'hospital-optimization-api' });
});

/**
 * @swagger
 * /api/v1/auth/signup:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: admin@hospital.com
 *               password:
 *                 type: string
 *                 example: mysecurepassword
 *               role:
 *                 type: string
 *                 example: admin
 *     responses:
 *       201:
 *         description: User created successfully
 *       400:
 *         description: User already exists
 */
app.post('/api/v1/auth/signup', async (req: Request, res: Response) => {
  try {
    // SECURITY SAFEGUARD: Only allow open signup if ZERO users exist in the database.
    const userCount = await prisma.user.count();
    if (userCount > 0) {
      return res.status(403).json({ error: 'System is already initialized. Additional admins must be created internally.' });
    }

    const { email, password, role } = req.body;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: {
        email,
        password_hash,
        role: 'ADMIN' // Force the first user to be the master ADMIN
      }
    });

    res.status(201).json({ message: 'User created successfully', userId: user.id });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== AUTH ENDPOINTS ====================

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-me';

const requireRole = (role: string) => {
  return (req: Request, res: Response, next: express.NextFunction) => {
    const userRole = (req as any).user?.role;
    if (userRole !== role) {
      return res.status(403).json({ error: `Forbidden: requires ${role} role` });
    }
    next();
  };
};

// Middleware to verify JWT
const authenticateToken = (req: Request, res: Response, next: express.NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    (req as any).user = user;
    next();
  });
};

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Authenticate admin and issue JWT
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful, JWT issued
 *       401:
 *         description: Invalid credentials
 */
app.post('/api/v1/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

    // Issue JWT
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
    
    res.json({ message: 'Login successful', token, role: user.role });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: End session
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
app.post('/api/v1/auth/logout', (req: Request, res: Response) => {
  // In a stateless JWT setup, logout is handled client-side by deleting the token.
  res.json({ message: 'Logged out successfully (Please remove token from client)' });
});

/**
 * @swagger
 * /api/v1/auth/me:
 *   get:
 *     summary: Return current logged-in user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user details
 *       401:
 *         description: Access denied
 */
app.get('/api/v1/auth/me', authenticateToken, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.id;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({ id: user.id, email: user.email, role: user.role });
  } catch (error) {
    console.error('Error fetching current user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/dashboard:
 *   get:
 *     summary: Fetch Dashboard Summary
 *     responses:
 *       200:
 *         description: Returns lists of departments, active alerts, and queue states
 */
app.get('/api/v1/dashboard', async (req: Request, res: Response) => {
  try {
    const departments = await prisma.department.findMany({
      include: {
        queues: { orderBy: { timestamp: 'desc' }, take: 1 },
        alerts: { where: { status: 'ACTIVE' } }
      }
    });
    res.json({ data: departments });
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== PATIENTS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/patients:
 *   get:
 *     summary: List all patients
 *     responses:
 *       200:
 *         description: A list of patients
 */
app.get('/api/v1/patients', async (req: Request, res: Response) => {
  try {
    const patients = await prisma.patient.findMany();
    res.json({ data: patients });
  } catch (error) {
    console.error('Error fetching patients:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/patients/{id}:
 *   get:
 *     summary: Get a single patient by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Patient details
 *       404:
 *         description: Patient not found
 */
app.get('/api/v1/patients/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const patient = await prisma.patient.findUnique({ where: { id } });
    if (!patient) return res.status(404).json({ error: 'Patient not found' });
    res.json({ data: patient });
  } catch (error) {
    console.error('Error fetching patient:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/patients:
 *   post:
 *     summary: Register a new patient
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               contact_info:
 *                 type: string
 *     responses:
 *       201:
 *         description: Patient created
 */
app.post('/api/v1/patients', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { name, contact_info } = req.body;
    const patient = await prisma.patient.create({
      data: { name, contact_info }
    });
    res.status(201).json({ message: 'Patient created', data: patient });
  } catch (error) {
    console.error('Error creating patient:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/patients/{id}:
 *   put:
 *     summary: Update patient info
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               contact_info:
 *                 type: string
 *     responses:
 *       200:
 *         description: Patient updated
 */
app.put('/api/v1/patients/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { name, contact_info } = req.body;
    const patient = await prisma.patient.update({
      where: { id },
      data: { name, contact_info }
    });
    res.json({ message: 'Patient updated', data: patient });
  } catch (error) {
    console.error('Error updating patient:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/patients/{id}:
 *   delete:
 *     summary: Remove a patient record
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Patient deleted
 */
app.delete('/api/v1/patients/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.patient.delete({ where: { id } });
    res.json({ message: 'Patient deleted successfully' });
  } catch (error) {
    console.error('Error deleting patient:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== USERS (ADMIN MANAGEMENT) ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/users:
 *   get:
 *     summary: List all users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of users
 */
app.get('/api/v1/users', authenticateToken, async (req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, role: true } // Explicitly exclude password_hash
    });
    res.json({ data: users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/users:
 *   post:
 *     summary: Create a new user (Admin use)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *     responses:
 *       201:
 *         description: User created
 */
app.post('/api/v1/users', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { email, password, role } = req.body;
    
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: { email, password_hash, role: role || 'admin' },
      select: { id: true, email: true, role: true }
    });

    res.status(201).json({ message: 'User created', data: user });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/users/{id}:
 *   put:
 *     summary: Update user info (role or password reset)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated
 */
app.put('/api/v1/users/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { role, password } = req.body;
    
    const updateData: any = {};
    if (role) updateData.role = role;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      updateData.password_hash = await bcrypt.hash(password, salt);
    }

    const user = await prisma.user.update({
      where: { id },
      data: updateData,
      select: { id: true, email: true, role: true }
    });

    res.json({ message: 'User updated', data: user });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/users/{id}:
 *   delete:
 *     summary: Remove a user
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User deleted
 */
app.delete('/api/v1/users/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.user.delete({ where: { id } });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== DEPARTMENTS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/departments:
 *   get:
 *     summary: List all departments with current load summary
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of departments with queue and bed status
 */
app.get('/api/v1/departments', authenticateToken, async (req: Request, res: Response) => {
  try {
    const departments = await prisma.department.findMany({
      include: {
        queues: { orderBy: { timestamp: 'desc' }, take: 1 },
        beds: true
      }
    });
    
    // Calculate load summary for each department
    const summary = departments.map(dept => {
      const totalBeds = dept.beds.length;
      const occupiedBeds = dept.beds.filter(b => b.status === 'OCCUPIED').length;
      const currentQueue = dept.queues.length > 0 ? dept.queues[0].queue_length : 0;
      
      return {
        ...dept,
        load_summary: {
          totalBeds,
          occupiedBeds,
          occupancyRate: totalBeds > 0 ? (occupiedBeds / totalBeds) * 100 : 0,
          currentQueue
        }
      };
    });
    
    res.json({ data: summary });
  } catch (error) {
    console.error('Error fetching departments:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/departments/{id}:
 *   get:
 *     summary: Get single department detail
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Department details
 */
app.get('/api/v1/departments/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const department = await prisma.department.findUnique({
      where: { id },
      include: { beds: true, alerts: { where: { status: 'ACTIVE' } } }
    });
    if (!department) return res.status(404).json({ error: 'Department not found' });
    res.json({ data: department });
  } catch (error) {
    console.error('Error fetching department:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/departments:
 *   post:
 *     summary: Create a new department
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               capacity_thresholds:
 *                 type: object
 *     responses:
 *       201:
 *         description: Department created
 */
app.post('/api/v1/departments', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { name, capacity_thresholds } = req.body;
    const department = await prisma.department.create({
      data: { name, capacity_thresholds: capacity_thresholds || {} }
    });
    res.status(201).json({ message: 'Department created', data: department });
  } catch (error) {
    console.error('Error creating department:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/departments/{id}:
 *   put:
 *     summary: Update capacity thresholds/config
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               capacity_thresholds:
 *                 type: object
 *     responses:
 *       200:
 *         description: Department updated
 */
app.put('/api/v1/departments/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { name, capacity_thresholds } = req.body;
    
    const updateData: any = {};
    if (name) updateData.name = name;
    if (capacity_thresholds) updateData.capacity_thresholds = capacity_thresholds;

    const department = await prisma.department.update({
      where: { id },
      data: updateData
    });
    res.json({ message: 'Department updated', data: department });
  } catch (error) {
    console.error('Error updating department:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/departments/{id}:
 *   delete:
 *     summary: Remove department
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Department deleted
 */
app.delete('/api/v1/departments/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.department.delete({ where: { id } });
    res.json({ message: 'Department deleted successfully' });
  } catch (error) {
    console.error('Error deleting department:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/departments/{id}/forecast:
 *   get:
 *     summary: Get predicted demand/wait/occupancy for a time window
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: query
 *         name: horizon
 *         schema:
 *           type: string
 *         description: e.g., '1h', '24h'
 *     responses:
 *       200:
 *         description: Forecast data
 */
app.get('/api/v1/departments/:id/forecast', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const horizon = req.query.horizon || '24h';
    
    // Fetch predictions generated by the ML service stored in DB
    const predictions = await prisma.prediction.findMany({
      where: { id },
      orderBy: { forecast_time: 'asc' }
    });
    
    res.json({ data: predictions, horizon });
  } catch (error) {
    console.error('Error fetching forecasts:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== DOCTORS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/doctors:
 *   get:
 *     summary: List all doctors
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of doctors
 */
app.get('/api/v1/doctors', authenticateToken, async (req: Request, res: Response) => {
  try {
    const doctors = await prisma.doctor.findMany();
    res.json({ data: doctors });
  } catch (error) {
    console.error('Error fetching doctors:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/availability:
 *   get:
 *     summary: Query availability/shifts
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: date
 *         schema:
 *           type: string
 *         description: YYYY-MM-DD
 *     responses:
 *       200:
 *         description: Availability results
 */
app.get('/api/v1/doctors/availability', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const dateStr = req.query.date as string;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    if (dateStr) {
      const startDate = new Date(dateStr);
      const endDate = new Date(dateStr);
      endDate.setDate(endDate.getDate() + 1);
      
      whereClause.start_time = {
        gte: startDate,
        lt: endDate
      };
    }
    
    const availability = await prisma.doctorAvailability.findMany({
      where: whereClause,
      include: { doctor: true }
    });
    
    res.json({ data: availability });
  } catch (error) {
    console.error('Error fetching availability:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/{id}:
 *   get:
 *     summary: Get single doctor detail
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Doctor details
 */
app.get('/api/v1/doctors/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const doctor = await prisma.doctor.findUnique({
      where: { id },
      include: { availabilities: true }
    });
    if (!doctor) return res.status(404).json({ error: 'Doctor not found' });
    res.json({ data: doctor });
  } catch (error) {
    console.error('Error fetching doctor:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors:
 *   post:
 *     summary: Add a new doctor
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               specialty:
 *                 type: string
 *               department_id:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Doctor created
 */
app.post('/api/v1/doctors', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { name, specialty, department_id } = req.body;
    
    if (!department_id) {
      return res.status(400).json({ error: 'department_id is required' });
    }
    
    const doctor = await prisma.doctor.create({
      data: { name, specialty, department_id }
    });
    res.status(201).json({ message: 'Doctor created', data: doctor });
  } catch (error) {
    console.error('Error creating doctor:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/{id}:
 *   put:
 *     summary: Update doctor info
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               specialty:
 *                 type: string
 *               department_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Doctor updated
 */
app.put('/api/v1/doctors/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { name, specialty, department_id } = req.body;
    
    const updateData: any = {};
    if (name) updateData.name = name;
    if (specialty) updateData.specialty = specialty;
    if (department_id) updateData.department_id = department_id;

    const doctor = await prisma.doctor.update({
      where: { id },
      data: updateData
    });
    res.json({ message: 'Doctor updated', data: doctor });
  } catch (error) {
    console.error('Error updating doctor:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/{id}:
 *   delete:
 *     summary: Remove doctor
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Doctor deleted
 */
app.delete('/api/v1/doctors/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.doctor.delete({ where: { id } });
    res.json({ message: 'Doctor deleted successfully' });
  } catch (error) {
    console.error('Error deleting doctor:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/{id}/appointments:
 *   get:
 *     summary: A doctor's booked appointments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Doctor appointments
 */
app.get('/api/v1/doctors/:id/appointments', authenticateToken, async (req: Request, res: Response) => {
  try {
    const doctor_id = parseInt(req.params.id);
    const appointments = await prisma.appointment.findMany({
      where: { doctor_id },
      include: { patient: true, department: true },
      orderBy: { datetime: 'asc' }
    });
    res.json({ data: appointments });
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/doctors/{id}/availability:
 *   put:
 *     summary: Update doctor availability
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               department_id:
 *                 type: integer
 *               start_time:
 *                 type: string
 *                 format: date-time
 *               end_time:
 *                 type: string
 *                 format: date-time
 *               availability:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Availability logged
 */
app.put('/api/v1/doctors/:id/availability', authenticateToken, async (req: Request, res: Response) => {
  try {
    const doctor_id = parseInt(req.params.id);
    const { department_id, start_time, end_time, availability } = req.body;
    
    // Create an availability block in the database
    const newAvail = await prisma.doctorAvailability.create({
      data: {
        doctor_id,
        department_id,
        shift: 'custom', // To be deprecated later
        start_time: new Date(start_time),
        end_time: new Date(end_time),
        availability: availability !== undefined ? availability : true
      }
    });
    
    res.status(201).json({ message: 'Availability logged', data: newAvail });
  } catch (error) {
    console.error('Error updating availability:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== BEDS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/beds:
 *   get:
 *     summary: List beds and status
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *         description: Optional department filter
 *     responses:
 *       200:
 *         description: A list of beds
 */
app.get('/api/v1/beds', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    
    const beds = await prisma.bed.findMany({
      where: whereClause,
      include: { department: true }
    });
    
    res.json({ data: beds });
  } catch (error) {
    console.error('Error fetching beds:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/beds:
 *   post:
 *     summary: Add a new bed
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               department_id:
 *                 type: integer
 *               status:
 *                 type: string
 *                 example: AVAILABLE
 *     responses:
 *       201:
 *         description: Bed created
 */
app.post('/api/v1/beds', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { department_id, status } = req.body;
    const bed = await prisma.bed.create({
      data: { department_id, status: status || 'AVAILABLE' }
    });
    res.status(201).json({ message: 'Bed created', data: bed });
  } catch (error) {
    console.error('Error creating bed:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/beds/{id}:
 *   put:
 *     summary: Update bed status
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 example: OCCUPIED
 *               department_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Bed updated
 */
app.put('/api/v1/beds/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { status, department_id } = req.body;
    
    const updateData: any = {};
    if (status) updateData.status = status;
    if (department_id) updateData.department_id = department_id;

    const bed = await prisma.bed.update({
      where: { id },
      data: updateData
    });
    res.json({ message: 'Bed updated', data: bed });
  } catch (error) {
    console.error('Error updating bed:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/beds/{id}:
 *   delete:
 *     summary: Remove bed
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Bed deleted
 */
app.delete('/api/v1/beds/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.bed.delete({ where: { id } });
    res.json({ message: 'Bed deleted successfully' });
  } catch (error) {
    console.error('Error deleting bed:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== ARRIVALS & QUEUE ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/arrivals:
 *   get:
 *     summary: Query arrival history
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: start_date
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: end_date
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Pagination limit (default 100)
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *         description: Pagination offset (default 0)
 *     responses:
 *       200:
 *         description: Arrival history
 */
app.get('/api/v1/arrivals', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const start_date = req.query.start_date as string;
    const end_date = req.query.end_date as string;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    if (start_date || end_date) {
      whereClause.timestamp = {};
      if (start_date) whereClause.timestamp.gte = new Date(start_date);
      if (end_date) whereClause.timestamp.lte = new Date(end_date);
    }
    
    const arrivals = await prisma.patientArrival.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
      take: limit,
      skip: offset
    });
    
    res.json({ data: arrivals });
  } catch (error) {
    console.error('Error fetching arrivals:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/arrivals:
 *   post:
 *     summary: Log a new patient arrival (supports single or array for bulk)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               department_id:
 *                 type: integer
 *               category:
 *                 type: string
 *               timestamp:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       201:
 *         description: Arrival logged
 */
app.post('/api/v1/arrivals', authenticateToken, async (req: Request, res: Response) => {
  try {
    // Check if it's bulk ingestion (array) or single object
    const data = Array.isArray(req.body) ? req.body : [req.body];
    
    const arrivalsData = data.map((item: any) => ({
      department_id: item.department_id,
      category: item.category || 'walk-in',
      timestamp: item.timestamp ? new Date(item.timestamp) : undefined // undefined lets Prisma use @default(now())
    }));

    const result = await prisma.patientArrival.createMany({
      data: arrivalsData
    });
    
    res.status(201).json({ message: `${result.count} arrival(s) logged successfully` });
  } catch (error) {
    console.error('Error logging arrival:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/queue:
 *   get:
 *     summary: Current queue length per department
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Queue logs
 */
app.get('/api/v1/queue', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    
    // Fetch the latest queue logs
    const queues = await prisma.queue.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
      take: limit,
      skip: offset
    });
    
    res.json({ data: queues });
  } catch (error) {
    console.error('Error fetching queue:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/queue:
 *   post:
 *     summary: Update/log queue length
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               department_id:
 *                 type: integer
 *               queue_length:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Queue logged
 */
app.post('/api/v1/queue', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { department_id, queue_length } = req.body;
    
    const queueLog = await prisma.queue.create({
      data: {
        department_id,
        queue_length
      }
    });
    
    res.status(201).json({ message: 'Queue logged', data: queueLog });
  } catch (error) {
    console.error('Error logging queue:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== ALERTS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/alerts:
 *   get:
 *     summary: List active/past alerts
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *         description: e.g. ACTIVE or ACKNOWLEDGED
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Pagination limit (default 100)
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *         description: Pagination offset (default 0)
 *     responses:
 *       200:
 *         description: List of alerts
 */
app.get('/api/v1/alerts', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const status = req.query.status as string;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    if (status) whereClause.status = status.toUpperCase();
    
    const alerts = await prisma.alert.findMany({
      where: whereClause,
      include: { department: true },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset
    });
    
    res.json({ data: alerts });
  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/alerts/{id}:
 *   get:
 *     summary: Get a specific alert
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Alert details
 *       404:
 *         description: Alert not found
 */
app.get('/api/v1/alerts/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const alert = await prisma.alert.findUnique({
      where: { id },
      include: { department: true }
    });
    
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    
    res.json({ data: alert });
  } catch (error) {
    console.error('Error fetching alert:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/alerts/{id}/acknowledge:
 *   post:
 *     summary: Mark alert as seen/handled
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Alert acknowledged
 */
app.post('/api/v1/alerts/:id/acknowledge', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    const alert = await prisma.alert.update({
      where: { id },
      data: { status: 'ACKNOWLEDGED' }
    });
    
    res.json({ message: 'Alert acknowledged', data: alert });
  } catch (error) {
    console.error('Error acknowledging alert:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== APPOINTMENTS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/appointments:
 *   get:
 *     summary: List appointments (filterable)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: date
 *         schema:
 *           type: string
 *           description: YYYY-MM-DD
 *       - in: query
 *         name: patient_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: doctor_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Pagination limit (default 100)
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *         description: Pagination offset (default 0)
 *     responses:
 *       200:
 *         description: A list of appointments
 */
app.get('/api/v1/appointments', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const patient_id = req.query.patient_id ? parseInt(req.query.patient_id as string) : undefined;
    const doctor_id = req.query.doctor_id ? parseInt(req.query.doctor_id as string) : undefined;
    const dateStr = req.query.date as string;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    if (patient_id) whereClause.patient_id = patient_id;
    if (doctor_id) whereClause.doctor_id = doctor_id;
    if (dateStr) {
      const startDate = new Date(dateStr);
      const endDate = new Date(dateStr);
      endDate.setDate(endDate.getDate() + 1);
      
      whereClause.datetime = {
        gte: startDate,
        lt: endDate
      };
    }
    
    const appointments = await prisma.appointment.findMany({
      where: whereClause,
      include: { patient: true, doctor: true, department: true },
      orderBy: { datetime: 'asc' },
      take: limit,
      skip: offset
    });
    
    res.json({ data: appointments });
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/appointments:
 *   post:
 *     summary: Create appointment
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               datetime:
 *                 type: string
 *                 format: date-time
 *               department_id:
 *                 type: integer
 *               patient_id:
 *                 type: integer
 *               doctor_id:
 *                 type: integer
 *               slot:
 *                 type: string
 *               status:
 *                 type: string
 *                 example: SCHEDULED
 *     responses:
 *       201:
 *         description: Appointment created
 */
app.post('/api/v1/appointments', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { datetime, department_id, patient_id, doctor_id, slot, status } = req.body;
    
    if (!doctor_id) {
      return res.status(400).json({ error: 'doctor_id is required' });
    }
    
    const appointment = await prisma.appointment.create({
      data: {
        datetime: new Date(datetime),
        department_id,
        patient_id,
        doctor_id,
        slot: slot || 'standard',
        status: status || 'SCHEDULED'
      }
    });
    
    res.status(201).json({ message: 'Appointment created', data: appointment });
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/appointments/{id}:
 *   put:
 *     summary: Update status/reschedule
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               datetime:
 *                 type: string
 *                 format: date-time
 *               status:
 *                 type: string
 *               doctor_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Appointment updated
 */
app.put('/api/v1/appointments/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { datetime, status, doctor_id } = req.body;
    
    const updateData: any = {};
    if (datetime) updateData.datetime = new Date(datetime);
    if (status) updateData.status = status;
    if (doctor_id) updateData.doctor_id = doctor_id;

    const appointment = await prisma.appointment.update({
      where: { id },
      data: updateData
    });
    
    res.json({ message: 'Appointment updated', data: appointment });
  } catch (error) {
    console.error('Error updating appointment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/appointments/{id}:
 *   delete:
 *     summary: Cancel appointment
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Appointment cancelled/deleted
 */
app.delete('/api/v1/appointments/:id', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.appointment.delete({ where: { id } });
    res.json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/patients/{id}/appointments:
 *   get:
 *     summary: A patient's appointment history
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Patient appointments
 */
app.get('/api/v1/patients/:id/appointments', authenticateToken, async (req: Request, res: Response) => {
  try {
    const patient_id = parseInt(req.params.id);
    const appointments = await prisma.appointment.findMany({
      where: { patient_id },
      include: { doctor: true, department: true },
      orderBy: { datetime: 'desc' }
    });
    res.json({ data: appointments });
  } catch (error) {
    console.error('Error fetching patient appointments:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==================== RECOMMENDATIONS ENDPOINTS ====================

/**
 * @swagger
 * /api/v1/recommendations:
 *   get:
 *     summary: List current allocation recommendations
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: department_id
 *         schema:
 *           type: integer
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *         description: e.g. PENDING, APPLIED, DISMISSED
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Pagination limit (default 100)
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *         description: Pagination offset (default 0)
 *     responses:
 *       200:
 *         description: List of recommendations
 */
app.get('/api/v1/recommendations', authenticateToken, async (req: Request, res: Response) => {
  try {
    const department_id = req.query.department_id ? parseInt(req.query.department_id as string) : undefined;
    const status = req.query.status as string;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
    
    let whereClause: any = {};
    if (department_id) whereClause.department_id = department_id;
    if (status) whereClause.status = status.toUpperCase();
    
    const recommendations = await prisma.recommendation.findMany({
      where: whereClause,
      include: { department: true },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset
    });
    
    res.json({ data: recommendations });
  } catch (error) {
    console.error('Error fetching recommendations:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/recommendations/{id}:
 *   get:
 *     summary: Get a single recommendation detail
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Recommendation details
 */
app.get('/api/v1/recommendations/:id', authenticateToken, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const recommendation = await prisma.recommendation.findUnique({
      where: { id },
      include: { department: true, alerts: true }
    });
    if (!recommendation) return res.status(404).json({ error: 'Recommendation not found' });
    res.json({ data: recommendation });
  } catch (error) {
    console.error('Error fetching recommendation:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/recommendations/{id}/apply:
 *   post:
 *     summary: Accept a recommendation (writes through to doctors/beds)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Recommendation applied
 */
app.post('/api/v1/recommendations/:id/apply', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    // TODO: In full implementation, parse the action string/JSON and execute DB updates on beds/doctors.
    const recommendation = await prisma.recommendation.update({
      where: { id },
      data: { status: 'APPLIED' }
    });
    
    res.json({ message: 'Recommendation applied successfully', data: recommendation });
  } catch (error) {
    console.error('Error applying recommendation:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/recommendations/{id}/dismiss:
 *   post:
 *     summary: Reject a recommendation
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Recommendation dismissed
 */
app.post('/api/v1/recommendations/:id/dismiss', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    
    const recommendation = await prisma.recommendation.update({
      where: { id },
      data: { status: 'DISMISSED' }
    });
    
    res.json({ message: 'Recommendation dismissed', data: recommendation });
  } catch (error) {
    console.error('Error dismissing recommendation:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /api/v1/recommendations/run:
 *   post:
 *     summary: Trigger optimization run (internal/admin-triggered)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               department_id:
 *                 type: integer
 *     responses:
 *       202:
 *         description: Optimization run triggered
 */
app.post('/api/v1/recommendations/run', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { department_id } = req.body || {};
    
    // TODO: Make an HTTP request to the Python OR-Tools Optimization Service (port 8002)
    // using axios/fetch, passing the department_id and current capacity.
    
    res.status(202).json({ 
      message: 'Optimization run triggered successfully. Calling Python OR-Tools service in background...', 
      department_id 
    });
  } catch (error) {
    console.error('Error triggering optimization:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

export default app;
