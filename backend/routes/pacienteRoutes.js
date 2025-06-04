const express = require('express');
const { body, param, query } = require('express-validator');
const pacienteController = require('../controllers/pacienteController');
const { protect, restrictTo } = require('../middlewares/authMiddleware');

const router = express.Router();

// Proteger todas las rutas
router.use(protect);

// Validaciones comunes
const validatePacienteData = [
  body('nombre')
    .trim()
    .notEmpty()
    .withMessage('El nombre es requerido')
    .isLength({ min: 2 })
    .withMessage('El nombre debe tener al menos 2 caracteres'),
  body('apellidoPaterno')
    .trim()
    .notEmpty()
    .withMessage('El apellido paterno es requerido'),
  body('fechaNacimiento')
    .notEmpty()
    .withMessage('La fecha de nacimiento es requerida')
    .isISO8601()
    .withMessage('Formato de fecha inválido'),
  body('sexo')
    .trim()
    .notEmpty()
    .withMessage('El sexo es requerido')
    .isIn(['M', 'F'])
    .withMessage('El sexo debe ser M o F'),
  body('contacto.telefono')
    .optional()
    .matches(/^[0-9]{10}$/)
    .withMessage('Formato de teléfono inválido'),
  body('contacto.email')
    .optional()
    .isEmail()
    .withMessage('Email inválido')
    .normalizeEmail(),
  body('tipoSangre')
    .optional()
    .isIn(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'])
    .withMessage('Tipo de sangre inválido')
];

// Validación para entrada de historial médico
const validateHistorialEntry = [
  body('motivo')
    .trim()
    .notEmpty()
    .withMessage('El motivo es requerido'),
  body('diagnostico')
    .trim()
    .notEmpty()
    .withMessage('El diagnóstico es requerido'),
  body('tipo')
    .trim()
    .notEmpty()
    .withMessage('El tipo de consulta es requerido')
    .isIn(['consulta', 'urgencia', 'hospitalizacion'])
    .withMessage('Tipo de consulta inválido')
];

// Rutas para administradores y doctores
router.use(restrictTo('admin', 'doctor'));

// Crear paciente
router.post('/',
  validatePacienteData,
  pacienteController.createPaciente
);

// Obtener lista de pacientes con filtros
router.get('/',
  query('page').optional().isInt({ min: 1 }).withMessage('Página inválida'),
  query('limit').optional().isInt({ min: 1 }).withMessage('Límite inválido'),
  pacienteController.getPacientes
);

// Buscar pacientes
router.get('/search',
  query('q').notEmpty().withMessage('Término de búsqueda requerido'),
  pacienteController.searchPacientes
);

// Obtener estadísticas (solo admin)
router.get('/stats',
  restrictTo('admin'),
  pacienteController.getPacienteStats
);

// Rutas específicas por ID
router.route('/:id')
  .get(
    param('id').isMongoId().withMessage('ID inválido'),
    pacienteController.getPaciente
  )
  .put(
    param('id').isMongoId().withMessage('ID inválido'),
    validatePacienteData,
    pacienteController.updatePaciente
  )
  .delete(
    restrictTo('admin'),
    param('id').isMongoId().withMessage('ID inválido'),
    pacienteController.deletePaciente
  );

// Agregar entrada al historial médico
router.post('/:id/historial',
  param('id').isMongoId().withMessage('ID inválido'),
  validateHistorialEntry,
  restrictTo('doctor'),
  pacienteController.addHistorialMedico
);

// Rutas para pacientes
// Los pacientes solo pueden ver su propio expediente
router.get('/mi-expediente',
  restrictTo('paciente'),
  pacienteController.getPaciente
);

module.exports = router;
