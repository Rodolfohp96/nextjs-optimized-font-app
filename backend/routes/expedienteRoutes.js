const express = require('express');
const { body, param, query } = require('express-validator');
const expedienteController = require('../controllers/expedienteController');
const { protect, restrictTo, checkExpedientePermission } = require('../middlewares/authMiddleware');

const router = express.Router();

// Proteger todas las rutas
router.use(protect);

// Validaciones comunes
const validateExpedienteData = [
  body('paciente')
    .isMongoId()
    .withMessage('ID de paciente inválido'),
  body('tipo')
    .trim()
    .notEmpty()
    .withMessage('El tipo de expediente es requerido')
    .isIn([
      'historia_clinica',
      'nota_evolucion',
      'nota_interconsulta',
      'nota_referencia',
      'nota_urgencias',
      'nota_hospitalizacion',
      'consentimiento_informado',
      'resultado_laboratorio',
      'estudio_imagen',
      'receta_medica'
    ])
    .withMessage('Tipo de expediente inválido'),
  body('contenido')
    .isObject()
    .withMessage('El contenido es requerido'),
  body('contenido.fecha')
    .optional()
    .isISO8601()
    .withMessage('Formato de fecha inválido'),
  body('contenido.motivo')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('El motivo no puede estar vacío'),
  body('contenido.diagnostico')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('El diagnóstico no puede estar vacío')
];

// Validaciones para firma digital
const validateFirmaData = [
  body('certificado.numeroSerie')
    .trim()
    .notEmpty()
    .withMessage('El número de serie del certificado es requerido'),
  body('certificado.emisor')
    .trim()
    .notEmpty()
    .withMessage('El emisor del certificado es requerido'),
  body('certificado.vigencia.inicio')
    .isISO8601()
    .withMessage('Fecha de inicio de vigencia inválida'),
  body('certificado.vigencia.fin')
    .isISO8601()
    .withMessage('Fecha de fin de vigencia inválida')
];

// Rutas para crear y listar expedientes (solo doctores)
router.route('/')
  .post(
    restrictTo('doctor'),
    validateExpedienteData,
    expedienteController.createExpediente
  )
  .get(
    query('page').optional().isInt({ min: 1 }).withMessage('Página inválida'),
    query('limit').optional().isInt({ min: 1 }).withMessage('Límite inválido'),
    query('paciente').optional().isMongoId().withMessage('ID de paciente inválido'),
    expedienteController.getExpedientes
  );

// Rutas específicas por ID
router.route('/:id')
  .get(
    param('id').isMongoId().withMessage('ID inválido'),
    checkExpedientePermission,
    expedienteController.getExpediente
  )
  .put(
    restrictTo('doctor'),
    param('id').isMongoId().withMessage('ID inválido'),
    checkExpedientePermission,
    validateExpedienteData,
    expedienteController.updateExpediente
  );

// Ruta para firmar expediente
router.post('/:id/firmar',
  restrictTo('doctor'),
  param('id').isMongoId().withMessage('ID inválido'),
  validateFirmaData,
  expedienteController.firmarExpediente
);

// Ruta para verificar firma
router.get('/:id/verificar-firma',
  param('id').isMongoId().withMessage('ID inválido'),
  checkExpedientePermission,
  expedienteController.verificarFirma
);

// Ruta para descargar PDF
router.get('/:id/pdf',
  param('id').isMongoId().withMessage('ID inválido'),
  checkExpedientePermission,
  expedienteController.downloadPDF
);

// Rutas para pacientes
// Los pacientes solo pueden ver sus propios expedientes
router.get('/mis-expedientes',
  restrictTo('paciente'),
  expedienteController.getExpedientes
);

// Rutas para administradores
router.use(restrictTo('admin'));

// Ruta para obtener estadísticas de expedientes
router.get('/stats/general',
  expedienteController.getExpedienteStats
);

// Ruta para obtener expedientes por doctor
router.get('/stats/por-doctor',
  query('doctor').optional().isMongoId().withMessage('ID de doctor inválido'),
  expedienteController.getExpedientesPorDoctor
);

// Ruta para obtener expedientes por tipo
router.get('/stats/por-tipo',
  expedienteController.getExpedientesPorTipo
);

module.exports = router;
