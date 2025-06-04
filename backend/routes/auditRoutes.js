const express = require('express');
const { query } = require('express-validator');
const auditController = require('../controllers/auditController');
const { protect, restrictTo } = require('../middlewares/authMiddleware');

const router = express.Router();

// Proteger todas las rutas y restringir a administradores
router.use(protect);
router.use(restrictTo('admin'));

// Validaciones comunes para filtros
const validateDateRange = [
  query('fechaInicio')
    .optional()
    .isISO8601()
    .withMessage('Formato de fecha inicial inválido'),
  query('fechaFin')
    .optional()
    .isISO8601()
    .withMessage('Formato de fecha final inválido')
    .custom((value, { req }) => {
      if (req.query.fechaInicio && value) {
        return new Date(value) >= new Date(req.query.fechaInicio);
      }
      return true;
    })
    .withMessage('La fecha final debe ser posterior a la fecha inicial')
];

// Validaciones para filtros de consulta
const validateQueryFilters = [
  query('usuario')
    .optional()
    .isMongoId()
    .withMessage('ID de usuario inválido'),
  query('rolUsuario')
    .optional()
    .isIn(['admin', 'doctor', 'paciente'])
    .withMessage('Rol de usuario inválido'),
  query('accion')
    .optional()
    .isIn([
      'crear',
      'leer',
      'actualizar',
      'eliminar',
      'login',
      'logout',
      'firmar_documento',
      'generar_pdf',
      'subir_archivo',
      'descargar_archivo',
      'acceso_denegado'
    ])
    .withMessage('Acción inválida'),
  query('entidadTipo')
    .optional()
    .isIn(['Usuario', 'Paciente', 'Expediente', 'Documento'])
    .withMessage('Tipo de entidad inválido'),
  query('entidadId')
    .optional()
    .isMongoId()
    .withMessage('ID de entidad inválido'),
  query('exitoso')
    .optional()
    .isBoolean()
    .withMessage('El valor de exitoso debe ser true o false'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Página inválida'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Límite inválido (1-100)')
];

// Obtener registros de auditoría con filtros
router.get('/',
  validateDateRange,
  validateQueryFilters,
  auditController.getAuditLogs
);

// Exportar registros a CSV
router.get('/export',
  validateDateRange,
  validateQueryFilters,
  auditController.exportAuditLogs
);

// Obtener estadísticas de auditoría
router.get('/stats',
  validateDateRange,
  auditController.getAuditStats
);

// Rutas específicas por tipo de entidad
router.get('/usuarios',
  validateDateRange,
  query('usuario').optional().isMongoId().withMessage('ID de usuario inválido'),
  auditController.getAuditLogs
);

router.get('/pacientes',
  validateDateRange,
  query('paciente').optional().isMongoId().withMessage('ID de paciente inválido'),
  auditController.getAuditLogs
);

router.get('/expedientes',
  validateDateRange,
  query('expediente').optional().isMongoId().withMessage('ID de expediente inválido'),
  auditController.getAuditLogs
);

// Rutas para monitoreo de seguridad
router.get('/security/failed-logins',
  validateDateRange,
  auditController.getFailedLogins
);

router.get('/security/access-denied',
  validateDateRange,
  auditController.getAccessDenied
);

router.get('/security/suspicious-activity',
  validateDateRange,
  auditController.getSuspiciousActivity
);

// Rutas para reportes específicos
router.get('/reports/user-activity',
  validateDateRange,
  query('usuario').isMongoId().withMessage('ID de usuario requerido'),
  auditController.getUserActivity
);

router.get('/reports/document-access',
  validateDateRange,
  query('expediente').isMongoId().withMessage('ID de expediente requerido'),
  auditController.getDocumentAccess
);

router.get('/reports/system-usage',
  validateDateRange,
  auditController.getSystemUsage
);

// Ruta para obtener resumen de actividad
router.get('/summary',
  query('periodo')
    .optional()
    .isIn(['dia', 'semana', 'mes', 'año'])
    .withMessage('Periodo inválido'),
  auditController.getActivitySummary
);

// Ruta para obtener alertas de seguridad
router.get('/alerts',
  validateDateRange,
  query('nivel')
    .optional()
    .isIn(['bajo', 'medio', 'alto', 'critico'])
    .withMessage('Nivel de alerta inválido'),
  auditController.getSecurityAlerts
);

module.exports = router;
