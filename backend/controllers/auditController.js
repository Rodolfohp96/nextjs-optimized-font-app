const AuditLog = require('../models/AuditLog');
const { AppError, catchAsync } = require('../middlewares/errorHandler');
const { Parser } = require('json2csv');

// Función auxiliar para registrar la propia auditoría de consultas
const registrarConsultaAuditoria = async (req, filtros, resultados) => {
  await AuditLog.registrar({
    usuario: req.user._id,
    rolUsuario: req.user.role,
    accion: 'consultar_auditoria',
    entidad: {
      tipo: 'AuditLog',
      id: null
    },
    detalles: {
      filtros,
      resultados: resultados.length
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.sessionID
    },
    resultado: {
      exitoso: true,
      mensaje: 'Consulta de registros de auditoría exitosa'
    }
  });
};

// Obtener registros de auditoría con filtros
exports.getAuditLogs = catchAsync(async (req, res, next) => {
  // Verificar que sea administrador
  if (req.user.role !== 'admin') {
    return next(new AppError('No tiene permiso para ver registros de auditoría', 403));
  }

  // Construir filtros
  const filtros = {};

  // Filtrar por usuario
  if (req.query.usuario) {
    filtros.usuario = req.query.usuario;
  }

  // Filtrar por rol
  if (req.query.rolUsuario) {
    filtros.rolUsuario = req.query.rolUsuario;
  }

  // Filtrar por acción
  if (req.query.accion) {
    filtros.accion = req.query.accion;
  }

  // Filtrar por tipo de entidad
  if (req.query.entidadTipo) {
    filtros['entidad.tipo'] = req.query.entidadTipo;
  }

  // Filtrar por ID de entidad
  if (req.query.entidadId) {
    filtros['entidad.id'] = req.query.entidadId;
  }

  // Filtrar por resultado
  if (req.query.exitoso !== undefined) {
    filtros['resultado.exitoso'] = req.query.exitoso === 'true';
  }

  // Filtrar por rango de fechas
  if (req.query.fechaInicio || req.query.fechaFin) {
    filtros.timestamp = {};
    if (req.query.fechaInicio) {
      filtros.timestamp.$gte = new Date(req.query.fechaInicio);
    }
    if (req.query.fechaFin) {
      filtros.timestamp.$lte = new Date(req.query.fechaFin);
    }
  }

  // Paginación
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;
  const skip = (page - 1) * limit;

  // Ejecutar consulta
  const logs = await AuditLog.find(filtros)
    .populate('usuario', 'name email role')
    .sort('-timestamp')
    .skip(skip)
    .limit(limit);

  const total = await AuditLog.countDocuments(filtros);

  // Registrar esta consulta en la auditoría
  await registrarConsultaAuditoria(req, filtros, logs);

  res.status(200).json({
    status: 'success',
    results: logs.length,
    total,
    data: {
      logs
    }
  });
});

// Exportar registros de auditoría a CSV
exports.exportAuditLogs = catchAsync(async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return next(new AppError('No tiene permiso para exportar registros de auditoría', 403));
  }

  // Construir filtros (similar a getAuditLogs)
  const filtros = {};
  
  if (req.query.fechaInicio || req.query.fechaFin) {
    filtros.timestamp = {};
    if (req.query.fechaInicio) {
      filtros.timestamp.$gte = new Date(req.query.fechaInicio);
    }
    if (req.query.fechaFin) {
      filtros.timestamp.$lte = new Date(req.query.fechaFin);
    }
  }

  // Obtener todos los registros que coincidan con los filtros
  const logs = await AuditLog.find(filtros)
    .populate('usuario', 'name email role')
    .sort('-timestamp');

  // Transformar datos para CSV
  const logsParaExportar = logs.map(log => ({
    Fecha: log.timestamp.toLocaleString(),
    Usuario: log.usuario ? log.usuario.name : 'N/A',
    Email: log.usuario ? log.usuario.email : 'N/A',
    Rol: log.rolUsuario,
    Accion: log.accion,
    EntidadTipo: log.entidad.tipo,
    EntidadId: log.entidad.id,
    ResultadoExitoso: log.resultado.exitoso ? 'Sí' : 'No',
    Mensaje: log.resultado.mensaje,
    IP: log.seguridad.ip,
    UserAgent: log.seguridad.userAgent
  }));

  // Configurar campos para CSV
  const campos = [
    { label: 'Fecha', value: 'Fecha' },
    { label: 'Usuario', value: 'Usuario' },
    { label: 'Email', value: 'Email' },
    { label: 'Rol', value: 'Rol' },
    { label: 'Acción', value: 'Accion' },
    { label: 'Tipo de Entidad', value: 'EntidadTipo' },
    { label: 'ID de Entidad', value: 'EntidadId' },
    { label: 'Exitoso', value: 'ResultadoExitoso' },
    { label: 'Mensaje', value: 'Mensaje' },
    { label: 'Dirección IP', value: 'IP' },
    { label: 'Navegador', value: 'UserAgent' }
  ];

  // Generar CSV
  const json2csvParser = new Parser({ fields: campos });
  const csv = json2csvParser.parse(logsParaExportar);

  // Registrar la exportación
  await AuditLog.registrar({
    usuario: req.user._id,
    rolUsuario: req.user.role,
    accion: 'exportar_auditoria',
    entidad: {
      tipo: 'AuditLog',
      id: null
    },
    detalles: {
      filtros,
      registrosExportados: logs.length
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.sessionID
    },
    resultado: {
      exitoso: true,
      mensaje: 'Exportación de registros de auditoría exitosa'
    }
  });

  // Enviar archivo CSV
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 
    `attachment; filename=auditoria_${new Date().toISOString()}.csv`);
  res.status(200).send(csv);
});

// Obtener estadísticas de auditoría
exports.getAuditStats = catchAsync(async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return next(new AppError('No tiene permiso para ver estadísticas de auditoría', 403));
  }

  // Periodo de tiempo para las estadísticas
  const fechaFin = new Date();
  const fechaInicio = new Date();
  fechaInicio.setDate(fechaInicio.getDate() - 30); // últimos 30 días

  // Obtener estadísticas
  const stats = await AuditLog.aggregate([
    {
      $match: {
        timestamp: { $gte: fechaInicio, $lte: fechaFin }
      }
    },
    {
      $group: {
        _id: null,
        totalRegistros: { $sum: 1 },
        accionesExitosas: {
          $sum: { $cond: [{ $eq: ['$resultado.exitoso', true] }, 1, 0] }
        },
        accionesFallidas: {
          $sum: { $cond: [{ $eq: ['$resultado.exitoso', false] }, 1, 0] }
        }
      }
    }
  ]);

  // Obtener distribución por tipo de acción
  const distribucionAcciones = await AuditLog.aggregate([
    {
      $match: {
        timestamp: { $gte: fechaInicio, $lte: fechaFin }
      }
    },
    {
      $group: {
        _id: '$accion',
        count: { $sum: 1 }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);

  // Obtener distribución por rol de usuario
  const distribucionRoles = await AuditLog.aggregate([
    {
      $match: {
        timestamp: { $gte: fechaInicio, $lte: fechaFin }
      }
    },
    {
      $group: {
        _id: '$rolUsuario',
        count: { $sum: 1 }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);

  // Registrar consulta de estadísticas
  await AuditLog.registrar({
    usuario: req.user._id,
    rolUsuario: req.user.role,
    accion: 'consultar_estadisticas_auditoria',
    entidad: {
      tipo: 'AuditLog',
      id: null
    },
    detalles: {
      periodo: {
        inicio: fechaInicio,
        fin: fechaFin
      }
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.sessionID
    },
    resultado: {
      exitoso: true,
      mensaje: 'Consulta de estadísticas exitosa'
    }
  });

  res.status(200).json({
    status: 'success',
    data: {
      stats: stats[0],
      distribucionAcciones,
      distribucionRoles,
      periodo: {
        inicio: fechaInicio,
        fin: fechaFin
      }
    }
  });
});
