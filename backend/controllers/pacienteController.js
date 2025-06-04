const Paciente = require('../models/Paciente');
const AuditLog = require('../models/AuditLog');
const { AppError, catchAsync } = require('../middlewares/errorHandler');

// Función auxiliar para registrar auditoría
const registrarAuditoria = async (req, accion, entidadId, detalles, exitoso, mensaje) => {
  await AuditLog.registrar({
    usuario: req.user._id,
    rolUsuario: req.user.role,
    accion,
    entidad: {
      tipo: 'Paciente',
      id: entidadId
    },
    detalles,
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.sessionID
    },
    resultado: {
      exitoso,
      mensaje
    }
  });
};

// Crear nuevo paciente
exports.createPaciente = catchAsync(async (req, res, next) => {
  // Validar que solo doctores y admins puedan crear pacientes
  if (!['doctor', 'admin'].includes(req.user.role)) {
    return next(new AppError('No tiene permiso para crear pacientes', 403));
  }

  // Crear paciente
  const paciente = await Paciente.create({
    ...req.body,
    createdBy: req.user._id
  });

  // Registrar en audit log
  await registrarAuditoria(
    req,
    'crear',
    paciente._id,
    { datos: req.body },
    true,
    'Paciente creado exitosamente'
  );

  res.status(201).json({
    status: 'success',
    data: {
      paciente
    }
  });
});

// Obtener todos los pacientes (con filtros y paginación)
exports.getPacientes = catchAsync(async (req, res, next) => {
  // Construir query
  const queryObj = { ...req.query };
  const excludedFields = ['page', 'sort', 'limit', 'fields'];
  excludedFields.forEach(el => delete queryObj[el]);

  // Filtrado avanzado
  let queryStr = JSON.stringify(queryObj);
  queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `$${match}`);

  // Construir query
  let query = Paciente.find(JSON.parse(queryStr));

  // Sorting
  if (req.query.sort) {
    const sortBy = req.query.sort.split(',').join(' ');
    query = query.sort(sortBy);
  }

  // Field limiting
  if (req.query.fields) {
    const fields = req.query.fields.split(',').join(' ');
    query = query.select(fields);
  }

  // Pagination
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const skip = (page - 1) * limit;

  query = query.skip(skip).limit(limit);

  // Ejecutar query
  const pacientes = await query;
  const total = await Paciente.countDocuments(JSON.parse(queryStr));

  // Registrar consulta en audit log
  await registrarAuditoria(
    req,
    'consultar',
    null,
    { filtros: queryObj, pagina: page, limite: limit },
    true,
    'Consulta de pacientes exitosa'
  );

  res.status(200).json({
    status: 'success',
    results: pacientes.length,
    total,
    data: {
      pacientes
    }
  });
});

// Obtener un paciente específico
exports.getPaciente = catchAsync(async (req, res, next) => {
  const paciente = await Paciente.findById(req.params.id)
    .populate({
      path: 'historialMedico.doctor',
      select: 'name'
    });

  if (!paciente) {
    return next(new AppError('No se encontró el paciente', 404));
  }

  // Registrar consulta
  await registrarAuditoria(
    req,
    'consultar',
    paciente._id,
    null,
    true,
    'Consulta de paciente exitosa'
  );

  res.status(200).json({
    status: 'success',
    data: {
      paciente
    }
  });
});

// Actualizar paciente
exports.updatePaciente = catchAsync(async (req, res, next) => {
  // Verificar permisos
  if (!['doctor', 'admin'].includes(req.user.role)) {
    return next(new AppError('No tiene permiso para actualizar pacientes', 403));
  }

  // Obtener estado actual para comparar cambios
  const pacienteAntes = await Paciente.findById(req.params.id);
  if (!pacienteAntes) {
    return next(new AppError('No se encontró el paciente', 404));
  }

  // Actualizar paciente
  const paciente = await Paciente.findByIdAndUpdate(
    req.params.id,
    {
      ...req.body,
      updatedBy: req.user._id
    },
    {
      new: true,
      runValidators: true
    }
  );

  // Registrar cambios en audit log
  await registrarAuditoria(
    req,
    'actualizar',
    paciente._id,
    {
      cambios: {
        antes: pacienteAntes.toObject(),
        despues: paciente.toObject()
      }
    },
    true,
    'Paciente actualizado exitosamente'
  );

  res.status(200).json({
    status: 'success',
    data: {
      paciente
    }
  });
});

// Eliminar paciente (soft delete)
exports.deletePaciente = catchAsync(async (req, res, next) => {
  // Solo admins pueden eliminar pacientes
  if (req.user.role !== 'admin') {
    return next(new AppError('No tiene permiso para eliminar pacientes', 403));
  }

  const paciente = await Paciente.findById(req.params.id);
  if (!paciente) {
    return next(new AppError('No se encontró el paciente', 404));
  }

  // Realizar soft delete
  paciente.active = false;
  paciente.updatedBy = req.user._id;
  await paciente.save();

  // Registrar eliminación
  await registrarAuditoria(
    req,
    'eliminar',
    paciente._id,
    null,
    true,
    'Paciente eliminado (soft delete)'
  );

  res.status(204).json({
    status: 'success',
    data: null
  });
});

// Agregar entrada al historial médico
exports.addHistorialMedico = catchAsync(async (req, res, next) => {
  if (req.user.role !== 'doctor') {
    return next(new AppError('Solo doctores pueden agregar al historial médico', 403));
  }

  const paciente = await Paciente.findById(req.params.id);
  if (!paciente) {
    return next(new AppError('No se encontró el paciente', 404));
  }

  // Agregar entrada al historial
  paciente.historialMedico.push({
    ...req.body,
    doctor: req.user._id,
    fecha: new Date()
  });

  await paciente.save();

  // Registrar en audit log
  await registrarAuditoria(
    req,
    'agregar_historial',
    paciente._id,
    { entrada: req.body },
    true,
    'Entrada agregada al historial médico'
  );

  res.status(200).json({
    status: 'success',
    data: {
      paciente
    }
  });
});

// Buscar pacientes
exports.searchPacientes = catchAsync(async (req, res, next) => {
  const { q } = req.query;
  if (!q) {
    return next(new AppError('Debe proporcionar un término de búsqueda', 400));
  }

  // Crear índice de texto si no existe
  await Paciente.collection.createIndex({
    nombre: 'text',
    'apellidoPaterno': 'text',
    'apellidoMaterno': 'text'
  });

  const pacientes = await Paciente.find({
    $text: { $search: q }
  }).limit(10);

  // Registrar búsqueda
  await registrarAuditoria(
    req,
    'buscar',
    null,
    { termino: q },
    true,
    'Búsqueda de pacientes realizada'
  );

  res.status(200).json({
    status: 'success',
    results: pacientes.length,
    data: {
      pacientes
    }
  });
});

// Obtener estadísticas de pacientes (solo admin)
exports.getPacienteStats = catchAsync(async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return next(new AppError('No tiene permiso para ver estadísticas', 403));
  }

  const stats = await Paciente.aggregate([
    {
      $group: {
        _id: null,
        totalPacientes: { $sum: 1 },
        edadPromedio: { $avg: { $subtract: [new Date(), '$fechaNacimiento'] } },
        generoDistribucion: {
          $push: '$sexo'
        }
      }
    }
  ]);

  // Registrar consulta de estadísticas
  await registrarAuditoria(
    req,
    'consultar_estadisticas',
    null,
    { stats },
    true,
    'Consulta de estadísticas exitosa'
  );

  res.status(200).json({
    status: 'success',
    data: {
      stats
    }
  });
});
