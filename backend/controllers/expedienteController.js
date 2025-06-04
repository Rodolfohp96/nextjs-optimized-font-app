const { PDFDocument, StandardFonts } = require('pdf-lib');
const Expediente = require('../models/Expediente');
const Paciente = require('../models/Paciente');
const Firma = require('../models/Firma');
const AuditLog = require('../models/AuditLog');
const { AppError, catchAsync } = require('../middlewares/errorHandler');
const config = require('../config/config');
const fs = require('fs').promises;
const path = require('path');

// Función auxiliar para registrar auditoría
const registrarAuditoria = async (req, accion, entidadId, detalles, exitoso, mensaje) => {
  await AuditLog.registrar({
    usuario: req.user._id,
    rolUsuario: req.user.role,
    accion,
    entidad: {
      tipo: 'Expediente',
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

// Generar PDF del expediente
const generarPDF = async (expediente, paciente) => {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontSize = 12;

  // Encabezado
  page.drawText('EXPEDIENTE CLÍNICO ELECTRÓNICO', {
    x: 50,
    y: page.getHeight() - 50,
    size: 16,
    font
  });

  // Datos del paciente
  page.drawText(`Paciente: ${paciente.nombreCompleto}`, {
    x: 50,
    y: page.getHeight() - 80,
    size: fontSize,
    font
  });

  // Contenido del expediente
  let yPosition = page.getHeight() - 120;
  
  // Tipo de expediente
  page.drawText(`Tipo: ${expediente.tipo}`, {
    x: 50,
    y: yPosition,
    size: fontSize,
    font
  });
  yPosition -= 20;

  // Fecha
  page.drawText(`Fecha: ${expediente.contenido.fecha.toLocaleDateString()}`, {
    x: 50,
    y: yPosition,
    size: fontSize,
    font
  });
  yPosition -= 40;

  // Contenido principal
  const contenido = expediente.contenido;
  for (const [key, value] of Object.entries(contenido)) {
    if (key !== 'fecha' && key !== 'metadata') {
      page.drawText(`${key}: ${value}`, {
        x: 50,
        y: yPosition,
        size: fontSize,
        font
      });
      yPosition -= 20;
    }
  }

  // Información de firma
  if (expediente.firmaDigital) {
    yPosition -= 40;
    page.drawText('FIRMADO DIGITALMENTE POR:', {
      x: 50,
      y: yPosition,
      size: fontSize,
      font
    });
    yPosition -= 20;
    page.drawText(`Dr. ${expediente.firmaDigital.firmante.name}`, {
      x: 50,
      y: yPosition,
      size: fontSize,
      font
    });
    yPosition -= 20;
    page.drawText(`Fecha de firma: ${expediente.firmaDigital.fechaFirma.toLocaleString()}`, {
      x: 50,
      y: yPosition,
      size: fontSize,
      font
    });
  }

  return await pdfDoc.save();
};

// Crear nuevo expediente
exports.createExpediente = catchAsync(async (req, res, next) => {
  // Verificar permisos
  if (req.user.role !== 'doctor') {
    return next(new AppError('Solo doctores pueden crear expedientes', 403));
  }

  // Verificar existencia del paciente
  const paciente = await Paciente.findById(req.body.paciente);
  if (!paciente) {
    return next(new AppError('No se encontró el paciente', 404));
  }

  // Crear expediente
  const expediente = await Expediente.create({
    ...req.body,
    createdBy: req.user._id,
    estado: 'borrador'
  });

  // Generar PDF
  const pdfBuffer = await generarPDF(expediente, paciente);

  // Guardar PDF
  const pdfFileName = `expediente_${expediente._id}.pdf`;
  const pdfPath = path.join(config.fileUploadDir, 'expedientes', pdfFileName);
  await fs.mkdir(path.dirname(pdfPath), { recursive: true });
  await fs.writeFile(pdfPath, pdfBuffer);

  // Actualizar expediente con ruta del PDF
  expediente.documento = {
    url: `/uploads/expedientes/${pdfFileName}`,
    hash: expediente.documento.hash,
    createdAt: new Date()
  };
  await expediente.save();

  // Registrar en audit log
  await registrarAuditoria(
    req,
    'crear',
    expediente._id,
    { datos: req.body },
    true,
    'Expediente creado exitosamente'
  );

  res.status(201).json({
    status: 'success',
    data: {
      expediente
    }
  });
});

// Firmar expediente
exports.firmarExpediente = catchAsync(async (req, res, next) => {
  if (req.user.role !== 'doctor') {
    return next(new AppError('Solo doctores pueden firmar expedientes', 403));
  }

  const expediente = await Expediente.findById(req.params.id);
  if (!expediente) {
    return next(new AppError('No se encontró el expediente', 404));
  }

  if (expediente.estado === 'firmado') {
    return next(new AppError('El expediente ya está firmado', 400));
  }

  // Crear firma digital
  const firma = await Firma.create({
    expedienteId: expediente._id,
    doctorId: req.user._id,
    certificado: {
      numeroSerie: req.body.certificado.numeroSerie,
      emisor: req.body.certificado.emisor,
      vigencia: {
        inicio: new Date(req.body.certificado.vigencia.inicio),
        fin: new Date(req.body.certificado.vigencia.fin)
      }
    }
  });

  // Actualizar expediente
  expediente.firmaDigital = {
    firmante: req.user._id,
    fechaFirma: new Date(),
    certificado: firma.certificado,
    selloDigital: firma.firma
  };
  expediente.estado = 'firmado';
  await expediente.save();

  // Regenerar PDF con firma
  const paciente = await Paciente.findById(expediente.paciente);
  const pdfBuffer = await generarPDF(expediente, paciente);
  
  // Actualizar PDF
  const pdfFileName = `expediente_${expediente._id}.pdf`;
  const pdfPath = path.join(config.fileUploadDir, 'expedientes', pdfFileName);
  await fs.writeFile(pdfPath, pdfBuffer);

  // Registrar en audit log
  await registrarAuditoria(
    req,
    'firmar',
    expediente._id,
    { firma: firma._id },
    true,
    'Expediente firmado exitosamente'
  );

  res.status(200).json({
    status: 'success',
    data: {
      expediente
    }
  });
});

// Obtener expediente
exports.getExpediente = catchAsync(async (req, res, next) => {
  const expediente = await Expediente.findById(req.params.id)
    .populate('paciente')
    .populate('createdBy', 'name')
    .populate('firmaDigital.firmante', 'name');

  if (!expediente) {
    return next(new AppError('No se encontró el expediente', 404));
  }

  // Verificar permisos
  if (req.user.role === 'paciente' && 
      expediente.paciente._id.toString() !== req.user.pacienteId) {
    return next(new AppError('No tiene permiso para ver este expediente', 403));
  }

  // Registrar acceso
  await expediente.registrarAcceso(req.user._id, 'leer', req.ip);

  // Registrar en audit log
  await registrarAuditoria(
    req,
    'consultar',
    expediente._id,
    null,
    true,
    'Consulta de expediente exitosa'
  );

  res.status(200).json({
    status: 'success',
    data: {
      expediente
    }
  });
});

// Descargar PDF del expediente
exports.downloadPDF = catchAsync(async (req, res, next) => {
  const expediente = await Expediente.findById(req.params.id)
    .populate('paciente');

  if (!expediente) {
    return next(new AppError('No se encontró el expediente', 404));
  }

  // Verificar permisos
  if (req.user.role === 'paciente' && 
      expediente.paciente._id.toString() !== req.user.pacienteId) {
    return next(new AppError('No tiene permiso para descargar este expediente', 403));
  }

  const pdfPath = path.join(config.fileUploadDir, 'expedientes', 
    path.basename(expediente.documento.url));

  // Verificar integridad del documento
  if (!expediente.verificarIntegridad()) {
    return next(new AppError('El documento ha sido alterado', 400));
  }

  // Registrar descarga
  await registrarAuditoria(
    req,
    'descargar',
    expediente._id,
    null,
    true,
    'Descarga de expediente exitosa'
  );

  res.download(pdfPath);
});

// Listar expedientes
exports.getExpedientes = catchAsync(async (req, res, next) => {
  let query = {};

  // Filtrar por paciente si se especifica
  if (req.query.paciente) {
    query.paciente = req.query.paciente;
  }

  // Si es paciente, solo ver sus expedientes
  if (req.user.role === 'paciente') {
    query.paciente = req.user.pacienteId;
  }

  // Paginación
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const skip = (page - 1) * limit;

  const expedientes = await Expediente.find(query)
    .populate('paciente', 'nombre apellidoPaterno apellidoMaterno')
    .populate('createdBy', 'name')
    .sort('-createdAt')
    .skip(skip)
    .limit(limit);

  const total = await Expediente.countDocuments(query);

  // Registrar consulta
  await registrarAuditoria(
    req,
    'listar',
    null,
    { filtros: query, pagina: page, limite: limit },
    true,
    'Consulta de expedientes exitosa'
  );

  res.status(200).json({
    status: 'success',
    results: expedientes.length,
    total,
    data: {
      expedientes
    }
  });
});

// Verificar firma de expediente
exports.verificarFirma = catchAsync(async (req, res, next) => {
  const expediente = await Expediente.findById(req.params.id)
    .populate('firmaDigital.firmante', 'name');

  if (!expediente) {
    return next(new AppError('No se encontró el expediente', 404));
  }

  if (!expediente.firmaDigital) {
    return next(new AppError('El expediente no está firmado', 400));
  }

  const firma = await Firma.findOne({ expedienteId: expediente._id });
  const resultado = await firma.verificarFirma();

  // Registrar verificación
  await registrarAuditoria(
    req,
    'verificar_firma',
    expediente._id,
    { resultado },
    resultado.valida,
    resultado.mensaje
  );

  res.status(200).json({
    status: 'success',
    data: resultado
  });
});
