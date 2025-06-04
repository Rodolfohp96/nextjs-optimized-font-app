const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  // Usuario que realizó la acción
  usuario: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  // Rol del usuario al momento de la acción
  rolUsuario: {
    type: String,
    enum: ['admin', 'doctor', 'paciente'],
    required: true
  },

  // Tipo de acción realizada
  accion: {
    type: String,
    enum: [
      // Acciones de autenticación
      'login',
      'logout',
      'reset_password',
      'change_password',
      
      // Acciones CRUD
      'crear',
      'leer',
      'actualizar',
      'eliminar',
      
      // Acciones específicas del sistema
      'firmar_documento',
      'generar_pdf',
      'subir_archivo',
      'descargar_archivo',
      'otorgar_acceso',
      'revocar_acceso'
    ],
    required: true
  },

  // Entidad afectada
  entidad: {
    tipo: {
      type: String,
      enum: ['Usuario', 'Paciente', 'Expediente', 'Documento'],
      required: true
    },
    id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    }
  },

  // Detalles de la acción
  detalles: {
    // Cambios realizados (para actualizaciones)
    cambios: {
      anterior: mongoose.Schema.Types.Mixed,
      nuevo: mongoose.Schema.Types.Mixed
    },
    
    // Metadata adicional
    metadata: {
      navegador: String,
      sistemaOperativo: String,
      dispositivo: String
    }
  },

  // Información de seguridad
  seguridad: {
    ip: {
      type: String,
      required: true
    },
    userAgent: String,
    sessionId: String
  },

  // Resultado de la acción
  resultado: {
    exitoso: {
      type: Boolean,
      required: true
    },
    mensaje: String,
    codigoError: String
  },

  // Timestamp con zona horaria
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  }
}, {
  timestamps: true,
  // No permitir modificaciones una vez creado
  capped: {
    size: 5242880, // 5MB
    max: 10000     // máximo 10,000 documentos
  }
});

// Índices para consultas frecuentes
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ usuario: 1, timestamp: -1 });
auditLogSchema.index({ 'entidad.tipo': 1, 'entidad.id': 1 });
auditLogSchema.index({ accion: 1, timestamp: -1 });

// Método estático para crear un nuevo registro de auditoría
auditLogSchema.statics.registrar = async function(datos) {
  try {
    const log = new this({
      usuario: datos.usuario,
      rolUsuario: datos.rolUsuario,
      accion: datos.accion,
      entidad: datos.entidad,
      detalles: datos.detalles || {},
      seguridad: {
        ip: datos.ip,
        userAgent: datos.userAgent,
        sessionId: datos.sessionId
      },
      resultado: {
        exitoso: datos.exitoso,
        mensaje: datos.mensaje,
        codigoError: datos.codigoError
      }
    });

    await log.save();
    return log;
  } catch (error) {
    console.error('Error al registrar auditoría:', error);
    // En caso de error al registrar auditoría, no debemos fallar la operación principal
    // pero debemos asegurarnos de loggearlo
    return null;
  }
};

// Método estático para buscar registros con filtros comunes
auditLogSchema.statics.buscar = async function(filtros) {
  const query = {};

  if (filtros.usuario) query.usuario = filtros.usuario;
  if (filtros.accion) query.accion = filtros.accion;
  if (filtros.entidadTipo) query['entidad.tipo'] = filtros.entidadTipo;
  if (filtros.entidadId) query['entidad.id'] = filtros.entidadId;
  if (filtros.exitoso !== undefined) query['resultado.exitoso'] = filtros.exitoso;
  
  if (filtros.fechaInicio || filtros.fechaFin) {
    query.timestamp = {};
    if (filtros.fechaInicio) query.timestamp.$gte = new Date(filtros.fechaInicio);
    if (filtros.fechaFin) query.timestamp.$lte = new Date(filtros.fechaFin);
  }

  return this.find(query)
    .sort({ timestamp: -1 })
    .limit(filtros.limite || 100)
    .skip(filtros.skip || 0)
    .populate('usuario', 'name email role');
};

// Prevenir modificaciones en registros existentes
auditLogSchema.pre('save', function(next) {
  if (!this.isNew) {
    const error = new Error('Los registros de auditoría no pueden ser modificados');
    return next(error);
  }
  next();
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;
