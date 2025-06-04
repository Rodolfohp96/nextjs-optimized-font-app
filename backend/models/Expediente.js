const mongoose = require('mongoose');
const crypto = require('crypto');

const expedienteSchema = new mongoose.Schema({
  // Referencia al paciente
  paciente: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Paciente',
    required: [true, 'El paciente es requerido']
  },

  // Tipo de expediente según NOM-004-SSA3-2012
  tipo: {
    type: String,
    enum: {
      values: [
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
      ],
      message: 'Tipo de expediente no válido'
    },
    required: [true, 'El tipo de expediente es requerido']
  },

  // Contenido del expediente
  contenido: {
    // Campos comunes
    fecha: {
      type: Date,
      required: true,
      default: Date.now
    },
    motivo: String,
    padecimientoActual: String,
    diagnostico: String,
    tratamiento: String,
    pronostico: String,
    
    // Campos específicos según tipo
    datosEspecificos: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },

    // Metadata del documento
    metadata: {
      version: {
        type: Number,
        default: 1
      },
      ultimaModificacion: Date,
      modificadoPor: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      }
    }
  },

  // Documento PDF generado
  documento: {
    url: String,          // URL o path al PDF
    hash: String,         // Hash SHA-256 del contenido
    createdAt: Date      // Fecha de generación
  },

  // Firma digital (FIEL o e.firma)
  firmaDigital: {
    firmante: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    fechaFirma: {
      type: Date,
      required: true
    },
    certificado: {
      numeroSerie: String,
      emisor: String,
      vigencia: {
        inicio: Date,
        fin: Date
      }
    },
    selloDigital: String,     // Firma RSA-SHA256 en base64
    cadenaOriginal: String    // Datos que se firmaron
  },

  // Control de acceso y auditoría
  permisos: [{
    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    nivel: {
      type: String,
      enum: ['lectura', 'escritura', 'administrador']
    },
    otorgadoPor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    fecha: Date
  }],

  historialAccesos: [{
    usuario: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    accion: {
      type: String,
      enum: ['crear', 'leer', 'actualizar', 'firmar']
    },
    fecha: Date,
    ip: String
  }],

  // Estado del expediente
  estado: {
    type: String,
    enum: ['borrador', 'firmado', 'cancelado'],
    default: 'borrador'
  },

  // Campos de control
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  active: {
    type: Boolean,
    default: true,
    select: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Índices
expedienteSchema.index({ paciente: 1, fecha: -1 });
expedienteSchema.index({ 'firmaDigital.fechaFirma': -1 });
expedienteSchema.index({ estado: 1 });

// Middleware para generar hash del contenido antes de guardar
expedienteSchema.pre('save', function(next) {
  if (this.isModified('contenido')) {
    const contenidoString = JSON.stringify(this.contenido);
    this.documento.hash = crypto
      .createHash('sha256')
      .update(contenidoString)
      .digest('hex');
    this.documento.createdAt = new Date();
  }
  next();
});

// Método para verificar integridad del documento
expedienteSchema.methods.verificarIntegridad = function() {
  const contenidoString = JSON.stringify(this.contenido);
  const hashCalculado = crypto
    .createHash('sha256')
    .update(contenidoString)
    .digest('hex');
  return hashCalculado === this.documento.hash;
};

// Método para registrar acceso
expedienteSchema.methods.registrarAcceso = async function(usuario, accion, ip) {
  this.historialAccesos.push({
    usuario,
    accion,
    fecha: new Date(),
    ip
  });
  await this.save();
};

// Middleware para soft delete
expedienteSchema.pre(/^find/, function(next) {
  if (!this.getQuery().includeInactive) {
    this.find({ active: { $ne: false } });
  }
  next();
});

const Expediente = mongoose.model('Expediente', expedienteSchema);

module.exports = Expediente;
