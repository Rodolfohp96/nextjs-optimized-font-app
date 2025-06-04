const mongoose = require('mongoose');
const crypto = require('crypto');

const firmaSchema = new mongoose.Schema({
  // Referencia al expediente firmado
  expediente: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Expediente',
    required: [true, 'El expediente es requerido']
  },

  // Firmante (doctor o personal autorizado)
  firmante: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'El firmante es requerido']
  },

  // Información del certificado digital
  certificado: {
    // Número de serie del certificado (e.firma/FIEL)
    numeroSerie: {
      type: String,
      required: [true, 'El número de serie del certificado es requerido']
    },
    
    // Información del emisor (SAT/autoridad certificadora)
    emisor: {
      nombreComun: String,      // Common Name (CN)
      organizacion: String,     // Organization (O)
      unidad: String,          // Organizational Unit (OU)
      pais: String            // Country (C)
    },
    
    // Vigencia del certificado
    vigencia: {
      inicio: {
        type: Date,
        required: true
      },
      fin: {
        type: Date,
        required: true
      }
    },

    // Certificado público en formato PEM
    certificadoPublico: {
      type: String,
      required: true
    }
  },

  // Firma digital
  firma: {
    // Algoritmo usado para firmar (RSA-SHA256, ECDSA, etc)
    algoritmo: {
      type: String,
      enum: ['RSA-SHA256', 'ECDSA-P256-SHA256'],
      default: 'RSA-SHA256'
    },

    // Cadena original (datos que se firmaron)
    cadenaOriginal: {
      type: String,
      required: true
    },

    // Sello digital (firma en base64)
    selloDigital: {
      type: String,
      required: true
    },

    // Hash del documento original
    hashDocumento: {
      type: String,
      required: true
    }
  },

  // Timestamp de la firma
  timestamp: {
    fecha: {
      type: Date,
      required: true,
      default: Date.now
    },
    // Opcional: Timestamp de una autoridad de sellado de tiempo (TSA)
    selloTiempo: {
      autoridad: String,
      sello: String,
      fecha: Date
    }
  },

  // Metadata de la firma
  metadata: {
    // Dispositivo/ubicación desde donde se firmó
    dispositivo: String,
    ip: String,
    ubicacion: {
      ciudad: String,
      pais: String,
      coordenadas: {
        latitud: Number,
        longitud: Number
      }
    },
    
    // Propósito de la firma
    proposito: {
      type: String,
      enum: [
        'creacion_expediente',
        'actualizacion_expediente',
        'nota_medica',
        'receta',
        'consentimiento_informado',
        'resultado_laboratorio'
      ],
      required: true
    }
  },

  // Estado de la firma
  estado: {
    type: String,
    enum: ['valida', 'revocada', 'expirada'],
    default: 'valida'
  },

  // En caso de revocación
  revocacion: {
    fecha: Date,
    motivo: String,
    revocadaPor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }
}, {
  timestamps: true
});

// Índices
firmaSchema.index({ expediente: 1, timestamp: -1 });
firmaSchema.index({ firmante: 1 });
firmaSchema.index({ 'certificado.numeroSerie': 1 });
firmaSchema.index({ estado: 1 });

// Método para verificar la validez de la firma
firmaSchema.methods.verificarFirma = async function() {
  try {
    // 1. Verificar que el certificado no haya expirado
    const ahora = new Date();
    if (ahora < this.certificado.vigencia.inicio || ahora > this.certificado.vigencia.fin) {
      return {
        valida: false,
        mensaje: 'El certificado ha expirado'
      };
    }

    // 2. Verificar que la firma no esté revocada
    if (this.estado === 'revocada') {
      return {
        valida: false,
        mensaje: 'La firma ha sido revocada',
        detalles: this.revocacion
      };
    }

    // 3. Verificar la integridad del documento
    const verificacion = crypto.createVerify(this.firma.algoritmo);
    verificacion.update(this.firma.cadenaOriginal);

    const certificadoPublico = this.certificado.certificadoPublico;
    const selloDigital = Buffer.from(this.firma.selloDigital, 'base64');

    const firmaValida = verificacion.verify(certificadoPublico, selloDigital);

    return {
      valida: firmaValida,
      mensaje: firmaValida ? 'Firma válida' : 'Firma inválida'
    };
  } catch (error) {
    return {
      valida: false,
      mensaje: 'Error al verificar la firma',
      error: error.message
    };
  }
};

// Método para revocar una firma
firmaSchema.methods.revocar = async function(usuario, motivo) {
  this.estado = 'revocada';
  this.revocacion = {
    fecha: new Date(),
    motivo,
    revocadaPor: usuario._id
  };
  await this.save();

  // Registrar en el log de auditoría
  await mongoose.model('AuditLog').registrar({
    usuario: usuario._id,
    rolUsuario: usuario.role,
    accion: 'revocar_firma',
    entidad: {
      tipo: 'Firma',
      id: this._id
    },
    detalles: {
      expediente: this.expediente,
      motivo
    },
    resultado: {
      exitoso: true,
      mensaje: 'Firma revocada exitosamente'
    }
  });
};

const Firma = mongoose.model('Firma', firmaSchema);

module.exports = Firma;
