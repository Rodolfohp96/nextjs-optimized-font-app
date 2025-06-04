const jwt = require('jsonwebtoken');
const config = require('../config/config');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Middleware para verificar JWT y autenticación
exports.protect = async (req, res, next) => {
  try {
    // 1. Obtener el token
    let token;
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      await registrarIntentoFallido(req, 'No se proporcionó token');
      return res.status(401).json({
        status: 'error',
        message: 'No está autorizado para acceder a este recurso'
      });
    }

    try {
      // 2. Verificar el token
      const decoded = jwt.verify(token, config.jwtSecret);

      // 3. Verificar si el usuario aún existe
      const user = await User.findById(decoded.id).select('+password');
      if (!user) {
        throw new Error('El usuario ya no existe');
      }

      // 4. Verificar si el usuario cambió su contraseña después de que se emitió el token
      if (user.changedPasswordAfter && user.changedPasswordAfter(decoded.iat)) {
        throw new Error('Usuario cambió recientemente su contraseña');
      }

      // 5. Verificar si el usuario está activo
      if (!user.active) {
        throw new Error('Usuario inactivo');
      }

      // Guardar el usuario en el request para uso posterior
      req.user = user;
      
      // Registrar acceso exitoso en audit log
      await registrarAccesoExitoso(req);
      
      next();
    } catch (error) {
      await registrarIntentoFallido(req, error.message);
      throw error;
    }
  } catch (error) {
    return res.status(401).json({
      status: 'error',
      message: 'No está autorizado para acceder a este recurso',
      error: error.message
    });
  }
};

// Middleware para restricción de roles
exports.restrictTo = (...roles) => {
  return async (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      await registrarIntentoFallido(req, 'Acceso denegado por rol insuficiente');
      return res.status(403).json({
        status: 'error',
        message: 'No tiene permiso para realizar esta acción'
      });
    }
    next();
  };
};

// Middleware para verificar permisos específicos sobre expedientes
exports.checkExpedientePermission = async (req, res, next) => {
  try {
    const expedienteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Los administradores tienen acceso completo
    if (userRole === 'admin') {
      return next();
    }

    const expediente = await mongoose.model('Expediente').findById(expedienteId);
    
    if (!expediente) {
      return res.status(404).json({
        status: 'error',
        message: 'Expediente no encontrado'
      });
    }

    // Verificar permisos específicos
    const permiso = expediente.permisos.find(p => p.usuario.toString() === userId);
    
    if (!permiso) {
      await registrarIntentoFallido(req, 'Sin permiso para acceder al expediente');
      return res.status(403).json({
        status: 'error',
        message: 'No tiene permiso para acceder a este expediente'
      });
    }

    // Verificar el nivel de acceso requerido
    const accionRequerida = req.method === 'GET' ? 'lectura' : 'escritura';
    if (accionRequerida === 'escritura' && permiso.nivel === 'lectura') {
      await registrarIntentoFallido(req, 'Nivel de permiso insuficiente');
      return res.status(403).json({
        status: 'error',
        message: 'No tiene permiso para modificar este expediente'
      });
    }

    // Agregar el permiso al request para uso posterior
    req.permisoExpediente = permiso;
    
    next();
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al verificar permisos',
      error: error.message
    });
  }
};

// Función auxiliar para registrar intentos fallidos de acceso
const registrarIntentoFallido = async (req, razon) => {
  try {
    await AuditLog.registrar({
      usuario: req.user?._id || null,
      rolUsuario: req.user?.role || 'anonymous',
      accion: 'acceso_denegado',
      entidad: {
        tipo: 'Sistema',
        id: null
      },
      detalles: {
        ruta: req.originalUrl,
        metodo: req.method,
        razon: razon
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        sessionId: req.sessionID
      },
      resultado: {
        exitoso: false,
        mensaje: razon
      }
    });
  } catch (error) {
    console.error('Error al registrar intento fallido:', error);
  }
};

// Función auxiliar para registrar accesos exitosos
const registrarAccesoExitoso = async (req) => {
  try {
    await AuditLog.registrar({
      usuario: req.user._id,
      rolUsuario: req.user.role,
      accion: 'acceso_exitoso',
      entidad: {
        tipo: 'Sistema',
        id: null
      },
      detalles: {
        ruta: req.originalUrl,
        metodo: req.method
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        sessionId: req.sessionID
      },
      resultado: {
        exitoso: true,
        mensaje: 'Acceso autorizado'
      }
    });
  } catch (error) {
    console.error('Error al registrar acceso exitoso:', error);
  }
};
