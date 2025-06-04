const config = require('../config/config');
const AuditLog = require('../models/AuditLog');

// Clase personalizada para errores operacionales
class AppError extends Error {
  constructor(message, statusCode, errorCode = null) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.errorCode = errorCode;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Función para manejar errores de MongoDB
const handleMongoError = (err) => {
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return new AppError(`Valor duplicado para el campo ${field}`, 400, 'DUPLICATE_VALUE');
  }
  return new AppError('Error en la base de datos', 500, 'DB_ERROR');
};

// Función para manejar errores de validación de Mongoose
const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  return new AppError(`Datos inválidos: ${errors.join('. ')}`, 400, 'VALIDATION_ERROR');
};

// Función para manejar errores de JWT
const handleJWTError = () => 
  new AppError('Token inválido', 401, 'INVALID_TOKEN');

const handleJWTExpiredError = () => 
  new AppError('Token expirado', 401, 'EXPIRED_TOKEN');

// Función para registrar el error en el log de auditoría
const logError = async (err, req) => {
  try {
    await AuditLog.registrar({
      usuario: req.user?._id || null,
      rolUsuario: req.user?.role || 'anonymous',
      accion: 'error_sistema',
      entidad: {
        tipo: 'Sistema',
        id: null
      },
      detalles: {
        mensaje: err.message,
        codigo: err.errorCode,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        ruta: req.originalUrl,
        metodo: req.method
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        sessionId: req.sessionID
      },
      resultado: {
        exitoso: false,
        mensaje: err.message,
        codigoError: err.errorCode
      }
    });
  } catch (error) {
    console.error('Error al registrar en audit log:', error);
  }
};

// Middleware principal de manejo de errores
const errorHandler = async (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Registrar el error en el log de auditoría
  await logError(err, req);

  // En desarrollo, enviar el error completo
  if (process.env.NODE_ENV === 'development') {
    return res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      errorCode: err.errorCode,
      stack: err.stack
    });
  }

  // En producción, manejar diferentes tipos de errores
  let error = { ...err };
  error.message = err.message;

  // Manejar diferentes tipos de errores
  if (error.name === 'CastError') 
    error = new AppError('Formato de datos inválido', 400, 'INVALID_FORMAT');
  if (error.name === 'ValidationError') 
    error = handleValidationError(error);
  if (error.code === 11000) 
    error = handleMongoError(error);
  if (error.name === 'JsonWebTokenError') 
    error = handleJWTError();
  if (error.name === 'TokenExpiredError') 
    error = handleJWTExpiredError();

  // Si es un error operacional conocido
  if (error.isOperational) {
    return res.status(error.statusCode).json({
      status: error.status,
      message: error.message,
      errorCode: error.errorCode
    });
  }

  // Para errores de programación u otros errores desconocidos
  console.error('ERROR 💥:', err);
  return res.status(500).json({
    status: 'error',
    message: 'Algo salió mal',
    errorCode: 'INTERNAL_ERROR'
  });
};

// Middleware para manejar errores de async/await
const catchAsync = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

// Middleware para rutas no encontradas
const notFound = (req, res, next) => {
  next(new AppError(`No se encontró ${req.originalUrl}`, 404, 'NOT_FOUND'));
};

module.exports = {
  AppError,
  errorHandler,
  catchAsync,
  notFound
};
