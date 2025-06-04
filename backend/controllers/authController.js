const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { promisify } = require('util');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const config = require('../config/config');
const { AppError, catchAsync } = require('../middlewares/errorHandler');

// Generar token JWT
const signToken = (id, role) => {
  return jwt.sign(
    { id, role },
    config.jwtSecret,
    { expiresIn: config.tokenExpiry }
  );
};

// Crear y enviar token
const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id, user.role);

  // Opciones para la cookie
  const cookieOptions = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 horas
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  };

  // Enviar cookie
  res.cookie('jwt', token, cookieOptions);

  // Remover password de la salida
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

// Registro de usuario
exports.signup = catchAsync(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Verificar si el rol es válido
  if (role === 'admin') {
    return next(new AppError('No se puede crear usuarios administradores directamente', 403));
  }

  // Crear usuario
  const user = await User.create({
    name,
    email,
    password,
    role
  });

  // Registrar en audit log
  await AuditLog.registrar({
    usuario: user._id,
    rolUsuario: user.role,
    accion: 'crear',
    entidad: {
      tipo: 'Usuario',
      id: user._id
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent')
    },
    resultado: {
      exitoso: true,
      mensaje: 'Usuario creado exitosamente'
    }
  });

  createSendToken(user, 201, req, res);
});

// Login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Verificar si email y password existen
  if (!email || !password) {
    return next(new AppError('Por favor proporcione email y contraseña', 400));
  }

  // 2) Verificar si el usuario existe y la contraseña es correcta
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.comparePassword(password))) {
    // Registrar intento fallido
    await AuditLog.registrar({
      usuario: user?._id,
      rolUsuario: user?.role || 'anonymous',
      accion: 'login',
      entidad: {
        tipo: 'Usuario',
        id: user?._id
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent')
      },
      resultado: {
        exitoso: false,
        mensaje: 'Intento de login fallido'
      }
    });

    return next(new AppError('Email o contraseña incorrectos', 401));
  }

  // 3) Verificar si el usuario está activo
  if (!user.active) {
    return next(new AppError('Su cuenta está desactivada', 401));
  }

  // 4) Actualizar último login
  user.lastLogin = Date.now();
  await user.save({ validateBeforeSave: false });

  // 5) Registrar login exitoso
  await AuditLog.registrar({
    usuario: user._id,
    rolUsuario: user.role,
    accion: 'login',
    entidad: {
      tipo: 'Usuario',
      id: user._id
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent')
    },
    resultado: {
      exitoso: true,
      mensaje: 'Login exitoso'
    }
  });

  // 6) Enviar token
  createSendToken(user, 200, req, res);
});

// Logout
exports.logout = catchAsync(async (req, res, next) => {
  // Registrar logout
  if (req.user) {
    await AuditLog.registrar({
      usuario: req.user._id,
      rolUsuario: req.user.role,
      accion: 'logout',
      entidad: {
        tipo: 'Usuario',
        id: req.user._id
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent')
      },
      resultado: {
        exitoso: true,
        mensaje: 'Logout exitoso'
      }
    });
  }

  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({ status: 'success' });
});

// Solicitar reset de contraseña
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Obtener usuario basado en email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('No existe usuario con ese email', 404));
  }

  // 2) Generar token random
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    // 3) Enviar email con token (implementar servicio de email)
    // TODO: Implementar envío de email

    // 4) Registrar solicitud
    await AuditLog.registrar({
      usuario: user._id,
      rolUsuario: user.role,
      accion: 'solicitar_reset_password',
      entidad: {
        tipo: 'Usuario',
        id: user._id
      },
      seguridad: {
        ip: req.ip,
        userAgent: req.get('user-agent')
      },
      resultado: {
        exitoso: true,
        mensaje: 'Token de reset generado'
      }
    });

    res.status(200).json({
      status: 'success',
      message: 'Token enviado al email'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('Hubo un error enviando el email. Intente más tarde.', 500));
  }
});

// Reset de contraseña
exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Obtener usuario basado en token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  // 2) Si el token no ha expirado y existe el usuario, establecer nueva contraseña
  if (!user) {
    return next(new AppError('Token inválido o expirado', 400));
  }

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Registrar cambio de contraseña
  await AuditLog.registrar({
    usuario: user._id,
    rolUsuario: user.role,
    accion: 'reset_password',
    entidad: {
      tipo: 'Usuario',
      id: user._id
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent')
    },
    resultado: {
      exitoso: true,
      mensaje: 'Contraseña actualizada'
    }
  });

  // 4) Log in al usuario
  createSendToken(user, 200, req, res);
});

// Actualizar contraseña (usuario loggeado)
exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Obtener usuario
  const user = await User.findById(req.user.id).select('+password');

  // 2) Verificar si la contraseña actual es correcta
  if (!(await user.comparePassword(req.body.passwordCurrent))) {
    return next(new AppError('Su contraseña actual es incorrecta', 401));
  }

  // 3) Actualizar contraseña
  user.password = req.body.password;
  await user.save();

  // 4) Registrar cambio
  await AuditLog.registrar({
    usuario: user._id,
    rolUsuario: user.role,
    accion: 'cambiar_password',
    entidad: {
      tipo: 'Usuario',
      id: user._id
    },
    seguridad: {
      ip: req.ip,
      userAgent: req.get('user-agent')
    },
    resultado: {
      exitoso: true,
      mensaje: 'Contraseña actualizada'
    }
  });

  // 5) Log in con nuevo token
  createSendToken(user, 200, req, res);
});
