const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

// Validación de registro
const validateSignup = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('El nombre es requerido')
    .isLength({ min: 2 })
    .withMessage('El nombre debe tener al menos 2 caracteres'),
  body('email')
    .trim()
    .notEmpty()
    .withMessage('El email es requerido')
    .isEmail()
    .withMessage('Email inválido')
    .normalizeEmail(),
  body('password')
    .trim()
    .notEmpty()
    .withMessage('La contraseña es requerida')
    .isLength({ min: 8 })
    .withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial'),
  body('role')
    .trim()
    .notEmpty()
    .withMessage('El rol es requerido')
    .isIn(['doctor', 'paciente'])
    .withMessage('Rol inválido')
];

// Validación de login
const validateLogin = [
  body('email')
    .trim()
    .notEmpty()
    .withMessage('El email es requerido')
    .isEmail()
    .withMessage('Email inválido')
    .normalizeEmail(),
  body('password')
    .trim()
    .notEmpty()
    .withMessage('La contraseña es requerida')
];

// Validación de cambio de contraseña
const validatePasswordUpdate = [
  body('passwordCurrent')
    .trim()
    .notEmpty()
    .withMessage('La contraseña actual es requerida'),
  body('password')
    .trim()
    .notEmpty()
    .withMessage('La nueva contraseña es requerida')
    .isLength({ min: 8 })
    .withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial')
];

// Rutas públicas
router.post('/signup', validateSignup, authController.signup);
router.post('/login', validateLogin, authController.login);
router.post('/forgot-password', 
  body('email').isEmail().withMessage('Email inválido'),
  authController.forgotPassword
);
router.post('/reset-password/:token',
  body('password').isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres'),
  authController.resetPassword
);

// Rutas protegidas
router.use(protect); // Middleware de autenticación para todas las rutas siguientes

router.post('/logout', authController.logout);
router.patch('/update-password', validatePasswordUpdate, authController.updatePassword);

module.exports = router;
