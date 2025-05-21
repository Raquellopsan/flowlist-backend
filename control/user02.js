const router = require("express").Router();
// Importamos el middleware de autenticación para proteger rutas que requieran autenticación
const authMiddleware = require("../middleware/authMiddleware");
// Importamos los servicios para manejar el registro, login, logout y obtener detalles del usuario
const {
  registro,
  login,
  logout,
  detallesUsuario,
} = require("../servicios/user");

// Definimos la ruta para el registro de un nuevo usuario
router.post("/registro", registro);

// Definimos la ruta para el login de un usuario
router.post("/login", login);

// Definimos la ruta para el logout de un usuario
router.post("/logout", logout);

// Definimos la ruta para obtener los detalles del usuario, esta ruta requiere autenticación (middleware authMiddleware)
router.get("/detallesUsuario", authMiddleware, detallesUsuario);

// Exportamos el enrutador para que pueda ser usado en otros archivos
module.exports = router;
