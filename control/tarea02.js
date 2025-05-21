// Importamos el middleware de autenticación para asegurar que el usuario esté autenticado
const authMiddleware = require("../middleware/authMiddleware");
// Importamos los servicios que gestionan las tareas (añadir, editar, eliminar)
const {
  añadirTarea,
  editarTarea,
  eliminarTarea,
} = require("../servicios/tarea");

const router = require("express").Router();

// Definimos la ruta para añadir una nueva tarea. Usamos el middleware para verificar la autenticación
router.post("/anadirTarea", authMiddleware, añadirTarea);

// Definimos la ruta para editar una tarea existente. Usamos el middleware de autenticación y el parámetro :id para identificar la tarea
router.put("/editarTarea/:id", authMiddleware, editarTarea);

// Definimos la ruta para eliminar una tarea existente. También verificamos la autenticación y usamos el parámetro :id
router.delete("/eliminarTarea/:id", authMiddleware, eliminarTarea);

// Exportamos el enrutador para que pueda ser usado en otros archivos
module.exports = router;
