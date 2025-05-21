// Importamos el modelo de tarea para interactuar con la base de datos
const tarea = require("../models/tareas");

// Función para crear nuevas tareas
const añadirTarea = async (peticion, respuesta) => {
  try {
    // Extraemos los datos enviados en la petición
    const { titulo, descripcion, prioridad, estado } = peticion.body;
    const { user } = peticion;

    // Validaciones para asegurarnos de que los campos requeridos estén presentes
    if (!titulo || !descripcion) {
      return respuesta
        .status(400)
        .json({ error: "Debes rellenar todos los campos" });
    }
    if (titulo.length < 6) {
      return respuesta
        .status(400)
        .json({ error: "El título debe tener mínimo 6 caracteres" });
    }
    if (descripcion.length < 6) {
      return respuesta
        .status(400)
        .json({ error: "La descripción debe tener mínimo 6 caracteres" });
    }

    // Creamos la nueva tarea con los datos recibidos
    const nuevaTarea = new tarea({ titulo, descripcion, prioridad, estado });
    await nuevaTarea.save(); // Guardamos la tarea en la base de datos

    // Asociamos la nueva tarea al usuario que la ha creado
    user.tareas.push(nuevaTarea._id);
    await user.save(); // Guardamos el usuario con la nueva tarea asociada

    // Respondemos con un mensaje de éxito
    return respuesta.status(200).json({ success: "Tarea añadida con éxito" });
  } catch (error) {
    // Si ocurre un error, respondemos con un error 500
    return respuesta.status(500).json({ error: "Error interno del servidor" });
  }
};

// Función para editar tareas ya existentes
const editarTarea = async (peticion, respuesta) => {
  try {
    // Extraemos el id de la tarea desde los parámetros de la petición
    const { id } = peticion.params;
    // Extraemos los nuevos datos de la tarea desde el cuerpo de la petición
    const { titulo, descripcion, prioridad, estado } = peticion.body;

    // Validaciones de los campos, similar a la creación de tarea
    if (!titulo || !descripcion) {
      return respuesta
        .status(400)
        .json({ error: "Debes rellenar todos los campos" });
    }
    if (titulo.length < 6) {
      return respuesta
        .status(400)
        .json({ error: "El título debe tener mínimo 6 caracteres" });
    }
    if (descripcion.length < 6) {
      return respuesta
        .status(400)
        .json({ error: "La descripción debe tener mínimo 6 caracteres" });
    }

    // Actualizamos la tarea en la base de datos usando el id
    await tarea.findByIdAndUpdate(id, {
      titulo,
      descripcion,
      prioridad,
      estado,
    });

    // Respondemos con un mensaje de éxito
    return respuesta.status(200).json({ success: "Tarea actualizada" });
  } catch (error) {
    // Si ocurre un error, respondemos con un error 404
    return respuesta.status(404).json({ error: "Error interno del servidor" });
  }
};

// Función para eliminar una tarea
const eliminarTarea = async (peticion, respuesta) => {
  try {
    // Extraemos el id de la tarea a eliminar desde los parámetros de la petición
    const { id } = peticion.params;

    // Buscamos y eliminamos la tarea en la base de datos
    const tareaEliminada = await tarea.findByIdAndDelete(id);

    // Si no encontramos la tarea, respondemos con un error 404
    if (!tareaEliminada) {
      return respuesta.status(404).json({ error: "Tarea no encontrada" });
    }

    // Respondemos con un mensaje de éxito
    return respuesta.status(200).json({ success: "Tarea eliminada con éxito" });
  } catch (error) {
    // Si ocurre un error, respondemos con un error 500
    return respuesta.status(500).json({ error: "Error al eliminar la tarea" });
  }
};

// Exportamos las funciones para que puedan ser usadas en otros archivos
module.exports = { añadirTarea, editarTarea, eliminarTarea };
