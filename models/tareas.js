const mongoose = require("mongoose");
const Schema = mongoose.Schema;

//plantilla para crear las tareas en la base de datos

const tareaSchema = new Schema({
  //un string obligatorio
  titulo: {
    type: String,
    required: true,
  },
  //un string obligatorio
  descripcion: {
    type: String,
    required: true,
  },
  //un string obligatorio, solo puede tener uno de esos tres valores, si no se define se toma por defecto prioridad baja
  prioridad: {
    type: String,
    required: true,
    enum: ["baja", "media", "alta"],
    default: "baja",
  },
  //un string obligatorio, solo puede colocarse en uno de esos 3 valores. Si no se define se colocará en nuevasTareas
  estado: {
    type: String,
    required: true,
    enum: ["sinComenzar", "enProceso", "completadas"],
    default: "sinComenzar",
  },
});

//creamos un modelo que se llama tarea y este tendrá la estructura que definimos anteriormente (tareaSchema). Lo exportamos para poder usarlo en otro archivo del proyecto
module.exports = mongoose.model("Tareas", tareaSchema);
