const mongoose = require("mongoose");

const Schema = mongoose.Schema;

//definir un esquema de usuario

const usuarioSchema = new Schema({
  //un string obligatorio con un nombre de usuario
  nombreUsuario: {
    type: String,
    required: true,
  },
  //un string obligatorio
  email: {
    type: String,
    required: true,
  },
  contraseña: {
    type: String,
    required: true,
  },
  tareas: [
    {
      type: Schema.Types.ObjectId,
      ref: "Tareas",
    },
  ],
});

//creamos un modelo que se llama usuario y este tendrá la estructura que definimos anteriormente (usuarioSchema). Lo exportamos para poder usarlo en otro archivo del proyecto
module.exports = mongoose.model("Usuario", usuarioSchema);
