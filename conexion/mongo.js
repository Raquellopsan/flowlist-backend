// Importamos mongoose para poder trabajar con MongoDB
const mongoose = require("mongoose");

// Función asincrónica para realizar la conexión a la base de datos
const conexion = async () => {
  try {
    // Intentamos conectar a la base de datos usando la URL almacenada en las variables de entorno
    await mongoose.connect(`${process.env.MONGO_URI}`);
    console.log("conectado"); // Si la conexión es exitosa, mostramos un mensaje en consola
  } catch (error) {
    // Si ocurre un error durante la conexión, lo capturamos y mostramos en consola
    console.log(error);
  }

  // await mongoose.connect(`${process.env.MONGO_URL}`);
  // console.log("conectado");
};

// Llamamos a la función para que la conexión se realice al ejecutar el script
conexion();
