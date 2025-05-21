// Importamos las dependencias necesarias
const express = require("express");
const servidor = express();
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config(); // Cargamos las variables de entorno
require("./conexion/mongo"); // Conectamos con la base de datos MongoDB
const usuarioApis = require("./control/user02"); // Rutas para las operaciones de usuario
const tareaApis = require("./control/tarea02"); // Rutas para las operaciones de tareas

// Configuramos el middleware CORS para permitir solicitudes desde el frontend
servidor.use(
  cors({
    origin: "http://localhost:5173", // Frontend (puerto donde se ejecuta la app)
    credentials: true, // Permite el envío de cookies
    methods: ["GET", "POST", "PUT", "DELETE"], // Métodos HTTP permitidos
    allowedHeaders: ["Content-Type", "Authorization"], // Cabeceras permitidas
  })
);

// Configuramos el middleware para procesar el cuerpo de las solicitudes como JSON
servidor.use(express.json());

// Configuramos el middleware para analizar las cookies de la petición
servidor.use(cookieParser());

// Rutas para los endpoints de usuario y tarea
servidor.use("/api/v1", usuarioApis); // Rutas de usuario
servidor.use("/api/v1", tareaApis); // Rutas de tareas

// Middleware para la ruta raíz, para probar que el servidor está funcionando
servidor.get("/", (peticion, respuesta) => {
  respuesta.send("estoy creando el backend");
});

// Configuración final para iniciar el servidor
servidor.listen(`${process.env.PORT}`, () => {
  console.log(
    `El servidor está funcionando en el puerto = ${process.env.PORT}`
  );
});
