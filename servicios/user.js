// Importamos los modelos y librerías necesarias
const User = require("../models/usuario");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const tareas = require("../models/tareas");

// Función para registrar un nuevo usuario
const registro = async (peticion, respuesta) => {
  try {
    // Extraemos los datos del cuerpo de la petición
    const { nombreUsuario, email, contraseña } = peticion.body;

    // Verificamos que los campos necesarios estén presentes
    if (!nombreUsuario || !email || !contraseña) {
      return respuesta
        .status(400)
        .json({ error: "Debe rellenar todos los campos" });
    }

    // Validamos que la contraseña tenga al menos 6 caracteres
    if (contraseña.length < 6) {
      return respuesta
        .status(400)
        .json({ error: "La contraseña debe tener mínimo 6 caracteres" });
    }

    // Verificamos si ya existe un usuario con el mismo email o nombre de usuario
    const checkUser = await User.findOne({
      $or: [{ email }, { nombreUsuario }],
    });

    if (checkUser) {
      return respuesta
        .status(400)
        .json({ error: "¡Tu usuario o email ya existen!" });
    } else {
      // Encriptamos la contraseña antes de guardarla
      const salt = await bcrypt.genSalt(10);
      const contraseñaHash = await bcrypt.hash(contraseña, salt);

      // Creamos un nuevo usuario
      const newUser = new User({
        nombreUsuario,
        email,
        contraseña: contraseñaHash, // ← Guardamos la contraseña encriptada
      });

      // Guardamos el nuevo usuario en la base de datos
      await newUser.save();

      return respuesta
        .status(200)
        .json({ success: "Te has registrado con éxito" });
    }
  } catch (error) {
    // En caso de error, respondemos con un error 404
    return respuesta.status(404).json({ error: "Error en el servidor" });
  }
};

// Función para realizar login de un usuario
const login = async (peticion, respuesta) => {
  try {
    // Extraemos los datos del cuerpo de la petición
    const { email, contraseña } = peticion.body;

    // Verificamos que los campos necesarios estén presentes
    if (!email || !contraseña) {
      return respuesta
        .status(400)
        .json({ error: "Debe rellenar todos los campos" });
    }

    // Buscamos el usuario en la base de datos
    const checkUser = await User.findOne({ email });
    if (!checkUser) {
      return respuesta.status(404).json({ error: "Usuario no encontrado" });
    }

    // Comparamos la contraseña ingresada con la encriptada en la base de datos
    const contraseñaValida = await bcrypt.compare(
      contraseña,
      checkUser.contraseña
    );
    if (!contraseñaValida) {
      return respuesta.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Creamos el token JWT con los datos del usuario
    const token = jwt.sign(
      { id: checkUser._id, email: checkUser.email },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Enviamos el token como una cookie para mantener la sesión activa
    respuesta.cookie("flowlistUserToken", token, {
      httpOnly: true, // Cookie solo accesible por el servidor
      sameSite: "lax", // Configuración de cookie para seguridad
      secure: false, // Configurar como true si usas HTTPS
      maxAge: 30 * 24 * 60 * 60 * 1000, // Cookie válida por 30 días
    });

    return respuesta
      .status(200)
      .json({ success: "Has iniciado sesión correctamente" });
  } catch (error) {
    return respuesta.status(200).json({ error: "Error en el servidor" });
  }
};

// Función para hacer logout del usuario
const logout = async (peticion, respuesta) => {
  try {
    // Limpiamos la cookie del usuario para finalizar sesión
    respuesta.clearCookie("flowlistUserToken", {
      httpOnly: true,
    });

    return respuesta
      .status(200)
      .json({ message: "Sesión finalizada. ¡Hasta pronto!" });
  } catch (error) {
    return respuesta.status(404).json({
      error: "Error en el servidor",
    });
  }
};

// Función para obtener los detalles del usuario y sus tareas
const detallesUsuario = async (peticion, respuesta) => {
  try {
    const { user } = peticion;

    // Buscamos al usuario por su id y poblamos las tareas asociadas a él
    const getDetails = await User.findById(user._id)
      .populate("tareas") // Traemos las tareas asociadas
      .select("-contraseña"); // Excluimos la contraseña de la respuesta

    if (getDetails) {
      const todasLasTareas = getDetails.tareas;
      let sinComenzar = [];
      let enProceso = [];
      let completadas = [];

      // Clasificamos las tareas por su estado
      todasLasTareas.map((item) => {
        if (item.estado === "sinComenzar") {
          sinComenzar.push(item);
        } else if (item.estado === "enProceso") {
          enProceso.push(item);
        } else {
          completadas.push(item);
        }
      });

      // Respondemos con las tareas clasificadas
      return respuesta.status(200).json({
        success: "success",
        tareas: {
          sinComenzar,
          enProceso,
          completadas,
        },
      });
    }
  } catch (error) {
    return respuesta.status(404).json({
      error: "Error en el servidor",
    });
  }
};

// Exportamos las funciones para ser utilizadas en otras partes de la aplicación
module.exports = { registro, login, logout, detallesUsuario };
