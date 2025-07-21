const jwt = require("jsonwebtoken");
const User = require("../models/usuario");

const authMiddleware = async (peticion, respuesta, siguiente) => {
  const authHeader = peticion.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return respuesta.status(401).json({ error: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1]; // Bearer <token>

  try {
    const verificado = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(verificado.id);

    if (!user) {
      return respuesta.status(404).json({ message: "usuario no encontrado" });
    }

    peticion.user = user;
    siguiente();
  } catch (error) {
    return respuesta.status(401).json({ message: "Token inválido" });
  }
};

module.exports = authMiddleware;
