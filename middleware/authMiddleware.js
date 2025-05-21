const jwt = require("jsonwebtoken");
const User = require("../models/usuario");

// es un middleware de autenticación en el que va a comprobar que el usuario tenga un token (JWT) valido en las cookies que ya hicimos, verifica el token, después busca al usuario en la base de datos y adjuntamos el u encontrado a la petición para que s epueda usar después

const authMiddleware = async (peticion, respuesta, siguiente) => {
  const token = peticion.cookies.flowlistUserToken; // extraemos el token de las cookies en concreto del flowlistUserToken que ya nombramos en user.js donde pasabamos el token a las cookies

  // console.log(token);

  try {
    if (!token) {
      return respuesta.status(401).json({ error: "nuevo usuario" });
    }
    // si no encontramos el token el status es 401(no autorizado) para despues indicar que es un nuevo usuario

    const verificado = jwt.verify(token, process.env.JWT_SECRET); // verificamos el token usando la clave secreta que pusimos en el .env. Si este es válido lo descodifica
    const user = await User.findById(verificado.id); // despues buscamos en la base de datos un u que cuyo ID sea el mismo que hay dentro del token ya descodificado

    if (!user) {
      return respuesta.status(404).json({ message: "usuario no encontrado" });
    }
    // si el usuario no se encuentra reponde con un 404

    peticion.user = user; //si todo ha salido ok añadimos el usuario a la peticion
    siguiente();
  } catch (error) {
    return respuesta.status(401).json({ message: "invalid token" }); // si algo falla por ejemplo si el token no es válido respondemos con un 401
  }
};

module.exports = authMiddleware;
