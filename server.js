const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

// Inicializa Firebase Admin SDK
const serviceAccount = require("./easyorder-grupo07-firebase-adminsdk-fbsvc-1944b0db27");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

/**
 * Endpoint para asignar un claim personalizado a un usuario
 */
app.post("/setRole", async (req, res) => {
  const { uid, role, local } = req.body;

  console.log("Datos recibidos en el servidor:", req.body); //verifica datos recibidos

  if (!uid || !role || !local) {
    return res.status(400).json({ error: "Faltan datos (uid, role o local)" });
  }

  try {
    await admin.auth().setCustomUserClaims(uid, { role, local });
    res.json({ success: true, message: `Rol '${role}' y local '${local}' asignado a UID: ${uid}` });
    console.log("Claims asignados:", { uid, role, local });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Endpoint para verificar el token y obtener los custom claims
 */
app.post("/getClaims", async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: "Token no proporcionado" });
  }

  try {
    // Verificar el idToken usando Firebase Admin SDK
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    console.log("Token decodificado:", decodedToken)

    // Acceder a los claims personalizados
    const role = decodedToken.role;
    const local = decodedToken.local;

    if (!role || !local) {
      return res.status(403).json({ error: "El usuario no tiene los claims necesarios" });
    }

    // Devolver los claims al cliente
    res.json({ success: true, role, local });
  } catch (error) {
    res.status(500).json({ error: "Token inválido o error al verificar", message: error.message });
  }
});

/**
 * Endpoint para asignar un claim personalizado solo al SUPERUSER (en teoria solo se usa una sola vez porque el super user no se borra)
 */
app.post("/setSuperRole", async (req, res) => {
  const { uid, role} = req.body;

  console.log("Datos recibidos en el servidor:", req.body); //verifica datos recibidos

  if (!uid || !role) {
    return res.status(400).json({ error: "Faltan datos (uid o role)" });
  }

  try {
    await admin.auth().setCustomUserClaims(uid, { role });
    res.json({ success: true, message: `Rol '${role}' asignado a UID: ${uid}` });
    console.log("Claims asignados:", { role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


/**
 * Endpoint para verificar el token y obtener los custom claims solo del super user esto es mas testeo
 */
app.post("/getClaimsSuper", async (req, res) => {
  console.log("Solicitud recibida en /getClaimsSuper"); // Log para confirmar que la solicitud ha llegado

  const { idToken } = req.body;
  console.log("Token recibido:", idToken); // Log del token recibido

  if (!idToken) {
      return res.status(400).json({ error: "Token no proporcionado" });
  }

  try {
      // Verificar el idToken usando Firebase Admin SDK
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      console.log("Token decodificado:", decodedToken); // Log del token decodificado

      // Acceder a los claims personalizados
      const role = decodedToken.role;

      if (!role) {
          console.log("Rol no encontrado en el token."); // Log si el rol no está presente
          return res.status(403).json({ error: "El usuario no tiene los claims necesarios" });
      }

      // Devolver los claims al cliente
      res.json({ success: true, role});
      console.log("Claims devueltos:", { success: true, role}); // Log de los claims devueltos
  } catch (error) {
      console.error("Error al verificar el token:", error.message); // Log del error
      res.status(500).json({ error: "Token inválido o error al verificar", message: error.message });
  }
});

/**
 * Endpoint para eliminar un usuario de Firebase Authentication pasando el uid del usuario que se queiera eliminar
 */
app.delete("/eliminarUsuario/:uid", async (req, res) => {
  const uid = req.params.uid; // Obtiene el UID del parámetro de la URL

  if (!uid) {
      return res.status(400).json({ error: "UID no proporcionado" });
  }

  try {
      await admin.auth().deleteUser(uid); // Eliminar el usuario por UID
      res.json({ success: true, message: `Usuario con UID ${uid} eliminado con éxito` });
      console.log("Usuario eliminado:", uid);
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});



app.get("/testConnection", (req, res) => {
  res.json({ message: "Conexión exitosa" });
});

// Servidor en puerto 3000 usando HTTP
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor1 ejecutándose en http://localhost:${PORT}`);
});



