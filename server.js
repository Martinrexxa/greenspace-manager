const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const sql = require("mssql");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

const dbConfig = {
    user: "sa",
    password: "1234",
    server: "MARTIN\\MARTINREXXA",
    database: "Sistema_riego",
    options: { trustServerCertificate: true }
};

// ======================
//        HTML
// ======================
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ======================
//        LOGIN
// ======================
app.post("/api/login", async (req, res) => {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
        return res.json({ success: false, message: "Faltan datos de login" });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // ================================
        //     CONSULTA ARREGLADA
  const result = await pool.request()
    .input("usuario", sql.VarChar(50), usuario)
    .query(`
        SELECT 
            u.UsuarioID,
            u.Usuario,
            u.Correo,
            u.Estado,
            u.FechaRegistro,
            r.Nombre AS RolNombre,
            e.Nombre AS EmpleadoNombre,
            e.Apellido AS EmpleadoApellido,
            u.ContrasenaHash
        FROM Usuarios u
        LEFT JOIN Roles r ON u.RolID = r.RolID
        LEFT JOIN Empleados e ON u.EmpleadoID = e.ID_empleado
        WHERE u.Usuario = @usuario
    `);


        if (result.recordset.length === 0) {
            return res.json({ success: false, message: "Usuario no encontrado" });
        }

        const user = result.recordset[0];

        if (user.Estado === 0) {
            return res.json({ success: false, message: "Usuario inactivo" });
        }

        const match = await bcrypt.compare(contrasena, user.ContrasenaHash);

        if (!match) {
            return res.json({ success: false, message: "Contraseña incorrecta" });
        }

        // Elimino el hash para no mandarlo al frontend
       return res.json({
    success: true,
    message: "Login correcto",
    redirect: "/dashboard",
    user: {
        nombreCompleto: `${user.EmpleadoNombre} ${user.EmpleadoApellido}`,
        rol: user.RolNombre,
        correo: user.Correo,
        usuario: user.Usuario
    }
});



    } catch (err) {
        console.log("Error en login:", err);
        return res.status(500).json({ success: false, message: "Error en el servidor" });
    }
});

// ======================
//      CREAR USUARIO
// ======================
app.post("/api/usuarios/create", async (req, res) => {
    const { nombre, correo, usuario, contrasena, rolID, empleadoID } = req.body;

    if (!nombre || !correo || !usuario || !contrasena || !rolID || !empleadoID) {
        return res.json({ success: false, message: "Faltan datos obligatorios" });
    }

    try {
        const hash = await bcrypt.hash(contrasena, 10);
        const pool = await sql.connect(dbConfig);

        await pool.request()
            .input("Nombre", sql.VarChar(120), nombre)
            .input("Correo", sql.VarChar(150), correo)
            .input("Usuario", sql.VarChar(50), usuario)
            .input("ContrasenaHash", sql.VarChar(255), hash)
            .input("Estado", sql.Bit, 1)
            .input("FechaRegistro", sql.DateTime, new Date())
            .input("RolID", sql.Int, rolID)
            .input("EmpleadoID", sql.Int, empleadoID)
            .query(`
                INSERT INTO Usuarios
                (Nombre, Correo, Usuario, ContrasenaHash, Estado, FechaRegistro, RolID, EmpleadoID)
                VALUES 
                (@Nombre, @Correo, @Usuario, @ContrasenaHash, @Estado, @FechaRegistro, @RolID, @EmpleadoID)
        `);

        return res.json({ success: true, message: "Usuario creado correctamente" });

    } catch (err) {
        console.log("Error al crear usuario:", err);
        return res.status(500).json({ success: false, message: "Error en el servidor" });
    }
});

// ======================
//      ROLES
// ======================
app.get("/api/roles", async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request().query(`SELECT RolID, Nombre FROM Roles`);
        res.json({ success: true, roles: result.recordset });

    } catch (err) {
        res.status(500).json({ success: false, message: "Error cargando roles" });
    }
});

// ======================
//     EMPLEADOS
// ======================
app.get("/api/empleados", async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request().query(`
            SELECT ID_empleado, Nombre, Apellido FROM Empleados
        `);
        res.json({ success: true, empleados: result.recordset });

    } catch (err) {
        res.status(500).json({ success: false, message: "Error cargando empleados" });
    }
});

// ======================
app.listen(3000, () => {
    console.log("🔥 Servidor corriendo en http://localhost:3000");
});
