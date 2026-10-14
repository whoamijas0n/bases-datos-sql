import os
import time
import psycopg2
from psycopg2 import extras
from flask import Flask, render_template, request

# =====================================================================
# LABORATORIO EDUCATIVO - BASES DE DATOS II
# Entorno de pruebas académicas para análisis de consultas y seguridad
# =====================================================================

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "db")
DB_NAME = os.getenv("DB_NAME", "labdb")
DB_USER = os.getenv("DB_USER", "labuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "labpassword123")
DB_PORT = int(os.getenv("DB_PORT", "5432"))

def get_db_connection():
    """Establece conexión a la base de datos PostgreSQL con reintentos."""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                port=DB_PORT,
                connect_timeout=3
            )
            return conn
        except psycopg2.OperationalError as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(1)

def ensure_database_seeded():
    """Asegura que las tablas y datos de prueba existan en la base de datos."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'estudiante',
                email VARCHAR(100)
            );
            CREATE TABLE IF NOT EXISTS academic_records (
                id SERIAL PRIMARY KEY,
                student_username VARCHAR(50) NOT NULL,
                subject VARCHAR(100) NOT NULL,
                grade NUMERIC(5, 2) NOT NULL,
                comments TEXT
            );
        """)
        conn.commit()

        # Sembrar usuarios si la tabla estuviera vacía
        cur.execute("SELECT count(*) FROM users;")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO users (username, password, role, email) VALUES
                    ('admin', 'AdminPass2026#', 'administrador', 'admin@lab.edu.local'),
                    ('prof_garcia', 'ProfesorSecure99!', 'docente', 'garcia@lab.edu.local'),
                    ('estudiante1', 'Estudiante123', 'estudiante', 'alumno1@lab.edu.local')
                ON CONFLICT DO NOTHING;
            """)
            conn.commit()

        # Sembrar registros académicos si la tabla estuviera vacía
        cur.execute("SELECT count(*) FROM academic_records;")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO academic_records (student_username, subject, grade, comments) VALUES
                    ('estudiante1', 'Bases de Datos II', 95.50, 'Aprobado con honores'),
                    ('estudiante1', 'Seguridad de la Informacion', 91.00, 'Excelente participacion'),
                    ('prof_garcia', 'Auditoria de Sistemas', 100.00, 'Catedratico titular');
            """)
            conn.commit()

        cur.close()
        conn.close()
    except Exception as e:
        print("Error asegurando datos en DB:", e)

@app.route("/", methods=["GET", "POST"])
def login():
    ensure_database_seeded()
    context = {
        "logged_in": False,
        "user_data": None,
        "raw_query": None,
        "query_mode": "vulnerable",
        "execution_time_ms": None,
        "db_error": None,
        "status_message": None,
        "submitted_username": "",
    }

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query_mode = request.form.get("mode", "vulnerable")

        context["query_mode"] = query_mode
        context["submitted_username"] = username

        start_time = time.perf_counter()
        conn = None

        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=extras.DictCursor)

            if query_mode == "vulnerable":
                # MODO EDUCATIVO VULNERABLE: Concatenación directa de entradas de usuario
                # Permite estudiar cómo el motor SQL parsea sintaxis arbitraria
                query = f"SELECT id, username, role, email FROM users WHERE username = '{username}' AND password = '{password}'"
                context["raw_query"] = query
                cursor.execute(query)
            else:
                # MODO SEGURO: Parámetros tipados (Prepared Statements / Parameterized Query)
                # La base de datos trata la entrada del usuario como literal de datos, no como código ejecutable
                query = "SELECT id, username, role, email FROM users WHERE username = %s AND password = %s"
                context["raw_query"] = f"{query} [Parametros: username='{username}', password='***']"
                cursor.execute(query, (username, password))

            records = cursor.fetchall()
            execution_time = (time.perf_counter() - start_time) * 1000
            context["execution_time_ms"] = round(execution_time, 2)

            if records:
                context["logged_in"] = True
                context["status_message"] = "Autenticación exitosa en el sistema."
                # Almacenar filas obtenidas para inspección académica
                context["user_data"] = [dict(row) for row in records]
            else:
                context["status_message"] = "Credenciales incorrectas: ningún registro coincide con la consulta."

            cursor.close()
            conn.close()

        except psycopg2.Error as err:
            execution_time = (time.perf_counter() - start_time) * 1000
            context["execution_time_ms"] = round(execution_time, 2)
            context["db_error"] = {
                "message": err.pgerror or str(err),
                "code": err.pgcode
            }
            context["status_message"] = "Excepción en el motor de base de datos."
            if conn:
                conn.close()
        except Exception as ex:
            context["status_message"] = f"Error del servidor: {str(ex)}"

    return render_template("login.html", **context)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
