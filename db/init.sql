-- =====================================================================
-- Laboratorio Educativo de Seguridad de Bases de Datos (Bases de Datos II)
-- Entorno controlado y aislado para análisis de consultas y seguridad
-- =====================================================================

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

-- Inserción de usuarios de prueba para el entorno académico
INSERT INTO users (username, password, role, email) VALUES
    ('admin', 'AdminPass2026#', 'administrador', 'admin@lab.edu.local'),
    ('prof_garcia', 'ProfesorSecure99!', 'docente', 'garcia@lab.edu.local'),
    ('estudiante1', 'Estudiante123', 'estudiante', 'alumno1@lab.edu.local')
ON CONFLICT (username) DO NOTHING;

-- Inserción de registros académicos de prueba
INSERT INTO academic_records (student_username, subject, grade, comments) VALUES
    ('estudiante1', 'Bases de Datos II', 95.50, 'Aprobado con honores'),
    ('estudiante1', 'Seguridad de la Informacion', 91.00, 'Excelente participacion'),
    ('prof_garcia', 'Auditoria de Sistemas', 100.00, 'Catedratico titular')
ON CONFLICT DO NOTHING;

-- Asegurar privilegios para el usuario de la aplicación
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO labuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO labuser;
