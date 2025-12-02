# api-tienda

Scaffolded Spring Boot API (Product) targeting Java 21.

Requirements
- JDK 21 installed and JAVA_HOME pointing to it
- Maven 3.8+ installed

Build and run
```powershell
# from repository root
mvn -v           # confirm Maven and Java 21
mvn clean package
mvn spring-boot:run
```

Access
- API base: http://localhost:8080/api/products

Database (MySQL)
- The project is configured to use a MySQL database named `tienda` on localhost and default port 3306.
- Default datasource settings are in `src/main/resources/application.properties` and use user `root`.

Create the database and grant privileges (run in MySQL shell):

```sql
CREATE DATABASE tienda CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON tienda.* TO 'root'@'localhost' IDENTIFIED BY '';
FLUSH PRIVILEGES;
```

If your root user has a password, set it in `application.properties` under `spring.datasource.password`.
