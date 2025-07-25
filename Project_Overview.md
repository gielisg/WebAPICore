## C# WebAPI Project with Authentication Library

This document provides an overview of the developed C# WebAPI project, which includes a dedicated authentication and data access library. The project demonstrates key functionalities such as JWT-based authentication, secure password management, and efficient SQL transaction handling using Dapper.

### 1. Project Structure

The solution is organized into two main projects:

*   **`AuthLibrary`**: A .NET Class Library containing the core business logic for authentication, password management, and database interactions. This library is designed to be reusable and can be distributed as a NuGet package.
*   **`WebAPIExample`**: An ASP.NET Core Web API project that consumes the `AuthLibrary` and provides example endpoints demonstrating its usage.

### 2. AuthLibrary - Core Functionalities

The `AuthLibrary` encapsulates the following features:

*   **JWT (JSON Web Token) Management:**
    *   **Refresh JWT Issuance:** A function to generate Refresh JWTs upon successful user login, including configurable expiry times and custom claims (e.g., `Role`, `DSN - Data Source Name`).
    *   **Access JWT Issuance:** A function to generate short-lived Access JWTs using a valid Refresh JWT.
    *   **Anonymous JWTs:** Support for issuing JWTs for unauthenticated (anonymous) access.
    *   **API Key JWTs:** Functionality to generate long-lived JWTs that can serve as API Keys.
*   **Password Management:**
    *   **Password Hashing:** Securely hashes user passwords using `PBKDF2` with a unique salt for each password, generating a corresponding `securityStamp`.
    *   **Password Verification:** Verifies a provided password against a stored hashed password and its `securityStamp`.
*   **SQL Transactions (using Dapper):**
    *   **Flexible SQL Execution:** A function to execute arbitrary SQL queries or stored procedures, accepting a DSN (Data Source Name) and a variable number of parameters.
    *   **Multiple Row Results:** Capable of returning multiple rows from query results.
    *   **Efficient Connection Management:** Utilizes Dapper for efficient database interactions, automatically handling connection opening and closing within the execution scope.

### 3. WebAPIExample - Integration and Usage

The `WebAPIExample` project demonstrates how to integrate and use the `AuthLibrary`'s functionalities:

*   **Authentication Endpoints (`Controllers/AuthController.cs`):**
    *   `/auth/register`: Example endpoint to demonstrate password hashing and `securityStamp` generation.
    *   `/auth/login`: Handles user login, verifies credentials, and issues a Refresh JWT.
    *   `/auth/refresh`: Accepts a Refresh JWT and issues a new Access JWT.
    *   `/auth/anonymous`: Provides an example of obtaining an anonymous JWT.
    *   `/auth/apikey`: Provides an example of obtaining an API Key JWT.
*   **Data Access Endpoint (`Controllers/DataController.cs`):**
    *   `/data/execute`: A protected API endpoint that requires a valid JWT for access. It demonstrates how to use the `AuthLibrary`'s SQL execution function to interact with a database.
*   **JWT Authentication Configuration:**
    *   The `WebAPIExample`'s `Program.cs` is configured to use JWT Bearer authentication, validating incoming JWTs based on the shared secret key.

### 4. NuGet Package Integration

The `AuthLibrary` is consumed by the `WebAPIExample` project as a NuGet package. This approach promotes modularity, reusability, and easier dependency management across multiple projects.

To pack the `AuthLibrary` into a NuGet package (for your reference or if you wish to rebuild it), navigate to the solution's root directory in your terminal and execute the following command:

```bash
dotnet pack AuthLibrary/AuthLibrary.csproj -c Release -o ./packages
```

This command will create the `AuthLibrary.1.0.0.nupkg` file (or similar version) in the `./packages` directory.

### 5. Verification Steps

To verify the project setup and functionality:

1.  **Build the Solution:**
    Navigate to the solution's root directory (`D:\Freelance - Resources\02\Freelance02`) in your terminal and run:
    ```bash
    dotnet build Freelance02.sln
    ```
    This command will compile both `AuthLibrary` and `WebAPIExample`. A successful build will show "Build succeeded." with 0 warnings and 0 errors.

2.  **Run the WebAPIExample Project:**
    From the solution's root directory, run the Web API project:
    ```bash
    dotnet run --project WebAPIExample/WebAPIExample.csproj
    ```
    This will start the Web API, typically on `https://localhost:7000` (or a similar port).

3.  **Test Endpoints:**
    Use a tool like Postman or Swagger UI (accessible via the running Web API's URL, e.g., `https://localhost:7000/swagger`) to test the API endpoints:
    *   **`/auth/register`**: To see how passwords are hashed.
    *   **`/auth/login`**: To obtain a Refresh JWT.
    *   **`/auth/refresh`**: To exchange a Refresh JWT for an Access JWT.
    *   **`/auth/anonymous` / `/auth/apikey`**: To obtain respective JWTs.
    *   **`/data/execute`**: To test a protected endpoint that executes SQL. Remember to include a valid Access JWT in the `Authorization: Bearer <token>` header for this endpoint.
