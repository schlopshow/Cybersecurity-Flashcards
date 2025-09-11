SQL Commands Cheat Sheet
Database Operations

CREATE DATABASE database_name; - Create a new database
SHOW DATABASES; - List all databases
USE database_name; - Switch to a database
DROP DATABASE database_name; - Delete a database

Table Operations

CREATE TABLE table_name (column definitions); - Create a new table
SHOW TABLES; - List all tables in current database
DESCRIBE table_name; - Show table structure
DROP TABLE table_name; - Delete a table
ALTER TABLE table_name ADD column_name datatype; - Add column
ALTER TABLE table_name DROP column_name; - Remove column
ALTER TABLE table_name RENAME COLUMN old_name TO new_name; - Rename column
ALTER TABLE table_name MODIFY column_name new_datatype; - Change column datatype

Data Operations

INSERT INTO table_name VALUES (values); - Insert data into all columns
INSERT INTO table_name (columns) VALUES (values); - Insert data into specific columns
SELECT * FROM table_name; - Select all data from table
SELECT columns FROM table_name; - Select specific columns
UPDATE table_name SET column=value WHERE condition; - Update records
DELETE FROM table_name WHERE condition; - Delete records

Query Modifiers

WHERE condition - Filter results
ORDER BY column ASC/DESC - Sort results
LIMIT number - Limit number of results
LIMIT offset, count - Limit with offset
LIKE 'pattern' - Pattern matching (% for multiple chars, _ for single char)

Logical Operators

AND or && - Both conditions must be true
OR or || - At least one condition must be true
NOT or ! - Negates the condition
!= or <> - Not equal to
