# MySQL Command Cheat Sheet:

## DATABASE OPERATIONS:
CREATE DATABASE database_name;
SHOW DATABASES;
USE database_name;
DROP DATABASE database_name;

## TABLE OPERATIONS:
CREATE TABLE table_name (column1 datatype, column2 datatype, ...);
SHOW TABLES;
DESCRIBE table_name;
DROP TABLE table_name;
ALTER TABLE table_name ADD column_name datatype;
ALTER TABLE table_name RENAME COLUMN old_name TO new_name;
ALTER TABLE table_name MODIFY column_name new_datatype;
ALTER TABLE table_name DROP column_name;

## DATA MANIPULATION:
INSERT INTO table_name VALUES (value1, value2, ...);
INSERT INTO table_name (column1, column2) VALUES (value1, value2);
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
UPDATE table_name SET column1 = value1 WHERE condition;
DELETE FROM table_name WHERE condition;

## FILTERING AND SORTING:
SELECT * FROM table_name WHERE condition;
SELECT * FROM table_name WHERE column LIKE 'pattern%';
SELECT * FROM table_name ORDER BY column ASC/DESC;
SELECT * FROM table_name LIMIT number;
SELECT * FROM table_name LIMIT offset, count;

## CONNECTION:
mysql -u username -p
mysql -u username -h hostname -P port -p
