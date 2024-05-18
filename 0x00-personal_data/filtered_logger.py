#!/usr/bin/env python3
"""
function called filter_datum that
returns the log message obfuscated
"""
import logging
import re
import os
import mysql.connector
from typing import List


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str
                 ) -> str:
    """
    Replace occurrences of field values in a log message
    with a redaction string.

    :param fields: List of strings representing the
        fields to obfuscate.
    :param redaction: String representing what to replace
        the field values with.
    :param message: String representing the log message.
    :param separator: String representing the character
        separating all fields in the log message.
    :return: The obfuscated log message.
    """
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern,
                  lambda m: f"{m.group().split('=')[0]}={redaction}",
                  message
                  )


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class to obfuscate sensitive
    information in log records.
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter with the fields to be redacted.

        :param fields: List of strings representing the fields to obfuscate.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record, redacting sensitive information.

        :param record: The log record to be formatted.
        :return: The formatted string with sensitive information redacted.
        """
        original_message = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields,
                            self.REDACTION,
                            original_message,
                            self.SEPARATOR
                            )


# Define the PII_FIELDS constant
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """
    Create and configure a logger with a stream handler
    and a redacting formatter.

    :return: Configured logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger


def get_db():
    """
    Obtain a database connection using credentials from environment variables.

    :return: A MySQL database connection object.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    connection = mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )

    return connection


def main():
    """
    Retrieve all rows from the 'users' table in the database and log each row
    with sensitive information redacted.
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")
    rows = cursor.fetchall()

    logger = get_logger()

    for row in rows:
        message = "; ".join([f"{key}={value}" for key, value in row.items()])
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
