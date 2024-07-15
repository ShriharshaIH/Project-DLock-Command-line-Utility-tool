# Project-DLock-Command-line-Utility-tool
DataLock or Dlock is Command line Utility tool for Encryption and Decryption of files in C 

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contributing](#contributing)
- [Contact](#contact)

## Introduction

This project is a C program that implements encryption and decryption functionalities using OpenSSL libraries. The program allows users to encrypt files with a password and generate a corresponding .lock file. Users can then use the same password to decrypt the .lock file and retrieve the original file.

## Features

- Encrypt files with a password
- Decrypt .lock files with the corresponding password
- Uses SHA-256 for password hashing
- Polymorphic encryption for enhanced security

## Prerequisites

- OpenSSL Library (version 1.1.1 or later)

## Installation

1. Clone this repository to your local machine.
2. Make sure you have the OpenSSL library installed.
3. Compile the C program using a C compiler (e.g., gcc).

## Usage

To encrypt a file, run the following command:
dlock.exe lock <input_file> <password>

To decrypt a .lock file, run the following command:
dlock.exe <input_file.lock> <password>


## License

This project is licensed under the MIT License.

## Contributing

Contributions to this project are welcome! If you find any issues or want to suggest improvements, feel free to create a pull request or open an issue.


