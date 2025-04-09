# User Authentication System

This project is a user authentication system built with **Python**, using **Flask** and **SQLite**. It includes user registration, login, and profile updates, along with OAuth 2.0 login via **Google** and **GitHub**, and password reset via email. Passwords are securely stored using **bcrypt** hashing. The system assumes that the provided email is unique for each user.

It supports multiple languages (Portuguese, English, and Spanish), with a dynamically translatable user interface. Role-based access control is also included, allowing only administrators to access user management features.

---

## Features

- **User Registration:** users can register with an email, password, and name.
- **User Login:** existing users can log in.
- **User Update:** admins can edit user data or block users (set status to inactive).
- **Password Recovery:** users can request a reset link via email.
- **OAuth Login:** users can log in using Google or GitHub accounts.
- **Multi-language Support:** Portuguese, English, and Spanish with dynamic UI translation.
- **Role-Based Access Control:** admin-only access for user management (set `is_admin` to `1` in `schema.sql` for admin).

