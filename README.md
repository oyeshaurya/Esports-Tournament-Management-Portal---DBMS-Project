Esports Tournament Management Portal
Project Overview
The Esports Tournament Management Portal is a web application built with Python Flask (app.py), plain HTML and CSS, and SQL for database management. This project was developed as part of the Database Management Systems (DBMS) course to create a simple yet functional platform to organize and manage esports tournaments.

The portal enables team registrations, match scheduling, and score tracking using SQL queries directly from the Flask backend without relying on templating engines like Jinja2. Static HTML pages serve as the frontend, with Flask handling routing and database operations.

Features
Team Registration:
Teams can register through HTML forms, with data stored and managed in an SQL database.

Tournament & Match Scheduling:
Organizers can schedule matches and update tournament details by interacting with the database through the backend.

Score Tracking:
Match results can be entered and updated directly in the database.

Simple Frontend:
Static HTML and CSS files provide the user interface, making the application straightforward and easy to navigate.

Database Integration:
Uses SQL queries executed in the Flask backend to maintain and manipulate tournament-related data.

Technologies Used:
Backend: Python Flask (app.py)

Frontend: HTML, CSS (static pages)

Database: MySQL

Routing and Logic: Flask handles HTTP requests and executes SQL queries

Project Structure
app.py – Flask application that handles routing, receives form data, executes SQL queries, and serves HTML files.

templates/ or static/ (depending on your setup) – Contains static HTML and CSS files used as the frontend.

How to Run Locally
1. Clone the repository:
git clone https://github.com/yourusername/esports-tournament-management-portal.git

2. Install Flask:
pip install flask


3. Set up the SQL database and configure the connection details in app.py.

4. Run the application:
python app.py

5. Open your web browser and go to http://localhost:5000 to access the portal.

Future Improvements:
1. Add dynamic page rendering with templating engines or JavaScript

2. Implement user authentication and role management

3. Introduce API endpoints for better modularity

4. Enhance UI/UX with interactive front-end frameworks

Conclusion:
This project highlights the integration of SQL database operations with a Flask backend and static frontend to create a functional esports tournament management system. It emphasizes core DBMS concepts and web development fundamentals without the complexity of advanced templating, making it an ideal learning project.

