# Django-CBV-ToDo: TaskMaster Project 🚀

A robust, production-ready Task Management Application built with **Django 5**, utilizing **Class-Based Views (CBVs)** for the frontend and **Django Rest Framework (DRF)** for API endpoints. This project demonstrates a hybrid architecture—combining a server-rendered Multi-Page Application (MPA) with modern, dynamic JavaScript interactions.

## 🌟 Project Overview

**TaskMaster** is designed to demonstrate advanced web development patterns, including:
-   **Hybrid Frontend**: Traditional Django templates enhanced with modular vanilla JavaScript for dynamic behavior (modals, AJAX).
-   **Scalable Backend**: RESTful API design using DRF and JWT authentication.
-   **Async Task Processing**: Integrated with **Celery** and **Redis** for background tasks (e.g., periodic cleanup).
-   **Containerization**: Fully Dockerized development environment including web, worker, scheduler, database, and mail server.

### 🛠️ Tech Stack
-   **Backend**: Python 3.13, Django 5.2, Django Rest Framework (DRF)
-   **Authentication**: JWT (JSON Web Tokens) via `djangorestframework-simplejwt` + Django Session Auth
-   **Database**: SQLite (Dev) / Extensible to PostgreSQL
-   **Async Tasks**: Celery 5.x, Redis 7.x
-   **Frontend**: Django Templates (Jinja-style), Vanilla CSS3 (Variables, Flexbox/Grid), Modular JavaScript (ES6+)
-   **Infrastructure**: Docker, Docker Compose, Nginx (Reverse Proxy)
-   **Dev Tools**: SMTP4Dev (Email Capture), Flake8, Black

---

## ✨ Features

### Authentication & Security
-   **User Accounts**: Sign Up, Login, and Logout functionality using Django's Authentication System.
-   **Password Management**:
    -   Secure "Change Password" flow.
    -   **Threaded Password Reset**: Asynchronous email sending using `smtp4dev` to prevent request blocking.
-   **Security**: CSRF protection, protected views (`LoginRequiredMixin`), and JWT token management.
-   **Token Cleanup**: Automated Celery Beat task to clean up expired/blacklisted JWT tokens daily.

### Dashboard & Task Management
-   **Interactive Dashboard**: View, and manage tasks in a clean UI.
-   **CRUD Operations**: Create, Read, Update (Toggle Complete), and Delete tasks.
-   **Assignments (Sub-tasks)**:
    -   Add strictly related assignments to tasks.
    -   Manage assignments via AJAX without page reloads.
-   **Pagination**: Server-side pagination (5 tasks per page) for performance.
-   **Dynamic Modals**: Custom JavaScript modal system for creating tasks and managing sub-tasks.
-   **Notification System**: Toast notifications for user feedback (Success/Error messages).

---

## 📂 Project Structure

```bash
Django-CBV-ToDo/
├── core/
│   ├── accounts/           # User authentication app (Views, Forms, APIs)
│   ├── todo/               # Task management app (Models, Views, APIs)
│   ├── core/               # Project settings and configuration
│   ├── templates/          # Global and app-specific Django templates
│   │   ├── accounts/       # Login, Register, Password templates
│   │   ├── todo/           # Dashboard template
│   │   ├── includes/       # Reusable components (Navbar, Messages, Pagination)
│   │   └── base.html       # Base layout with static assets
│   ├── staticfiles/        # Raw CSS/JS source files
│   │   ├── css/            # Modular CSS (main, layout, components, modals)
│   │   └── js/             # Modular JS (app, ui, auth, tasks)
│   ├── manage.py
│   └── ...
├── docker-compose.yml      # Service orchestration (Backend, Nginx, Redis, Celery, SMTP4Dev)
├── nginx-proxy.conf        # Nginx configuration
└── requirements.txt        # Python dependencies
```

---

## 🚀 Setup Instructions

### 1. Prerequisities
-   [Docker Desktop](https://www.docker.com/products/docker-desktop) (or Docker Engine)
-   Git

### 2. Clone the Repository
```bash
git clone https://github.com/mahdi921/Django-CBV-ToDo.git
cd Django-CBV-ToDo
```

### 3. Environment Configuration
The project uses `python-decouple`. Create a `.env` file in the `core/` directory (optional for Docker as it sets defaults, but recommended for production):
```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=your-allowed-hosts-here-divided-with-comma
```

### 4. Running with Docker (Recommended)
This brings up the entire stack: Django, Nginx, Redis, Celery Worker, Celery Beat, and SMTP4Dev.

```bash
docker-compose up -d --build
```

-   **Web App**: [http://localhost:8000](http://localhost:8000) (Served via Nginx)
-   **SMTP4Dev UI**: [http://localhost:5000](http://localhost:5000) (View sent emails here)

### 5. Apply Migrations
First-time setup requires applying database migrations inside the container:
```bash
docker-compose exec backend sh -c "python manage.py migrate"
```

### 6. Create Superuser (Optional)
```bash
docker-compose exec backend sh -c "python manage.py createsuperuser"
```

---

## 🐳 Docker Architecture

-   **todo-backend**: The Gunicorn/Django server.
-   **todo-nginx**: Reverse proxy serving static files and forwarding requests to the backend.
-   **todo-redis**: Message broker for Celery.
-   **todo-celery-worker**: Processes background tasks (e.g., sending emails).
-   **todo-celery-beat**: Scheduler for periodic tasks (e.g., token cleanup).
-   **smtp4dev**: Fake SMTP server for capturing development emails.

---

## 🧹 Running Without Docker (Manual)

If you prefer running locally with individual terminals:

1.  **Create Virtualenv**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run Server**:
    ```bash
    cd core
    python manage.py runserver
    ```
4.  **Run Celery** (Requires running local Redis):
    ```bash
    # Terminal 2 (Worker)
    celery -A core worker -l INFO
    
    # Terminal 3 (Beat)
    celery -A core beat -l INFO
    ```

*Note: You will need to configure `EMAIL_HOST` to `localhost` in `settings.py` if running outside Docker.*

---

## 📡 API Documentation

Usage of the API is primarily internal for the AJAX features, but it is fully exposed.

**Base URL**: `/api-auth/` (Auth) | `/tasks/api/v1/` (Tasks)

**Interactive Documentation**:
-   **Swagger UI**: `/swagger/`
-   **Redoc**: `/redoc/`

### Key Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **GET** | `/tasks/api/v1/task/` | List all tasks |
| **POST** | `/tasks/api/v1/task/` | Create a new task |
| **POST** | `/tasks/api/v1/assignment/` | Add assignment to task |
| **DELETE** | `/tasks/api/v1/assignment/{id}/` | Delete assignment |
| **PATCH** | `/tasks/api/v1/assignment/{id}/` | Update assignment (toggle complete) |

---

## 👨‍💻 Development Notes

### Threaded Email Sender
To prevent the application from hanging while waiting for SMTP servers, we implemented a **Threading-based Email Sender** in `core/accounts/api/utils.py`.
-   It spawns a new thread for `send()`.
-   It includes error handling to log failures without crashing the user request.
-   Used specifically for **Password Resets**.

### Frontend Architecture
We moved away from a monolithic SPA to a **Hybrid MPA**:
-   **Django Templates** handle routing and initial state.
-   **Vanilla JS** (`ui.js`, `tasks.js`) handles interactive elements like Modals and Toast notifications.
-   **CSS** is separated into modules: `layout.css` (grid/structure), `components.css` (cards, buttons), `modals.css`.

### Celery Beat
A periodic task is configured in `settings.py` to run daily at **2:00 AM UTC**:
-   `cleanup_expired_jwt_tokens`: Removes blacklisted or expired tokens from the database to maintain performance.

---

## 🤝 Contribution Guide

1.  **Fork** the repository.
2.  **Create a Branch**: `git checkout -b feature/AmazingFeature`.
3.  **Commit Changes**: `git commit -m 'Add some AmazingFeature'`.
4.  **Push**: `git push origin feature/AmazingFeature`.
5.  **Open a Pull Request**.

---

## 📄 License

This project is open-source and available under the **MIT License**.
