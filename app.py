import datetime
from functools import wraps
import bcrypt
from flask import Flask, jsonify, request
import jwt

app = Flask(__name__)

# CRITICAL: In production, store this securely in your environment variables
app.config["SECRET_KEY"] = "your_super_secret_cryptographic_key_here"

# In-memory "database" simulation for demo purposes
# In production, use a real database like PostgreSQL or MongoDB
USER_DB = {}


# --- MIDDLEWARE / DECORATOR FOR PROTECTED ROUTES ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if the Authorization header is present
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            # Standard format is "Bearer <token>"
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return (
                jsonify({"message": "Token is missing. Access denied."}),
                401,
            )

        try:
            # Decode and verify the JWT signature and expiration
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            # Inject the current authenticated user into the route logic
            current_user = USER_DB.get(data["username"])
            if not current_user:
                return jsonify({"message": "Invalid token user context."}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token structure."}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# --- AUTHENTICATION ROUTES ---


@app.route("/register", methods=["POST"])
def register():
    """Handles new user signup by securely hashing passwords."""
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"message": "Missing username or password."}), 400

    username = data["username"]
    password = data["password"]

    if username in USER_DB:
        return jsonify({"message": "User already exists."}), 400

    # 1. Generate a salt and hash the plain text password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)

    # 2. Save the hashed password, NEVER the plain text
    USER_DB[username] = {"username": username, "password": hashed_password}

    return jsonify({"message": "User registered successfully!"}), 201


@app.route("/login", methods=["POST"])
def login():
    """Verifies credentials and generates a signed JWT."""
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"message": "Missing credentials."}), 400

    username = data["username"]
    password = data["password"]

    user = USER_DB.get(username)
    if not user:
        return jsonify({"message": "Invalid username or password."}), 401

    # 3. Check submitted password against stored cryptographic hash
    if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        # 4. Generate the JWT Payload with an expiration time
        payload = {
            "username": user["username"],
            "exp": datetime.datetime.utcnow()
            + datetime.timedelta(hours=1),  # Token valid for 1 hour
            "iat": datetime.datetime.utcnow(),
        }

        # 5. Sign the token using your backend's secret key
        token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"message": "Invalid username or password."}), 401


# --- PROTECTED RESOURCE ROUTE ---


@app.route("/dashboard", methods=["GET"])
@token_required
def dashboard(current_user):
    """A secure route requiring a valid JWT payload to read data."""
    return jsonify(
        {
            "message": f"Welcome to your dashboard, {current_user['username']}!",
            "secret_data": "This data is only visible to authenticated requests.",
        }
    )


if __name__ == "__main__":
    app.run(debug=True)