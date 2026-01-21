from datetime import datetime
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv
from flask import Blueprint, current_app, Flask, request, render_template, jsonify, redirect, url_for
from flask_mail import Mail, Message
import sqlite3, random, re, os, bcrypt, threading, time, pytz

load_dotenv()

authentication = Blueprint("authentication", __name__)

current_app.config["MAIL_SERVER"] = "smtp.gmail.com"
current_app.config["MAIL_PORT"] = 587
current_app.config["MAIL_USE_TLS"] = True
current_app.config["MAIL_USE_SSL"] = False
current_app.config["MAIL_USERNAME"] = os.getenv("GMAIL_ADDRESS")
current_app.config["MAIL_PASSWORD"] = os.getenv("APP_PASSWORD")
current_app.config["MAIL_DEFAULT_SENDER"] = os.getenv("GMAIL_ADDRESS")
mail = Mail(current_app)

db = sqlite3.connect("data.db")
db.execute("""CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY NOT NULL UNIQUE,
	username TEXT NOT NULL UNIQUE,
	email TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	created DATETIME NOT NULL DEFAULT (datetime('now')),
	token INTEGER NOT NULL UNIQUE,
	ip TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT "open"
)""")
db.execute("""CREATE TABLE IF NOT EXISTS signins (
	id INTEGER PRIMARY KEY NOT NULL UNIQUE,
	email TEXT NOT NULL,
	otp INTEGER NOT NULL,
	token INTEGER NOT NULL UNIQUE
)""")
db.execute("""CREATE TABLE IF NOT EXISTS signups (
	id INTEGER PRIMARY KEY NOT NULL UNIQUE,
	username TEXT NOT NULL,
	email TEXT NOT NULL,
	password TEXT NOT NULL,
	otp INTEGER NOT NULL,
	token INTEGER NOT NULL UNIQUE,
	ip TEXT NOT NULL
)""")
db.execute("""CREATE TABLE IF NOT EXISTS resets (
	id INTEGER PRIMARY KEY NOT NULL UNIQUE,
	email TEXT NOT NULL,
	password TEXT NOT NULL,
	otp INTEGER NOT NULL,
	token INTEGER NOT NULL UNIQUE
)""")
db.commit()
db.close()

def db_cleanup(table, token):
	time.sleep(5*60)
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.execute(f"DELETE FROM {table} WHERE token=?", (token,))
	db.commit()
	db.close()
	
def relative_time(dt):
	now = datetime.now(pytz.utc)
	dt = dt.replace(tzinfo=pytz.utc)
	diff = relativedelta(now, dt)
	if diff.years:
		return f"{diff.years} year{'s' if diff.years > 1 else ''} ago"
	if diff.months:
		return f"{diff.months} month{'s' if diff.months > 1 else ''} ago"
	if diff.days:
		return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
	if diff.hours:
		return f"{diff.hours} hour{'s' if diff.hours > 1 else ''} ago"
	if diff.minutes:
		return f"{diff.minutes} minute{'s' if diff.minutes > 1 else ''} ago"
	if diff.seconds:
		return f"{diff.seconds} second{'s' if diff.seconds > 1 else ''} ago"
	return "just now"

def check_signed(cookies):
	if not cookies:
		return False
	if not cookies.get("user_token"):
		return False
	user_token = request.cookies.get("user_token")
	db = sqlite3.connect("data.db")
	db.row_factory = sqlite3.Row
	cursor = db.cursor()
	cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
	row = cursor.fetchone()
	db.close()
	if not row:
		return False
	return dict(row)

def check_fields(form, required_fields):
	for i in required_fields:
		if i not in form.keys():
			return jsonify({
				"error": "The above field was not submitted",
				"field": i
			}), 400
	for i in required_fields:
		if not form.get(i):
			return jsonify({
				"error": "The above field is empty",
				"field": i
			}), 400
	return False

@authentication.route("/auth", methods=["GET"])
def index():
	if check_signed(request.cookies):
		return redirect("/")
	return render_template("auth.html")

@authentication.route("/signin", methods=["POST"])
def signin():
	if check_signed(request.cookies):
		return redirect("/")
	required_fields = ["signin_username_or_email", "signin_password"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	signin_username_or_email = request.form.get("signin_username_or_email").strip()
	signin_password = request.form.get("signin_password")
	db = sqlite3.connect("data.db")
	db.row_factory = sqlite3.Row
	cursor = db.cursor()
	cursor.execute("SELECT email, password FROM users WHERE username=? OR email=?",
		(signin_username_or_email, signin_username_or_email))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({
			"error": "The username/email is invalid",
			"field": "signin_username_or_email"
		}), 400
	row = dict(row)
	signin_email = row.get("email")
	password = row.get("password")
	if not bcrypt.checkpw(
		signin_password.encode("utf-8"),
		password.encode("utf-8")
	):
		db.close()
		return jsonify({
			"error": "The password is invalid",
			"field": "signin_password"
		}), 400
	while True:
		signin_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM signins WHERE token=?", (signin_token,))
		row = cursor.fetchone()
		if not row:
			break
	otp = random.randint(100000, 999999)
	cursor.execute("INSERT INTO signins (email, otp, token) VALUES(?, ?, ?)",
		(signin_email, otp, signin_token))
	db.commit()
	db.close()
	mail.send(Message(
		subject="OTP for email verification for sign in",
		recipients=[signin_email],
		body=f"The OTP for the verification of your email for sign in is {otp}."
	))
	t = threading.Thread(target=db_cleanup, args=("signins", signin_token), daemon=True)
	t.start()
	return jsonify({
		"success": 1,
		"signin_token": signin_token
	}), 200
	
@authentication.route("/signup", methods=["POST"])
def signup():
	if check_signed(request.cookies):
		return redirect("/")
	required_fields = ["signup_username", "signup_email", "signup_password", "signup_password", "signup_confirm_password"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	signup_username = request.form.get("signup_username").lower().strip()
	if re.search(r"[^a-z0-9_]", signup_username):
		return jsonify({
			"error": "Only alphanums and _ allowed",
			"field": "signup_username"
		})
	signup_email = request.form.get("signup_email").lower().strip()
	if not re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", signup_email):
		return jsonify({
			"error": "The email is invalid",
			"field": "signup_email"
		})
	signup_password = request.form.get("signup_password")
	if not (
		re.search(r"[a-z]", signup_password)
		and re.search(r"[A-Z]", signup_password)
		and re.search(r"[0-9]", signup_password)
		and re.search(r"[^a-zA-Z0-9]", signup_password)
	) or len(signup_password) < 8:
		return jsonify({
			"error": "The password is weak",
			"field": "signup_password"
		})
	signup_confirm_password = request.form.get("signup_confirm_password")
	if signup_password != signup_confirm_password:
		return jsonify({
			"error": "The passwords do not match",
			"field": "signup_confirm_password"
		}), 400
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.execute("SELECT * FROM users WHERE username=?", (signup_username,))
	row = cursor.fetchone()
	if row:
		db.close()
		return jsonify({
			"error": "The username is already taken",
			"field": "signup_username"
		}), 400
	cursor.execute("SELECT * FROM users WHERE email=?", (signup_email,))
	row = cursor.fetchone()
	if row:
		db.close()
		return jsonify({
			"error": "The email is already used",
			"field": "signup_email"
		}), 400
	while True:
		signup_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM signups WHERE token=?", (signup_token,))
		row = cursor.fetchone()
		if not row:
			break
	otp = random.randint(100000, 999999)
	signup_password = bcrypt.hashpw(signup_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
	ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0]
	cursor.execute("INSERT INTO signups (username, email, password, otp, token, ip) VALUES(?, ?, ?, ?, ?, ?)",
		(signup_username, signup_email, signup_password, otp, signup_token, ip))
	db.commit()
	db.close()
	mail.send(Message(
		subject="OTP for email verification for sign up",
		recipients=[signup_email],
		body=f"The OTP for the verification of your email for sign up is {otp}."
	))
	t = threading.Thread(target=db_cleanup, args=("signups", signup_token), daemon=True)
	t.start()
	return jsonify({
		"success": 1,
		"signup_token": signup_token
	}), 200

@authentication.route("/reset", methods=["POST"])
def reset():
	if check_signed(request.cookies):
		return redirect("/")
	required_fields = ["reset_username_or_email", "reset_password", "reset_confirm_password"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	reset_username_or_email = request.form.get("reset_username_or_email").strip()
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.execute("SELECT email FROM users WHERE username=? OR email=?",
		(reset_username_or_email, reset_username_or_email))
	reset_email = cursor.fetchone()
	if not reset_email:
		db.close()
		return jsonify({
			"error": "The username/email is invalid",
			"field": "reset_username_or_email"
		}), 400
	reset_password = request.form.get("reset_password")
	if not (
		re.search(r"[a-z]", reset_password)
		and re.search(r"[A-Z]", reset_password)
		and re.search(r"[0-9]", reset_password)
		and re.search(r"[^a-zA-Z0-9]", reset_password)
	) or len(reset_password) < 8:
		db.close()
		return jsonify({
			"error": "The password is weak",
			"field": "reset_password"
		})
	reset_confirm_password = request.form.get("reset_confirm_password")
	if reset_password != reset_confirm_password:
		return jsonify({
			"error": "The passwords do not match",
			"field": "reset_confirm_password"
		}), 400
	while True:
		reset_token = random.randint(1000000000, 9999999999)
		cursor.execute("SELECT * FROM signups WHERE token=?", (reset_token,))
		row = cursor.fetchone()
		if not row:
			break
	otp = random.randint(100000, 999999)
	reset_password = bcrypt.hashpw(reset_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
	cursor.execute("INSERT INTO resets (email, password, otp, token) VALUES(?, ?, ?, ?)",
		(reset_email[0], reset_password, otp, reset_token))
	db.commit()
	db.close()
	mail.send(Message(
		subject="OTP for password reset",
		recipients=[reset_email[0]],
		body=f"The OTP for the reset of your password is {otp}."
	))
	t = threading.Thread(target=db_cleanup, args=("resets", reset_token), daemon=True)
	t.start()
	return jsonify({
		"success": 1,
		"reset_token": reset_token
	}), 200

@authentication.route("/otp", methods=["POST"])
def otp():
	if check_signed(request.cookies):
		return redirect("/")
	required_fields = ["otp", "token", "type"]
	error = check_fields(request.form, required_fields)
	if error:
		return error
	otp = request.form.get("otp").strip()
	token = request.form.get("token").strip()
	type = request.form.get("type").strip()
	db = sqlite3.connect("data.db")
	db.row_factory = sqlite3.Row
	cursor = db.cursor()
	if type == "signin":
		cursor.execute("SELECT * FROM signins WHERE token=?", (token,))
		row = cursor.fetchone()
		if not row:
			db.close()
			return jsonify({
				"error": "Your otp may've expired",
				"field": "otp"
			}), 400
		data = dict(row)
		email = data.get("email")
		if str(data.get("otp")) != otp:
			db.close()
			return jsonify({
				"error": "The otp is invalid",
				"field": "otp"
			}), 400
		while True:
			user_token = random.randint(1000000000, 9999999999)
			cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
			row = cursor.fetchone()
			if not row:
				break
		cursor.execute("UPDATE users SET token=? WHERE email=?", (user_token, email))
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"user_token": user_token
		}), 200
	elif type == "signup":
		cursor.execute("SELECT * FROM signups WHERE token=?", (token,))
		row = cursor.fetchone()
		if not row:
			db.close()
			return jsonify({
				"error": "Your otp may've expired",
				"field": "otp"
			}), 400
		data = dict(row)
		if str(data.get("otp")) != otp:
			db.close()
			return jsonify({
				"error": "The otp is invalid",
				"field": "otp"
			}), 400
		cursor.execute("DELETE FROM signups WHERE token=?", (token,))
		while True:
			user_token = random.randint(1000000000, 9999999999)
			cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
			row = cursor.fetchone()
			if not row:
				break
		cursor.execute("INSERT INTO users (username, email, password, token, ip) VALUES(?, ?, ?, ?, ?)",
			(data.get("username"), data.get("email"), data.get("password"), user_token, data.get("ip")))
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"user_token": user_token
		}), 200
	elif type == "reset":
		cursor.execute("SELECT * FROM resets WHERE token=?", (token,))
		row = cursor.fetchone()
		if not row:
			db.close()
			return jsonify({
				"error": "Your otp may've expired",
				"field": "otp"
			}), 400
		data = dict(row)
		if str(data.get("otp")) != otp:
			db.close()
			return jsonify({
				"error": "The otp is invalid",
				"field": "otp"
			}), 400
		cursor.execute("DELETE FROM resets WHERE token=?", (token,))
		while True:
			user_token = random.randint(1000000000, 9999999999)
			cursor.execute("SELECT * FROM users WHERE token=?", (user_token,))
			row = cursor.fetchone()
			if not row:
				break
		cursor.execute("UPDATE users SET password=?, token=? WHERE email=?",
			(data.get("password"), user_token, data.get("email")))
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"user_token": user_token
		}), 200
	else:
		db.close()
		return jsonify({
			"error": "Invalid form type",
			"field": "type"
		}), 400

if __name__ == "__main__":
	app.run()

