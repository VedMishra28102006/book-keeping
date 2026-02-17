from apis.authentication_api import check_signed
from datetime import datetime
from flask import Blueprint, Flask, jsonify, render_template, redirect, request
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import sqlite3

accounting = Blueprint("accounting", __name__)

def check_fields(form, required_fields):
	for i in required_fields:
		if i not in form.keys():
			return {
				"error": "Not submitted",
				"field": i
			}
	for i in required_fields:
		if not form.get(i):
			return {
				"error": "empty",
				"field": i
			}
	return False

@accounting.route("/", methods=["GET"])
def index():
	if not check_signed(request.cookies):
		return redirect("/auth")
	return render_template("accounting.html")

@accounting.route("/status", methods=["GET"])
def status():
	signed = check_signed(request.cookies)
	if not signed:
		return redirect("/auth")
	return jsonify({"status": signed.get("status"), "admin": signed.get("admin")}), 200

@accounting.route("/fy", methods=["POST", "GET", "PATCH", "DELETE"])
def fy():
	signed = check_signed(request.cookies)
	if not signed:
		return redirect("/auth")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT id FROM users WHERE token=?", (request.cookies.get("user_token"),))
	user_id = dict(cursor.fetchone()).get("id")
	cursor.execute(f"""CREATE TABLE IF NOT EXISTS fys_{user_id} (
		id INTEGER PRIMARY KEY UNIQUE NOT NULL,
		name TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT "open"
	)""")
	db.commit()
	if request.method == "POST":
		if signed.get("status") == "closed":
			db.close()
			return jsonify({
				"error": "Your account has been closed",
				"id": -1
			}), 400
		required_fields = ["fy_name"]
		error = check_fields(request.form, required_fields)
		if error:
			db.close()
			return jsonify(error), 400
		fy_name = request.form.get("fy_name").strip()
		cursor.execute(f"SELECT * FROM fys_{user_id} WHERE name=?", (fy_name,))
		row = cursor.fetchone()
		if row:
			db.close()
			return jsonify({
				"error": "Journal already exists",
				"id": row["id"]
			}), 400
		cursor.execute(f"INSERT INTO fys_{user_id} (name) VALUES(?)", (fy_name,))
		cursor.execute(f"SELECT * FROM fys_{user_id} WHERE name=?", (fy_name,))
		row = cursor.fetchone()
		row = dict(row)
		cursor.execute(f"""CREATE TABLE IF NOT EXISTS journal_{user_id}_{row.get("id")} (
			id INTEGER PRIMARY KEY UNIQUE NOT NULL,
			date TEXT NOT NULL,
			ac_debited TEXT NOT NULL,
			ac_credited TEXT NOT NULL,
			amount INTEGER NOT NULL,
			description TEXT NOT NULL
		)""")
		cursor.execute(f"""CREATE TABLE IF NOT EXISTS bs_{user_id}_{row.get("id")} (
			id INTEGER PRIMARY KEY UNIQUE NOT NULL,
			account TEXT NOT NULL,
			type TEXT NOT NULL,
			subtype TEXT NOT NULL,
			operation TEXT NOT NULL
		)""")
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"row": row
		}), 200
	elif request.method == "GET":
		cursor.execute(f"SELECT * FROM fys_{user_id}")
		rows = cursor.fetchall()
		rows = [dict(row) for row in rows]
		db.close()
		fy_q = request.args.get("fy_q")
		if rows and fy_q:
			vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))
			tfidf_matrix = vectorizer.fit_transform([row["name"].lower() for row in rows])
			query_vec = vectorizer.transform([fy_q.strip().lower()])
			sim_scores = cosine_similarity(query_vec, tfidf_matrix).flatten()
			rows = [rows[i] for i in sim_scores.argsort()[::-1] if sim_scores[i] >= 0.3]
		return jsonify(rows), 200
	elif request.method == "PATCH":
		if signed.get("status") == "closed":
			db.close()
			return jsonify({
				"error": "Your account has been closed",
				"id": -1
			}), 400
		error = check_fields(request.form, ["id", "purpose"])
		if error:
			db.close()
			return jsonify(error), 400
		purpose = request.form.get("purpose").strip()
		id = request.form.get("id").strip()
		if purpose == "update_text":
			error = check_fields(request.form, ["fy_name"])
			if error:
				db.close()
				return jsonify(error), 400
			cursor.execute(f"SELECT * FROM fys_{user_id} WHERE id=?", (id,))
			row = cursor.fetchone()
			if not row:
				db.close()
				return jsonify({"error": "Invalid id"}), 400
			fy_name = request.form.get("fy_name").strip()
			cursor.execute(f"SELECT * FROM fys_{user_id} WHERE name=? AND id!=?", (fy_name, id))
			row = cursor.fetchone()
			if row:
				db.close()
				return jsonify({
					"error": "Journal already exists",
					"id": row["id"]
				}), 400
			cursor.execute(f"UPDATE fys_{user_id} SET name=? WHERE id=?", (fy_name, id))
			db.commit()
			db.close()
			return jsonify({"success": 1}), 200
		elif purpose == "update_status":
			cursor.execute(f"SELECT * FROM fys_{user_id} WHERE id=?", (id,))
			row = cursor.fetchone()
			if not row:
				db.close()
				return jsonify({"error": "Invalid id"}), 400
			status = dict(row).get("status")
			cursor.execute(f"UPDATE fys_{user_id} SET status=? WHERE id=?", ("closed" if status == "open" else "open", id))
			db.commit()
			db.close()
			return jsonify({"success": 1, "status": "closed" if status == "open" else "open"}), 200
		else:
			return jsonify({"error": "Invalid purpose"}), 400
	elif request.method == "DELETE":
		if signed.get("status") == "closed":
			db.close()
			return jsonify({
				"error": "Your account has been closed",
				"id": -1
			}), 400
		error = check_fields(request.form, ["id"])
		if error:
			db.close()
			return jsonify(error), 400
		id = request.form.get("id").strip()
		cursor.execute(f"SELECT * FROM fys_{user_id} WHERE id=?", (id,))
		row = cursor.fetchone()
		if not row:
			db.close()
			return jsonify({"error": "Invalid id"}), 400
		row = dict(row)
		cursor.execute(f"DELETE FROM fys_{user_id} WHERE id=?", (id,))
		cursor.execute(f"DROP TABLE journal_{user_id}_{row.get("id")}")
		cursor.execute(f"DROP TABLE bs_{user_id}_{row.get("id")}")
		db.commit()
		db.close()
		return jsonify({"success": 1}), 200

@accounting.route("/journal/<id>", methods=["POST", "GET"])
def journal(id):
	signed = check_signed(request.cookies)
	if not signed:
		return redirect("/auth")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT id FROM users WHERE token=?", (request.cookies.get("user_token"),))
	user_id = dict(cursor.fetchone()).get("id")
	cursor.execute(f"SELECT * FROM fys_{user_id} WHERE id=?", (id,))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({"error": "Invalid id"}), 400
	row = dict(row)
	status = row.get("status")
	if request.method == "GET":
		cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")}")
		rows = cursor.fetchall()
		rows = [dict(row) for row in rows]
		total = 0
		if rows:
			cursor.execute(f"SELECT SUM(amount) FROM journal_{user_id}_{row.get("id")}")
			total = cursor.fetchone()
			total = total[0] if total and total[0] is not None else 0
		db.close()
		return jsonify({
			"rows": rows,
			"total": total,
			"fy_name": row.get("name")
		}), 200
	elif request.method == "POST":
		if signed.get("status") == "closed":
			db.close()
			return "", 204
		if status == "closed":
			db.close()
			return "", 204
		required_fields = ["date", "ac_debited", "ac_credited", "amount", "description"]
		balance = {}
		for i in range(0, len(request.json)):
			error = check_fields(request.json[i], required_fields)
			if error:
				error["index"] = i
				return jsonify(error), 400
			try:
				amount = float(request.json[i]["amount"])
			except:
				db.close()
				return jsonify({
					"error": "invalid amount",
					"field": "amount",
					"index": i
				}), 400
			if amount <= 0:
				db.close()
				return jsonify({
					"error": "invalid amount",
					"field": "amount",
					"index": i
				})
			date = request.json[i].get("date")
			try:
				datetime.strptime(date, "%Y-%m-%d")
			except:
				db.close()
				return jsonify({
					"error": "invalid date",
					"field": "date",
					"index": i
				}), 400
		cursor.execute(f"DROP TABLE journal_{user_id}_{row.get("id")}");
		cursor.execute(f"""CREATE TABLE IF NOT EXISTS journal_{user_id}_{row.get("id")} (
			id INTEGER PRIMARY KEY UNIQUE NOT NULL,
			date TEXT NOT NULL,
			ac_debited TEXT NOT NULL,
			ac_credited TEXT NOT NULL,
			amount INTEGER NOT NULL,
			description TEXT NOT NULL
		)""")
		for i in request.json:
			cursor.execute(f"INSERT INTO journal_{user_id}_{row.get("id")} (date, ac_debited, ac_credited, amount, description) VALUES(?, ?, ?, ?, ?)",
				(i["date"].strip(), i["ac_debited"].strip(), i["ac_credited"].strip(), i["amount"].strip(), i["description"].strip()))
		db.commit()
		db.close()
		return jsonify({"success": 1}), 200

@accounting.route("/ledger/<id>", methods=["DELETE", "GET", "PATCH"])
def ledger(id):
	if not check_signed(request.cookies):
		return redirect("/auth")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT id FROM users WHERE token=?", (request.cookies.get("user_token"),))
	user_id = dict(cursor.fetchone()).get("id")
	cursor.execute(f"SELECT id FROM fys_{user_id} WHERE id=?", (id,))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({"error": "Invalid id"}), 400
	row = dict(row)
	account = request.args.get("account")
	if request.method == "GET":
		if not account:
			cursor.execute(f"""
				SELECT ac_debited AS account FROM journal_{user_id}_{row["id"]}
				UNION SELECT ac_credited AS account FROM journal_{user_id}_{row["id"]}
			""")
			rows = cursor.fetchall()
			rows = [dict(row) for row in rows]
			ledger_q = request.args.get("ledger_q")
			if rows and ledger_q:
				vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))
				tfidf_matrix = vectorizer.fit_transform([row["account"].lower() for row in rows])
				query_vec = vectorizer.transform([ledger_q.strip().lower()])
				sim_scores = cosine_similarity(query_vec, tfidf_matrix).flatten()
				rows = [rows[i] for i in sim_scores.argsort()[::-1] if sim_scores[i] >= 0.3]
			cursor.execute(f"SELECT * FROM bs_{user_id}_{row["id"]}")
			bss = cursor.fetchall()
			bss = [dict(bs) for bs in bss]
			for i in range(len(rows)):
				for j in range(len(bss)):
					if rows[i].get("account") == bss[j].get("account"):
						rows[i]["operation"] = bss[j].get("operation")
						rows[i]["type"] = bss[j].get("type")
						rows[i]["subtype"] = bss[j].get("subtype")
						break
				if not rows[i].get("operation") or not rows[i].get("type") or not rows[i].get("subtype"):
					rows[i]["operation"] = None
					rows[i]["type"] = None
					rows[i]["subtype"] = None
				rows[i]["id"] = i
			db.close()
			return jsonify(rows), 200
		balance = 0
		cursor.execute(f"SELECT id,date,ac_credited AS account,amount FROM journal_{user_id}_{row["id"]} WHERE ac_debited=?", (account,))
		debit_side = cursor.fetchall()
		debit_total = 0
		if debit_side:
			debit_side = [dict(row) for row in debit_side]
			debit_total = sum([row["amount"] for row in debit_side])
			balance += debit_total
		cursor.execute(f"SELECT id,date,ac_debited AS account,amount FROM journal_{user_id}_{row["id"]} WHERE ac_credited=?", (account,))
		credit_side = cursor.fetchall()
		credit_total = 0
		if credit_side:
			credit_side = [dict(row) for row in credit_side]
			credit_total = sum([row["amount"] for row in credit_side])
			balance -= credit_total
		db.close()
		if not debit_side and not credit_side:
			return jsonify({"error": "invalid account"}), 400
		balance_side = None
		if balance > 0:
			balance_side = "credit_side"
		if balance < 0:
			balance_side = "debit_side"
		total = 0
		if debit_total and credit_total:
			total = debit_total if debit_total > credit_total else credit_total
		if not debit_total:
			total = credit_total
		if not credit_total:
			total = debit_total
		return jsonify({
			"debit_side": debit_side,
			"credit_side": credit_side,
			"balance_side": balance_side,
			"balance": abs(balance),
			"total": total
		}), 200
	elif request.method == "DELETE":
		cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (account, account))
		ac_test = cursor.fetchone()
		if not ac_test:
			db.close()
			return jsonify({"error": "Invalid account"}), 400
		cursor.execute(f"DELETE FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=?", (account, account))
		db.commit()
		db.close()
		return jsonify({"success": 1}), 200 
	elif request.method == "PATCH":
		cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (account, account))
		ac_test = cursor.fetchone()
		if not ac_test:
			db.close()
			return jsonify({"error": "Invalid account"}), 400
		new_name = request.form.get("new_name")
		cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (new_name, new_name))
		ac_test = cursor.fetchone()
		act = "remove" if ac_test else "rename"
		cursor.execute(f"UPDATE journal_{user_id}_{row.get("id")} SET ac_credited=? WHERE ac_credited=? AND ac_debited!=?", (new_name,account,new_name))
		cursor.execute(f"UPDATE journal_{user_id}_{row.get("id")} SET ac_debited=? WHERE ac_debited=? AND ac_credited!=?", (new_name,account,new_name))
		if act == "rename":
			cursor.execute(f"UPDATE bs_{user_id}_{row.get("id")} SET account=? WHERE account=?", (new_name, account))
		else:
			cursor.execute(f"DELETE FROM bs_{user_id}_{row.get("id")} WHERE account=?", (account,))
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"act": act
		}), 200

@accounting.route("/bs/<fy_id>", methods=["GET", "PATCH"])
def bs(fy_id):
	signed = check_signed(request.cookies)
	if not signed:
		return redirect("/auth")
	db = sqlite3.connect("data.db")
	cursor = db.cursor()
	cursor.row_factory = sqlite3.Row
	cursor.execute("SELECT id FROM users WHERE token=?", (request.cookies.get("user_token"),))
	user_id = dict(cursor.fetchone()).get("id")
	cursor.execute(f"SELECT * FROM fys_{user_id} WHERE id=?", (fy_id,))
	row = cursor.fetchone()
	if not row:
		db.close()
		return jsonify({"error": "Invalid id"}), 400
	row = dict(row)
	status = row.get("status")
	if signed.get("status") == "closed":
		db.close()
		return "", 204
	if status == "closed":
		db.close()
		return "", 204
	if request.method == "GET":
		cursor.execute(f"SELECT account, operation, subtype FROM bs_{user_id}_{row["id"]} WHERE type=?", ("asset",))
		assets = cursor.fetchall()
		assets_total = 0
		current_assets = []
		current_assets_total = 0
		noncurrent_assets = []
		noncurrent_assets_total = 0
		if assets:
			assets = [dict(row) for row in assets]
			i = 0
			assets_len = len(assets)
			while i < assets_len:
				account = assets[i].get("account")
				cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (account, account))
				ac_test = cursor.fetchone()
				if not ac_test:
					del assets[i]
					cursor.execute(f"DELETE FROM bs_{user_id}_{row.get("id")} WHERE account=?", (account,))
					db.commit()
					assets_len -= 1
					continue
				cursor.execute(f"""SELECT
					COALESCE ((SELECT SUM(amount) FROM journal_{user_id}_{row["id"]} WHERE ac_debited=?), 0)
					- COALESCE ((SELECT SUM(amount) FROM journal_{user_id}_{row["id"]} WHERE ac_credited=?), 0)
					AS balance
				""", (account, account))
				balance = cursor.fetchone()
				assets[i]["amount"] = abs(balance["balance"])
				if assets[i].get("subtype") == "current":
					current_assets.append(assets[i])
				else:
					noncurrent_assets.append(assets[i])
				i += 1
			if current_assets:
				current_assets_total = sum([row["amount"] for row in current_assets if row["operation"] == "add"]) - sum([row["amount"] for row in current_assets if row["operation"] == "less"])
			if noncurrent_assets:
				noncurrent_assets_total = sum([row["amount"] for row in noncurrent_assets if row["operation"] == "add"]) - sum([row["amount"] for row in noncurrent_assets if row["operation"] == "less"])
			if assets:
				assets_total = current_assets_total + noncurrent_assets_total
		assets = {
			"current": current_assets,
			"current_total": current_assets_total,
			"noncurrent": noncurrent_assets,
			"noncurrent_total": noncurrent_assets_total,
			"total": assets_total
		}
		cursor.execute(f"SELECT account, operation, subtype FROM bs_{user_id}_{row["id"]} WHERE type=?", ("liability",))
		liabilities = cursor.fetchall()
		liabilities_total = 0
		current_liabilities = []
		current_liabilities_total = 0
		noncurrent_liabilities = []
		noncurrent_liabilities_total = 0
		equity = []
		equity_total = 0
		if liabilities:
			liabilities = [dict(row) for row in liabilities]
			i = 0
			liabilities_len = len(liabilities)
			while i < liabilities_len:
				account = liabilities[i].get("account")
				cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (account, account))
				ac_test = cursor.fetchone()
				if not ac_test:
					del liabilities[i]
					cursor.execute(f"DELETE FROM bs_{user_id}_{row.get("id")} WHERE account=?", (account,))
					db.commit()
					liabilities_len -= 1
					continue
				cursor.execute(f"""SELECT
					COALESCE ((SELECT SUM(amount) FROM journal_{user_id}_{row["id"]} WHERE ac_debited=?), 0)
					- COALESCE ((SELECT SUM(amount) FROM journal_{user_id}_{row["id"]} WHERE ac_credited=?), 0)
					AS balance
				""", (account, account))
				balance = cursor.fetchone()
				liabilities[i]["amount"] = abs(balance["balance"])
				if liabilities[i].get("subtype") == "current":
					current_liabilities.append(liabilities[i])
				elif liabilities[i].get("subtype") == "noncurrent":
					noncurrent_liabilities.append(liabilities[i])
				else:
					equity.append(liabilities[i])
				i += 1
			if current_liabilities:
				current_liabilities_total = sum([row["amount"] for row in current_liabilities if row["operation"] == "add"]) - sum([row["amount"] for row in current_liabilities if row["operation"] == "less"])
			if noncurrent_liabilities:
				noncurrent_liabilities_total = sum([row["amount"] for row in noncurrent_liabilities if row["operation"] == "add"]) - sum([row["amount"] for row in noncurrent_liabilities if row["operation"] == "less"])
			if equity:
				equity_total = sum([row["amount"] for row in equity if row["operation"] == "add"]) - sum([row["amount"] for row in equity if row["operation"] == "less"])
			if liabilities:
				liabilities_total = current_liabilities_total + noncurrent_liabilities_total + equity_total
		liabilities = {
			"current": current_liabilities,
			"current_total": current_liabilities_total,
			"noncurrent": noncurrent_liabilities,
			"noncurrent_total": noncurrent_liabilities_total,
			"equity": equity,
			"equity_total": equity_total,
			"total": liabilities_total
		}
		db.close()
		return jsonify({
			"assets": assets,
			"liabilities": liabilities
		}), 200
	elif request.method == "PATCH":
		required_fields = ["type", "subtype", "account"]
		error = check_fields(request.form, required_fields)
		if error:
			db.close()
			return jsonify(error), 400
		type = request.form.get("type").strip()
		required_types = ["asset", "liability", "nota"]
		if type not in required_types:
			db.close()
			return jsonify({"error": "Invalid type"}), 400

		subtype = request.form.get("subtype").strip()
		required_subtypes = ["current", "noncurrent", "equity"]
		if type != "nota" and (subtype not in required_subtypes or (type == "asset" and subtype == "equity")):
			db.close()
			return jsonify({"error": "Invalid subtype"}), 400
		operation = request.form.get("operation").strip()
		required_operations = ["add", "less"]
		if type != "nota" and operation not in required_operations:
			db.close()
			return jsonify({"error": "Invalid operation"}), 400
		account = request.form.get("account").strip()
		cursor.execute(f"SELECT * FROM journal_{user_id}_{row.get("id")} WHERE ac_credited=? OR ac_debited=? LIMIT 1", (account, account))
		ac_test = cursor.fetchone()
		if not ac_test:
			db.close()
			return jsonify({"error": "Invalid account"}), 400
		cursor.execute(f"SELECT * FROM bs_{user_id}_{row.get("id")} WHERE account=?", (account,))
		bs = cursor.fetchone()
		if bs:
			if type == "nota":
				cursor.execute(f"DELETE FROM bs_{user_id}_{row.get("id")} WHERE account=?", (account,))	
			elif bs["type"] == type and bs["subtype"] == subtype and bs["operation"] == operation:
				db.close()
				return "", 204
			else:
				cursor.execute(f"UPDATE bs_{user_id}_{row.get("id")} SET type=?, subtype=?, operation=? WHERE account=?", (type, subtype, operation, account))
		else:
			if type != "nota":
				cursor.execute(f"INSERT INTO bs_{user_id}_{row.get("id")} (account, type, subtype, operation) VALUES(?, ?, ?, ?)", (account, type, subtype, operation))
		db.commit()
		db.close()
		return jsonify({
			"success": 1,
			"type": type,
			"subtype": subtype,
			"operation": operation
		}), 200