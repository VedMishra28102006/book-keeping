from flask import Blueprint, current_app, Flask

app = Flask(__name__)
with app.app_context():
	from apis.authentication_api import authentication
	app.register_blueprint(authentication)
	from apis.accounting_api import accounting
	app.register_blueprint(accounting)
	from apis.admin_api import admin
	app.register_blueprint(admin)

if __name__ == "__main__":
	app.run()