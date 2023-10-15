import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Query the user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]

    # Query the user's stock holdings and calculate the total value of each holding
    stocks = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
        user_id=user_id
    )

    # Calculate the total value of each stock holding and the grand total
    grand_total = cash
    for stock in stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]
        stock_data = lookup(symbol)
        stock_price = stock_data["price"]
        stock["name"] = stock_data["name"]
        stock["price"] = stock_price
        stock["total_value"] = stock_price * shares
        grand_total += stock["total_value"]

    return render_template("index.html", stocks=stocks, cash=cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Please enter a stock symbol")
        if not shares:
            return apology("Please enter the number of shares")
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Shares must be a positive integer")
        except ValueError:
            return apology("Shares must be a positive integer")
        stock = lookup(symbol)

        if stock is None:
            return apology("Invalid stock symbol")
        price = stock["price"]
        user_id = session["user_id"]
        user = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)
        cash = user[0]["cash"]
        total_cost = price * shares
        if cash < total_cost:
            return apology("You do not have enough cash to make this purchase")
        updated_cash = cash - total_cost

        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=updated_cash, user_id=user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price) VALUES (:user_id, :symbol, :name, :shares, :price)",
                   user_id=user_id, symbol=symbol, name=stock["name"], shares=shares, price=price)

        flash("Bought!")

        return redirect("/")

    return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, name, shares, price, Timestamp FROM transactions WHERE user_id = :user_id", user_id=user_id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    symbol = request.form.get("symbol")
    if not lookup(symbol):
        return apology("INVALID SYMBOL")
    symbol = lookup(symbol)
    return render_template("quoted.html", symbol = symbol)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirmation")
    if not username:
        return apology("Missing username", 400)
    elif not password or not confirm_password:
        return apology("Missing password", 400)
    elif password != confirm_password:
        return apology("Password don't match", 400)
    try:
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?);", username, generate_password_hash(password))
    except:
        return apology("Username is taken, please try another username", 400)

    flash("Registered Successful!")
    return redirect("/login")

        # session["user_id"] = X[0]["id"]

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Please select a stock")
        if not shares.isdigit() or int(shares) <= 0:
            return apology("Please enter a valid number of shares")
        owned_shares = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol", user_id=user_id, symbol=symbol)[0]["total_shares"]
        if owned_shares is None or int(shares) > owned_shares:
            return apology("You don't own that many shares of the stock")

        stock_data = lookup(symbol)
        stock_price = stock_data["price"]
        sale_total = stock_price * int(shares)
        user_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]
        new_cash_balance = user_cash + sale_total

        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price) VALUES (:user_id, :symbol, :name, :shares, :price)", user_id=user_id, symbol=symbol, name=stock_data["name"], shares=(-int(shares)), price=stock_price)
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=new_cash_balance, user_id=user_id)

        flash("Sold!")

        return redirect("/")
    stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0", user_id=user_id)

    return render_template("sell.html", stocks=stocks)