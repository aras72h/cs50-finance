import os
from datetime import datetime

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
    # Get user's stocks
    stocks = db.execute(
        "SELECT symbol, SUM(CASE WHEN type = 'buy' THEN shares WHEN type = 'sell' THEN -shares END) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol;", session["user_id"])
    # Get user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # Initialize total stocks value for user
    stocks_value = 0
    # Update the portfolio prices
    for stock in stocks:
        stock["price"] = lookup(stock["symbol"]).get("price")
    # # Calculate total stocks value
    for stock in stocks:
        stocks_value += stock["price"] * stock["shares"]
    return render_template("index.html", stocks=stocks, cash=cash, stocks_value=stocks_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # Check request method
    if request.method == "POST":
        stock_symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # Check for correct inputs
        if lookup(stock_symbol) == None:
            return apology("Not a valid stock symbol")
        if not shares.isdigit():
            return apology("Enter a positive number for shares")
        # Convert symbol letters to lowercase
        stock_symbol = request.form.get("symbol").lower()
        # Cast shares from string to integer
        shares = int(request.form.get("shares"))
        # Get price
        price = lookup(stock_symbol).get("price")
        # Get current datetime
        now = datetime.now()
        # Get user's cash balance
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])
        user_cash = user_cash[0].get("cash")
        # Check if user can afford shares
        cash_required = shares * price
        if cash_required > user_cash:
            return apology("you don't have enough funds. don't be sad")
        # Update user's account balance
        user_cash -= cash_required
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", user_cash, session["user_id"])
        # Store transaction in database
        db.execute("INSERT INTO transactions (user_id,symbol,shares,price,time,type) VALUES (?,?,?,?,?,?);",
                   session["user_id"], stock_symbol, shares, price, now, "buy")
        # Redirect to homepage
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    # Check for request method
    if request.method == "POST":
        # Store symbol in lowercase
        stock_symbol = request.form.get("symbol").lower()
        # Validate symbol
        if lookup(stock_symbol):
            quote = lookup(stock_symbol)
        else:
            # Return error for incorrect symbol
            return apology("not a valid symbol")
        return render_template("quoted.html", q=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Storing user's input into variables
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)
        # Checking for correct input from user
        if not (username and password and confirmation):
            return apology("all fields required")
        else:
            # Check username to be unique
            rows = db.execute("SELECT * FROM users WHERE username = ?;", username)
            if len(rows) != 0:
                return apology("username already exists")
            # Compare password and its confirmation
            elif password != confirmation:
                return apology("confirm your password correctly")
            else:
                # Insert user info into database
                db.execute("INSERT INTO users (username, hash) values (?, ?)", username, hash)
                return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Get user stocks
    stocks = db.execute(
        "SELECT symbol, SUM(CASE WHEN type = 'buy' THEN shares WHEN type = 'sell' THEN -shares END) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol;", session["user_id"])
    # Store user sell request
    if request.method == "POST":
        symbol = request.form.get("symbol").lower()
        shares = request.form.get("shares")
        price = lookup(symbol)["price"]
        """Check user input"""
        if lookup(symbol) == None:
            return apology("Not a valid stock symbol")
        if not shares.isdigit():
            return apology("Enter a positive number for shares")
        """Check if user has the shares to sell"""
        for stock in stocks:
            if stock.get("symbol") == symbol and stock.get("shares") < int(shares):
                return apology("You don't have enough")
        # Update transactions
        db.execute("INSERT INTO transactions (user_id,symbol,shares,price,time,type) VALUES (?,?,?,?,DATETIME('now'),?);",
                   session["user_id"], symbol, shares, price, "sell")
        # Add money to user's account
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        cash += (float(shares) * price)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        return redirect("/")

    return render_template("sell.html", stocks=stocks)
