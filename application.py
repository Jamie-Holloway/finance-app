import os
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import string
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Index route
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Get username + portfolio of user
    user = db.execute("SELECT username FROM users WHERE id=:uid;", uid=session["user_id"])[0]["username"]
    portfolio = db.execute("SELECT symbol, shares FROM portfolio WHERE username=:user;", user=user)

    # Initialise lists.
    symbols = []
    stock_names = []
    shares = []
    prices = []
    totals = []

    # Get users current cash reserves
    cash_reserves = db.execute("SELECT cash FROM users WHERE username=:user;", user=user)[0]['cash']
    net_worth = cash_reserves

    # Append relevant info to the lists, from portfolio + stock lookup.
    for stock in portfolio:
        # Lookup stock info for prices etc.
        response = lookup(stock['symbol'])

        # append to lists.
        symbols.append(stock['symbol'])
        stock_names.append(response['name'])
        shares.append(stock['shares'])
        prices.append(response['price'])
        totals.append(response['price'] * stock['shares'])
        net_worth += response['price'] * stock['shares']

    return render_template("index.html", symbols=symbols, stock_names=stock_names, shares=shares, prices=prices, totals=totals,  net_worth=net_worth, cash_reserves=cash_reserves)


# Buy route.
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        shares = request.form.get("shares")

        # Check that symbol & shares has been filled
        if not symbol or not shares:
            return apology("Input Symbol & Shares")

        # Check if symbol valid & shares valid
        response = lookup(symbol)
        print(response)

        if not response:
            return apology("Symbol not valid")
        if not shares.isdigit() or int(shares) < 1:
            return apology("Shares must be an integer greater than 0")

        # Check if can afford
        reserves = db.execute("SELECT cash FROM users WHERE id = :uid;", uid=session["user_id"])
        curr_user = db.execute("SELECT username FROM users WHERE id = :uid;", uid=session["user_id"])[0]["username"]
        total = response["price"] * float(shares)

        if total < reserves[0]["cash"]:
            # Add transaction to history
            curr_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            db.execute("INSERT INTO history (username, operation, symbol, price, shares, date_time) VALUES (:username, 'BUY', :symbol, :price, :shares, :date);",
                       username=db.execute("SELECT username FROM users WHERE id = :uid;", uid=session["user_id"])[0]["username"], symbol=symbol, price=total, shares=shares, date=curr_date)
            
            # Add stock to portfolio
            stock_check = db.execute("SELECT * FROM portfolio WHERE username=:user AND symbol=:symbol;",
                                     user=curr_user, symbol=symbol)
            
            if stock_check:
                # If already holding stock, modify shares.
                curr_shares = db.execute("SELECT shares FROM portfolio WHERE username=:user AND symbol=:symbol;",
                                         user=curr_user, symbol=symbol)[0]["shares"]
                
                db.execute("UPDATE portfolio SET shares = :shares WHERE symbol=:symbol",
                           shares=curr_shares + int(shares), symbol=symbol)
                db.execute("UPDATE users SET cash = :cash WHERE id= :uid;",
                           cash=reserves[0]["cash"] - total, uid=session["user_id"])
            else:
                # IF no stock held, add.
                db.execute("INSERT INTO portfolio (username, symbol, shares) VALUES (:username, :symbol, :shares);",
                           username=curr_user, symbol=symbol, shares=shares)
                db.execute("UPDATE users SET cash = :cash WHERE id= :uid;",
                           cash=reserves[0]["cash"] - total, uid=session["user_id"])

        else:
            return apology("Not enough cash money")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user = db.execute("SELECT username FROM users WHERE id=:uid;", uid=session["user_id"])[0]["username"]
    history = db.execute("SELECT symbol, price, shares, date_time FROM history WHERE username=:user;", user=user)

    print(user)
    print(history)

    # Initialise lists.
    symbols = []
    shares = []
    prices = []
    dates = []

    # Append stock info to lists.
    for stock in history:
        symbols.append(stock['symbol'])
        shares.append(stock['shares'])
        prices.append(stock['price'])
        dates.append(stock['date_time'])

    return render_template("history.html", symbols=symbols, shares=shares, prices=prices, dates=dates)


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

    if request.method == "POST":
        symb = request.form.get("symbol")
        
        # Check for valid inputs
        if not symb:
            return apology("Input a symbol")
        else:
            response = lookup(symb)

        if not response:
            return apology("Stock does not exist")
        else:
            return render_template("quoted.html", name=response["name"], price=usd(response["price"]), symbol=response["symbol"])

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        confirmation = request.form.get("confirmation")
        name_search = db.execute("SELECT username FROM users WHERE username = :user;", user=user)

        # Check username is okay
        if not user:
            return apology("Need Username")

        if len(name_search) != 0:
            if user in name_search[0].values():
                return apology("Name taken")

        # Check pw is okay
        if not pw:
            return apology("Need a password")
        elif not confirmation:
            return apology("Need to confirm pw")

        # Check pw matches
        if pw != confirmation:
            return apology("Passwords do not match")

        # hash pw
        db.execute("INSERT INTO users (username, hash) VALUES (:user, :hash);", user=user,
                   hash=generate_password_hash(pw, method="pbkdf2:sha256", salt_length=8))

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    username = db.execute("SELECT username FROM users WHERE id=:uid;", uid=session["user_id"])[0]["username"]

    if request.method == "POST":
        # Symbol data
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        neg_shares = int(shares) * -1

        response = lookup(symbol)
        price = response['price']

        total_price = price * float(shares)
        reserves = db.execute("SELECT cash FROM users WHERE id=:uid;", uid=session["user_id"])

        current_shares = db.execute("SELECT shares FROM portfolio WHERE username=:username AND symbol=:symbol;",
                                    username=username, symbol=symbol)[0]['shares']
        curr_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(shares)
        print(current_shares)

        if int(shares) > current_shares:
            return apology("You do not own that many shares.")

        # Add to history
        db.execute("INSERT INTO history (username, operation, symbol, price, shares, date_time) VALUES (:username, 'SELL', :symbol, :total_price, :shares, :date);",
                   username=username, symbol=symbol, total_price=total_price, shares=neg_shares, date=curr_date)

        if int(shares) == int(current_shares):
            db.execute("DELETE FROM portfolio WHERE username=:username AND symbol=:symbol;",
                       username=username, symbol=symbol)
            db.execute("UPDATE users SET cash = :cash WHERE id= :uid;",
                       cash=reserves[0]["cash"] + total_price, uid=session["user_id"])
        else:
            db.execute("UPDATE portfolio SET shares = :shares WHERE symbol=:symbol",
                       shares=current_shares - int(shares), symbol=symbol)
            db.execute("UPDATE users SET cash = :cash WHERE id= :uid;",
                       cash=reserves[0]["cash"] + total_price, uid=session["user_id"])

        return redirect("/")

    else:
        portfolio = db.execute("SELECT symbol FROM portfolio WHERE username=:username;", username=username)
        symbols = []
        for symbol in portfolio:
            symbols.append(symbol['symbol'])

        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
